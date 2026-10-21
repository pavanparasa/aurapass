//! `aurapass` — the command-line interface.
//!
//! Designed to be scriptable: every command can emit JSON, ids can be given by
//! prefix, and secrets can be read from a file, a pipe or the environment so
//! that nothing sensitive ends up in shell history or `ps` output.

mod render;

use aurapass_bridge::console::{self, SecretSource};
use aurapass_bridge::resolve_item;
use aurapass_core::audit::AuditOptions;
use aurapass_core::breach::{self, BreachClient};
use aurapass_core::config::AppConfig;
use aurapass_core::crypto::KdfPreset;
use aurapass_core::error::{Error, Result};
use aurapass_core::generator::{self, PasswordPolicy};
use aurapass_core::importers::{self, ImportFormat};
use aurapass_core::model::{Item, ItemKind};
use aurapass_core::totp::Totp;
use aurapass_core::util::expand_tilde;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use aurapass_core::vault::{SortOrder, UnlockedVault, VaultFile, VaultQuery};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "aurapass",
    about = "AuraPass — an offline-first password manager",
    version,
    after_help = "Examples:\n  \
        aurapass init ~/AuraPass/personal.aurapass --kdf moderate\n  \
        aurapass add -t GitHub -u alice --generate -U https://github.com\n  \
        aurapass otp GitHub\n  \
        aurapass get GitHub password | wl-copy\n  \
        aurapass audit --breach"
)]
struct Cli {
    /// Vault file to operate on. Falls back to $AURAPASS_VAULT, then to the
    /// most recently used vault.
    #[arg(short, long, value_name = "FILE", global = true, env = "AURAPASS_VAULT")]
    vault: Option<PathBuf>,

    /// Read the master password from this file instead of prompting.
    #[arg(long, value_name = "FILE", global = true, env = "AURAPASS_PASSWORD_FILE")]
    password_file: Option<PathBuf>,

    /// Read the master password from standard input.
    #[arg(long, global = true)]
    password_stdin: bool,

    /// Key file required to unlock the vault.
    #[arg(long, value_name = "FILE", global = true)]
    key_file: Option<PathBuf>,

    /// Allow reading the master password from $AURAPASS_MASTER_PASSWORD.
    #[arg(long, global = true)]
    password_env: bool,

    /// Emit machine-readable JSON where a command supports it.
    #[arg(long, global = true)]
    json: bool,

    /// Suppress non-essential output.
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new vault.
    Init(InitArgs),
    /// Show information about a vault without unlocking it.
    Info,
    /// List or search items.
    #[command(alias = "ls")]
    List(ListArgs),
    /// Print one item in full.
    Show(ShowArgs),
    /// Print a single field of an item (handy for $(…) in scripts).
    Get(GetArgs),
    /// Add an item.
    Add(AddArgs),
    /// Modify an item.
    Edit(EditArgs),
    /// Move an item to the bin, or delete it with --purge.
    Rm(RmArgs),
    /// Restore an item from the bin.
    Restore { #[arg(value_name = "ITEM")] item: String },
    /// Permanently delete everything in the bin.
    EmptyBin,
    /// Generate a password, passphrase or PIN.
    Gen(GenArgs),
    /// Print the current one-time password for an item.
    Otp(OtpArgs),
    /// Audit the vault for weak, reused and breached passwords.
    Audit(AuditArgs),
    /// Add items from another password manager's export.
    Import(ImportArgs),
    /// Write a plaintext export (CSV/JSON) or an encrypted backup.
    Export(ExportArgs),
    /// Change the master password.
    Passwd(PasswdArgs),
    /// List the categories in the vault.
    Categories,
    /// Show the activity log.
    Activity(ActivityArgs),
    /// Run the browser bridge in the foreground.
    Bridge(BridgeArgs),
    /// Report the pairing token and bridge address.
    BridgeInfo,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Where to create the vault.
    #[arg(value_name = "FILE")]
    path: Option<PathBuf>,
    /// Vault display name.
    #[arg(short, long)]
    name: Option<String>,
    /// Argon2id cost preset.
    #[arg(long, value_enum, default_value_t = KdfChoices::Interactive)]
    kdf: KdfChoices,
    /// Protect the vault with a key file as well as the password.
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,
    /// Generate a key file instead of choosing one.
    #[arg(long, value_name = "FILE", conflicts_with = "key_file")]
    generate_key_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KdfChoices {
    Interactive,
    Moderate,
    Paranoid,
}

impl From<KdfChoices> for KdfPreset {
    fn from(value: KdfChoices) -> Self {
        match value {
            KdfChoices::Interactive => KdfPreset::Interactive,
            KdfChoices::Moderate => KdfPreset::Moderate,
            KdfChoices::Paranoid => KdfPreset::Paranoid,
        }
    }
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Free-text query.
    #[arg(value_name = "QUERY")]
    query: Option<String>,
    /// Restrict to a kind (login, secure-note, credit-card, …).
    #[arg(short, long, value_name = "KIND")]
    kind: Vec<String>,
    /// Restrict to a tag.
    #[arg(long, value_name = "TAG")]
    tag: Vec<String>,
    /// Restrict to a category name.
    #[arg(short, long, value_name = "CATEGORY")]
    category: Option<String>,
    /// Only favourites.
    #[arg(short, long)]
    favorites: bool,
    /// Include items in the bin.
    #[arg(long)]
    trash: bool,
    /// Only items in the bin.
    #[arg(long, conflicts_with = "trash")]
    only_trash: bool,
    /// Sort order.
    #[arg(long, value_enum, default_value_t = SortChoices::Title)]
    sort: SortChoices,
    /// Print passwords in the table (they are hidden by default).
    #[arg(long)]
    reveal: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SortChoices {
    Title,
    Updated,
    Created,
    LastUsed,
    Kind,
}

impl From<SortChoices> for SortOrder {
    fn from(value: SortChoices) -> Self {
        match value {
            SortChoices::Title => SortOrder::Title,
            SortChoices::Updated => SortOrder::Updated,
            SortChoices::Created => SortOrder::Created,
            SortChoices::LastUsed => SortOrder::LastUsed,
            SortChoices::Kind => SortOrder::Kind,
        }
    }
}

#[derive(Args, Debug)]
struct ShowArgs {
    /// Item id (or an unambiguous prefix), or its exact title.
    #[arg(value_name = "ITEM")]
    item: String,
    /// Print secrets too.
    #[arg(long)]
    reveal: bool,
}

#[derive(Args, Debug)]
struct GetArgs {
    /// Item id (or an unambiguous prefix), or its exact title.
    #[arg(value_name = "ITEM")]
    item: String,
    /// Which field: title, username, password, url, totp, notes, otp.
    #[arg(value_name = "FIELD")]
    field: String,
}

#[derive(Args, Debug)]
struct AddArgs {
    /// Title of the new item.
    #[arg(short, long, value_name = "TITLE")]
    title: String,
    /// Item kind.
    #[arg(short, long, value_enum, default_value_t = KindChoices::Login)]
    kind: KindChoices,
    /// Account name.
    #[arg(short, long, value_name = "USERNAME")]
    username: Option<String>,
    /// Password. Prefer --generate or --password-stdin to keep it out of the
    /// shell history.
    #[arg(short, long, value_name = "PASSWORD")]
    password: Option<String>,
    /// Read the password from standard input.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
    /// Generate a password using the given policy length.
    #[arg(short, long, num_args = 0..=1, default_missing_value = "20", value_name = "LENGTH")]
    generate: Option<usize>,
    /// Website or application URL (repeatable).
    #[arg(short = 'U', long, value_name = "URL")]
    url: Vec<String>,
    /// One-time-password secret or otpauth:// URI.
    #[arg(long, value_name = "SECRET")]
    totp: Option<String>,
    /// Notes.
    #[arg(short, long, value_name = "TEXT")]
    notes: Option<String>,
    /// Tag (repeatable).
    #[arg(long, value_name = "TAG")]
    tag: Vec<String>,
    /// Category name; created if it does not exist.
    #[arg(short, long, value_name = "NAME")]
    category: Option<String>,
    /// Mark as a favourite.
    #[arg(long)]
    favorite: bool,
    /// Extra field as LABEL=VALUE (repeatable). Prefix the label with `!` to
    /// mark it sensitive.
    #[arg(long = "field", value_name = "LABEL=VALUE")]
    fields: Vec<String>,
    /// Print the generated password (otherwise it is only stored).
    #[arg(long)]
    show_generated: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KindChoices {
    Login,
    Password,
    SecureNote,
    CreditCard,
    BankAccount,
    Identity,
    SshKey,
    ApiKey,
    Wifi,
    SoftwareLicense,
    Database,
    Server,
    Custom,
}

impl From<KindChoices> for ItemKind {
    fn from(value: KindChoices) -> Self {
        match value {
            KindChoices::Login => ItemKind::Login,
            KindChoices::Password => ItemKind::Password,
            KindChoices::SecureNote => ItemKind::SecureNote,
            KindChoices::CreditCard => ItemKind::CreditCard,
            KindChoices::BankAccount => ItemKind::BankAccount,
            KindChoices::Identity => ItemKind::Identity,
            KindChoices::SshKey => ItemKind::SshKey,
            KindChoices::ApiKey => ItemKind::ApiKey,
            KindChoices::Wifi => ItemKind::Wifi,
            KindChoices::SoftwareLicense => ItemKind::SoftwareLicense,
            KindChoices::Database => ItemKind::Database,
            KindChoices::Server => ItemKind::Server,
            KindChoices::Custom => ItemKind::Custom,
        }
    }
}

#[derive(Args, Debug)]
struct EditArgs {
    /// Item id (or an unambiguous prefix), or its exact title.
    #[arg(value_name = "ITEM")]
    item: String,
    #[arg(short, long)]
    title: Option<String>,
    #[arg(short, long)]
    username: Option<String>,
    #[arg(short, long)]
    password: Option<String>,
    /// Read the new password from standard input.
    #[arg(long)]
    password_stdin: bool,
    /// Replace the password with a freshly generated one.
    #[arg(short, long, num_args = 0..=1, default_missing_value = "20")]
    generate: Option<usize>,
    #[arg(short = 'U', long)]
    url: Vec<String>,
    /// Replace the URL list entirely with the given values.
    #[arg(long)]
    clear_urls: bool,
    #[arg(long)]
    totp: Option<String>,
    /// Remove any stored one-time-password secret.
    #[arg(long)]
    clear_totp: bool,
    #[arg(short, long)]
    notes: Option<String>,
    #[arg(long)]
    tag: Vec<String>,
    /// Remove a tag.
    #[arg(long = "untag")]
    untag: Vec<String>,
    #[arg(short, long)]
    category: Option<String>,
    /// Toggle the favourite flag (no value needed).
    #[arg(long)]
    favorite: bool,
    #[arg(long)]
    unfavorite: bool,
    /// Append an extra field as LABEL=VALUE.
    #[arg(long = "field", value_name = "LABEL=VALUE")]
    fields: Vec<String>,
}

#[derive(Args, Debug)]
struct RmArgs {
    /// Item id (or an unambiguous prefix), or its exact title.
    #[arg(value_name = "ITEM")]
    item: String,
    /// Delete permanently instead of moving to the bin.
    #[arg(long)]
    purge: bool,
}

#[derive(Args, Debug)]
struct GenArgs {
    /// Password length.
    #[arg(short, long, default_value_t = 20)]
    length: usize,
    /// Exclude symbols.
    #[arg(long)]
    no_symbols: bool,
    /// Exclude digits.
    #[arg(long)]
    no_digits: bool,
    /// Exclude upper-case letters.
    #[arg(long)]
    no_uppercase: bool,
    /// Include look-alike characters.
    #[arg(long)]
    allow_ambiguous: bool,
    /// Generate a passphrase instead of a password.
    #[arg(short, long)]
    passphrase: bool,
    /// Number of words in a passphrase.
    #[arg(long, default_value_t = 6)]
    words: usize,
    /// Separator between passphrase words.
    #[arg(long, default_value = "-")]
    separator: String,
    /// Generate a numeric PIN instead.
    #[arg(long, num_args = 0..=1, default_missing_value = "4", value_name = "LENGTH")]
    pin: Option<usize>,
}

#[derive(Args, Debug)]
struct OtpArgs {
    /// Item id (or an unambiguous prefix), or its exact title.
    #[arg(value_name = "ITEM")]
    item: String,
    /// Keep printing the code until it changes (for a terminal sticky window).
    #[arg(short, long)]
    watch: bool,
}

#[derive(Args, Debug)]
struct AuditArgs {
    /// Check passwords against Have I Been Pwned (only hash prefixes are sent).
    #[arg(long)]
    breach: bool,
    /// Never touch the network.
    #[arg(long, conflicts_with = "breach")]
    offline: bool,
    /// Also list items that have never been used.
    #[arg(long)]
    unused: bool,
}

#[derive(Args, Debug)]
struct ImportArgs {
    /// The file to import.
    #[arg(value_name = "FILE")]
    file: PathBuf,
    /// Format; `auto` sniffs the contents.
    #[arg(short, long, value_enum, default_value_t = FormatChoices::Auto)]
    format: FormatChoices,
    /// Wrap everything in this category.
    #[arg(short, long, value_name = "NAME")]
    category: Option<String>,
    /// Overwrite existing items with the same title and username.
    #[arg(long)]
    overwrite: bool,
    /// Parse and report, but do not save anything.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FormatChoices {
    Auto,
    EnpassJson,
    EnpassCsv,
    BitwardenJson,
    BitwardenCsv,
    LastpassCsv,
    ChromeCsv,
    OnepasswordCsv,
    KeepassCsv,
    GenericCsv,
}

impl From<FormatChoices> for ImportFormat {
    fn from(value: FormatChoices) -> Self {
        match value {
            FormatChoices::Auto => ImportFormat::Auto,
            FormatChoices::EnpassJson => ImportFormat::EnpassJson,
            FormatChoices::EnpassCsv => ImportFormat::EnpassCsv,
            FormatChoices::BitwardenJson => ImportFormat::BitwardenJson,
            FormatChoices::BitwardenCsv => ImportFormat::BitwardenCsv,
            FormatChoices::LastpassCsv => ImportFormat::LastPassCsv,
            FormatChoices::ChromeCsv => ImportFormat::ChromeCsv,
            FormatChoices::OnepasswordCsv => ImportFormat::OnePasswordCsv,
            FormatChoices::KeepassCsv => ImportFormat::KeePassCsv,
            FormatChoices::GenericCsv => ImportFormat::GenericCsv,
        }
    }
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Destination file.
    #[arg(value_name = "FILE")]
    file: PathBuf,
    /// `csv` and `json` are **plaintext**; `backup` copies the encrypted vault.
    #[arg(short, long, value_enum, default_value_t = ExportChoices::Backup)]
    format: ExportChoices,
    /// Refuse to overwrite an existing file.
    #[arg(long)]
    no_clobber: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExportChoices {
    Csv,
    Json,
    Backup,
}

#[derive(Args, Debug)]
struct PasswdArgs {
    /// New Argon2id cost preset (defaults to keeping the current one).
    #[arg(long, value_enum)]
    kdf: Option<KdfChoices>,
    /// Read the new master password from this file (its first line) instead of
    /// prompting for it twice. The current password still comes from
    /// --password-file / --password-stdin / a prompt.
    #[arg(long, value_name = "FILE")]
    new_password_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ActivityArgs {
    /// How many entries to show.
    #[arg(short, long, default_value_t = 30)]
    limit: usize,
}

#[derive(Args, Debug)]
struct BridgeArgs {
    /// Port to listen on.
    #[arg(short, long, default_value_t = aurapass_core::DEFAULT_BRIDGE_PORT)]
    port: u16,
    /// Allow the extension to unlock the vault remotely.
    #[arg(long)]
    allow_remote_unlock: bool,
}

fn main() {
    if let Err(e) = run() {
        let message = e.to_string();
        eprintln!("aurapass: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let source = SecretSource {
        password_file: cli.password_file.clone(),
        password_stdin: cli.password_stdin,
        key_file: cli.key_file.clone(),
        allow_env: cli.password_env,
    };

    match &cli.command {
        Command::Init(args) => cmd_init(&cli, args, &source),
        Command::Info => cmd_info(&cli),
        Command::BridgeInfo => cmd_bridge_info(&cli),
        Command::Bridge(args) => cmd_bridge(&cli, args, &source),
        // Generating a password needs no vault at all.
        Command::Gen(args) => cmd_gen(&cli, args),
        // Everything else needs an unlocked vault.
        _ => {
            let mut vault = unlock(&cli, &source, "Master password: ")?;
            let result = dispatch(&cli, &mut vault);
            // Never leave changes unsaved, even when the command errored.
            if vault.is_dirty()
                && let Err(e) = vault.save()
            {
                eprintln!("aurapass: could not save the vault: {e}");
            }
            result
        }
    }
}

fn dispatch(cli: &Cli, vault: &mut UnlockedVault) -> Result<()> {
    match &cli.command {
        Command::List(args) => cmd_list(cli, vault, args),
        Command::Show(args) => cmd_show(cli, vault, args),
        Command::Get(args) => cmd_get(cli, vault, args),
        Command::Add(args) => cmd_add(cli, vault, args),
        Command::Edit(args) => cmd_edit(cli, vault, args),
        Command::Rm(args) => cmd_rm(cli, vault, args),
        Command::Restore { item } => cmd_restore(cli, vault, item),
        Command::EmptyBin => cmd_empty_bin(cli, vault),
        Command::Otp(args) => cmd_otp(cli, vault, args),
        Command::Audit(args) => cmd_audit(cli, vault, args),
        Command::Import(args) => cmd_import(cli, vault, args),
        Command::Export(args) => cmd_export(cli, vault, args),
        Command::Passwd(args) => cmd_passwd(cli, vault, args),
        Command::Categories => cmd_categories(cli, vault),
        Command::Activity(args) => cmd_activity(cli, vault, args),
        Command::Init(_) | Command::Info | Command::Bridge(_) | Command::BridgeInfo | Command::Gen(_) => {
            unreachable!("handled before unlocking")
        }
    }
}

// ------------------------------------------------------------------ vault

fn resolve_vault_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = &cli.vault {
        return Ok(expand_tilde(&path.to_string_lossy()));
    }
    let config = AppConfig::load();
    if let Some(recent) = config.pinned_vaults().first() {
        return Ok(recent.path.clone());
    }
    Err(Error::other(
        "no vault selected: pass --vault <file>, set $AURAPASS_VAULT, or create one with `aurapass init`",
    ))
}

fn unlock(cli: &Cli, source: &SecretSource, prompt: &str) -> Result<UnlockedVault> {
    let path = resolve_vault_path(cli)?;
    let file = VaultFile::load(&path)?;
    let secret = console::resolve_secret(source, prompt)?;
    let vault = file.unlock(&secret.password, secret.keyfile_bytes())?;
    Ok(vault)
}

fn cmd_init(cli: &Cli, args: &InitArgs, source: &SecretSource) -> Result<()> {
    let path = match &args.path {
        Some(p) => expand_tilde(&p.to_string_lossy()),
        // Fall back to the global `--vault` so `init --vault foo` works too.
        None => match &cli.vault {
            Some(p) => expand_tilde(&p.to_string_lossy()),
            None => {
                let name = args.name.clone().unwrap_or_else(|| "AuraPass".into());
                AppConfig::suggested_vault_path(&name)
            }
        },
    };
    if path.exists() {
        return Err(Error::other(format!(
            "{} already exists — refusing to overwrite it",
            path.display()
        )));
    }
    let name = args.name.clone().unwrap_or_else(|| {
        path.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "AuraPass".into())
    });

    // A generated key file is written before the vault so a failure cannot
    // leave a vault that nobody can open.
    let mut keyfile_bytes: Option<Vec<u8>> = None;
    if let Some(target) = &args.generate_key_file {
        let target = expand_tilde(&target.to_string_lossy());
        if target.exists() {
            return Err(Error::other(format!(
                "{} already exists",
                target.display()
            )));
        }
        let material = aurapass_core::crypto::random_vec(64);
        aurapass_core::util::atomic_write(&target, &material, 0o600)?;
        if !cli.quiet {
            println!("Wrote key file {}", target.display());
            println!("Keep it somewhere safe: without it the vault cannot be opened.");
        }
        keyfile_bytes = Some(material);
    } else if let Some(existing) = &args.key_file {
        keyfile_bytes = Some(console::read_keyfile(&expand_tilde(
            &existing.to_string_lossy(),
        ))?);
    }

    let secret = if keyfile_bytes.is_some() {
        // With a key file the password still matters, but a file-only vault is
        // not offered: two factors should be independent.
        console::resolve_secret(source, "Master password for the new vault: ")?
    } else if source.password_file.is_some() || source.password_stdin {
        console::resolve_secret(source, "Master password for the new vault: ")?
    } else {
        let password = console::prompt_new_password(
            "Choose a master password: ",
            "Confirm master password: ",
        )?;
        aurapass_core::vault::validate_master_password(&password)?;
        let strength = aurapass_core::strength::evaluate(&password, &[]);
        if strength.score < 2 {
            return Err(Error::WeakPassword(format!(
                "that master password is rated “{}” ({}); pick something longer",
                strength.label, strength.crack_time
            )));
        }
        console::Secret::password_only(password)
    };

    let keyfile = keyfile_bytes.or_else(|| secret.keyfile.clone());
    let vault = VaultFile::create(
        &path,
        &secret.password,
        name.clone(),
        args.kdf.into(),
        keyfile.as_deref(),
    )?;

    let mut config = AppConfig::load();
    config.remember_vault(&path, name.clone());
    config.save()?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "path": path,
                "name": name,
                "kdf": format!("{:?}", vault.kdf().preset().unwrap_or(KdfPreset::Interactive)),
                "memory_kib": vault.kdf().memory_kib,
                "iterations": vault.kdf().iterations,
                "has_keyfile": vault.file().envelope.has_keyfile,
            }))?
        );
    } else {
        println!("Created “{name}” at {}", path.display());
        println!(
            "Key derivation: Argon2id, {} MiB × {} pass(es){}{}",
            vault.kdf().memory_kib / 1024,
            vault.kdf().iterations,
            if vault.file().envelope.has_keyfile {
                ", with a key file"
            } else {
                ""
            },
            if vault.kdf().preset() == Some(KdfPreset::Interactive) {
                " (change it any time with `aurapass passwd --kdf paranoid`)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn cmd_info(cli: &Cli) -> Result<()> {
    let path = resolve_vault_path(cli)?;
    let file = VaultFile::load(&path)?;
    let info = file.info();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "path": info.path,
                "name": info.name,
                "vault_id": info.vault_id,
                "version": info.version,
                "created_at": info.created_at,
                "updated_at": info.updated_at,
                "revision": info.revision,
                "size_bytes": info.size_bytes,
                "has_keyfile": info.has_keyfile,
                "kdf": {
                    "algo": "argon2id",
                    "memory_kib": info.kdf.memory_kib,
                    "iterations": info.kdf.iterations,
                    "parallelism": info.kdf.parallelism,
                },
            }))?
        );
    } else {
        println!("Vault:        {}", info.name);
        println!("File:         {}", info.path.display());
        println!("Id:           {}", info.vault_id);
        println!("Format:       version {} ({})", info.version, aurapass_core::APP_NAME);
        println!("Created:      {}", info.created_at.to_rfc3339());
        println!("Last saved:   {}", info.updated_at.to_rfc3339());
        println!("Revision:     {}", info.revision);
        println!("Size:         {}", aurapass_core::util::human_bytes(info.size_bytes));
        println!(
            "Key deriv.:   Argon2id {} MiB × {} pass(es), parallelism {}",
            info.kdf.memory_kib / 1024,
            info.kdf.iterations,
            info.kdf.parallelism
        );
        println!(
            "Key file:     {}",
            if info.has_keyfile { "yes" } else { "no" }
        );
        let mode = std::fs::metadata(&info.path)
            .ok()
            .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
            .unwrap_or_else(|| "?".into());
        println!("Permissions:  {mode}");
    }
    Ok(())
}

fn cmd_bridge_info(cli: &Cli) -> Result<()> {
    let config = AppConfig::load();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "enabled": config.bridge.enabled,
                "address": config.bridge.address(),
                "token": config.bridge.token,
                "require_gui": config.bridge.require_gui,
            }))?
        );
    } else {
        println!("Address: {}", config.bridge.address());
        println!("Token:   {}", config.bridge.token);
        println!(
            "Enabled: {}{}",
            config.bridge.enabled,
            if config.bridge.require_gui {
                " (unlocking requires the desktop app)"
            } else {
                " (the extension may unlock remotely)"
            }
        );
    }
    Ok(())
}

fn cmd_bridge(cli: &Cli, args: &BridgeArgs, source: &SecretSource) -> Result<()> {
    use std::sync::Arc;
    let config = AppConfig::load();
    let vault = unlock(cli, source, "Master password: ")?;
    let mut bridge_config = config.bridge.clone();
    bridge_config.port = args.port;
    bridge_config.require_gui = !args.allow_remote_unlock;
    let name = vault.name().to_string();
    let items = vault.stats().items;
    let bridge = Arc::new(aurapass_bridge::Bridge::with_vault(bridge_config, vault));
    let running = aurapass_bridge::start(bridge.clone(), args.port)?;
    if !cli.quiet {
        println!("Unlocked “{name}” ({items} items)");
        println!("Bridge listening on ws://{}", running.address());
        println!("Pairing token: {}", bridge.token());
        println!("Press Ctrl-C to stop.");
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        bridge.flush_if_dirty()?;
    }
}

// ------------------------------------------------------------------ items

fn build_query(args: &ListArgs) -> Result<VaultQuery> {
    let kinds = args
        .kind
        .iter()
        .map(|k| parse_kind(k))
        .collect::<Result<Vec<_>>>()?;
    Ok(VaultQuery {
        text: args.query.clone().unwrap_or_default(),
        kinds,
        tags: args.tag.clone(),
        favorites_only: args.favorites,
        include_trashed: args.trash,
        only_trashed: args.only_trash,
        sort: args.sort.into(),
        category: None,
    })
}

fn parse_kind(raw: &str) -> Result<ItemKind> {
    let key = raw
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '_'], "-");
    let kind = match key.as_str() {
        "login" | "logins" => ItemKind::Login,
        "password" | "passwords" => ItemKind::Password,
        "note" | "notes" | "secure-note" => ItemKind::SecureNote,
        "card" | "credit-card" | "creditcard" => ItemKind::CreditCard,
        "bank" | "bank-account" => ItemKind::BankAccount,
        "identity" => ItemKind::Identity,
        "ssh" | "ssh-key" => ItemKind::SshKey,
        "api" | "api-key" => ItemKind::ApiKey,
        "wifi" | "wi-fi" => ItemKind::Wifi,
        "license" | "licence" | "software-license" => ItemKind::SoftwareLicense,
        "database" | "db" => ItemKind::Database,
        "server" => ItemKind::Server,
        "custom" => ItemKind::Custom,
        other => {
            return Err(Error::other(format!(
                "unknown kind {other:?}; try: login, password, secure-note, credit-card, bank-account, identity, ssh-key, api-key, wifi, software-license, database, server, custom"
            )));
        }
    };
    Ok(kind)
}

fn cmd_list(cli: &Cli, vault: &UnlockedVault, args: &ListArgs) -> Result<()> {
    let mut query = build_query(args)?;
    if let Some(category) = &args.category {
        query.category = Some(resolve_category(vault, category)?);
    }
    let ids = vault.query(&query);
    let items: Vec<&Item> = ids.iter().filter_map(|id| vault.item(*id)).collect();

    if cli.json {
        let payload: Vec<_> = items
            .iter()
            .map(|i| {
                json!({
                    "id": i.id,
                    "title": i.title,
                    "kind": i.kind,
                    "username": i.username,
                    "url": i.primary_url(),
                    "favorite": i.favorite,
                    "tags": i.tags,
                    "has_totp": i.totp.is_some(),
                    "trashed": i.trashed,
                    "updated_at": i.updated_at,
                    "password": if args.reveal { i.password.clone() } else { None::<String> },
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    if items.is_empty() {
        if !cli.quiet {
            println!("No items matched.");
        }
        return Ok(());
    }

    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| {
            let mut row = vec![
                i.id.to_string()[..8].to_string(),
                format!("{} {}", i.kind.icon(), i.title),
                i.username.clone().unwrap_or_default(),
                i.primary_url().unwrap_or("").to_string(),
                if i.totp.is_some() { "otp".into() } else { String::new() },
                if i.favorite { "★".into() } else { String::new() },
            ];
            if args.reveal {
                row.push(i.password().unwrap_or("").to_string());
            }
            row
        })
        .collect();

    let mut headers = vec!["ID", "TITLE", "USERNAME", "URL", "OTP", "★"];
    if args.reveal {
        headers.push("PASSWORD");
    }
    println!(
        "{}",
        render::table(&headers, &rows, render::TableOptions::default())
    );
    if !cli.quiet {
        println!(
            "\n{} item(s). Secrets are hidden: add --reveal to print passwords.",
            items.len()
        );
    }
    Ok(())
}

fn resolve_category(vault: &UnlockedVault, name: &str) -> Result<Uuid> {
    vault
        .data
        .categories
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))
        .map(|c| c.id)
        .ok_or_else(|| Error::CategoryNotFound(name.to_string()))
}

fn cmd_show(cli: &Cli, vault: &UnlockedVault, args: &ShowArgs) -> Result<()> {
    let id = resolve_item(vault, &args.item)?;
    let item = vault
        .item(id)
        .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;

    if cli.json {
        println!("{}", render::item_json(item, args.reveal)?);
        return Ok(());
    }

    let mask = |value: Option<&str>| -> String {
        match value {
            None | Some("") => String::new(),
            Some(v) if args.reveal => v.to_string(),
            Some(v) => "•".repeat(v.chars().count().min(24)),
        }
    };

    println!("{} {}", item.kind.icon(), item.title);
    println!("{}", render::rule());
    println!("Id:        {}", item.id);
    println!("Kind:      {}", item.kind.label());
    if let Some(username) = &item.username {
        println!("Username:  {username}");
    }
    if item.password.is_some() {
        println!("Password:  {}", mask(item.password()));
        if let Some(s) = item.strength() {
            println!("Strength:  {} ({})", s.label, s.crack_time);
        }
    }
    if let Some(url) = item.primary_url() {
        for (index, u) in item.urls.iter().enumerate() {
            println!("{}:  {u}", if index == 0 { "URL      " } else { "           " });
        }
        let _ = url;
    }
    if item.totp.is_some() {
        match Totp::parse(item.totp.as_deref().unwrap_or(""))
            .and_then(|t| t.code_at(aurapass_core::now_unix()))
        {
            Ok(code) => println!("One-time:  {} (rotates every 30s)", code),
            Err(_) => println!("One-time:  present but unreadable"),
        }
    }
    if let Some(category) = item.category.and_then(|c| vault.data.category_name(c)) {
        println!("Category:  {category}");
    }
    if !item.tags.is_empty() {
        println!("Tags:      {}", item.tags.join(", "));
    }
    if item.favorite {
        println!("Favorite:  yes");
    }
    if item.trashed {
        println!("Note:      this item is in the bin");
    }
    if let Some(expires) = item.expires_at {
        println!("Expires:   {}", expires.to_rfc3339());
    }
    if !item.fields.is_empty() {
        println!("\nCustom fields");
        for field in &item.fields {
            let value = if field.sensitive {
                mask(Some(&field.value))
            } else {
                field.value.clone()
            };
            println!("  {}: {value}", field.label);
        }
    }
    if !item.notes.is_empty() {
        println!("\nNotes\n{}", render::indent(&item.notes, "  "));
    }
    if !item.attachments.is_empty() {
        println!("\nAttachments");
        for a in &item.attachments {
            println!("  {} ({})", a.name, aurapass_core::util::human_bytes(a.size));
        }
    }
    if item.password_history.len() > 0 {
        println!("\nPrevious passwords: {}", item.password_history.len());
        for entry in item.password_history.iter().take(5) {
            println!(
                "  {}  {}",
                entry.changed_at.format("%Y-%m-%d"),
                mask(Some(&entry.password))
            );
        }
    }
    println!(
        "\nCreated {}  ·  Modified {}{}",
        item.created_at.format("%Y-%m-%d %H:%M"),
        item.updated_at.format("%Y-%m-%d %H:%M"),
        item.last_used_at
            .map(|t| format!("  ·  Last used {}", t.format("%Y-%m-%d")))
            .unwrap_or_default()
    );
    Ok(())
}

/// Fields `aurapass get` understands, so typos fail loudly instead of
/// silently printing nothing.
const GETTABLE_FIELDS: [&str; 9] = [
    "title", "username", "password", "url", "urls", "totp", "otp", "notes", "id",
];

fn cmd_get(cli: &Cli, vault: &mut UnlockedVault, args: &GetArgs) -> Result<()> {
    let id = resolve_item(vault, &args.item)?;
    let field = args.field.to_ascii_lowercase();

    if !GETTABLE_FIELDS.contains(&field.as_str()) {
        // Fall through to custom fields before giving up.
        let custom = vault
            .item(id)
            .and_then(|i| {
                i.fields
                    .iter()
                    .find(|f| f.label.eq_ignore_ascii_case(&args.field))
            })
            .map(|f| f.value.clone());
        return match custom {
            Some(value) => {
                print!("{value}");
                Ok(())
            }
            None => Err(Error::other(format!(
                "unknown field {:?}; try one of: {}",
                args.field,
                GETTABLE_FIELDS.join(", ")
            ))),
        };
    }

    let item = vault
        .item(id)
        .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;
    let value = match field.as_str() {
        "title" => item.title.clone(),
        "username" => item.username.clone().unwrap_or_default(),
        "password" => item.password.clone().unwrap_or_default(),
        "url" => item.primary_url().unwrap_or_default().to_string(),
        "urls" => item.urls.join("\n"),
        "totp" | "otp" => {
            let raw = item.totp.clone().unwrap_or_default();
            if raw.is_empty() {
                String::new()
            } else {
                Totp::parse(&raw)?.code_at(aurapass_core::now_unix())?
            }
        }
        "notes" => item.notes.clone(),
        "id" => id.to_string(),
        _ => unreachable!("checked against GETTABLE_FIELDS"),
    };

    if !cli.quiet {
        vault.note_usage(id);
    }
    // No trailing newline: this is meant for $(…) substitution.
    print!("{value}");
    use std::io::Write as _;
    std::io::stdout().flush()?;
    Ok(())
}

fn parse_extra_fields(raw: &[String]) -> Result<Vec<aurapass_core::model::Field>> {
    let mut out = Vec::new();
    for spec in raw {
        let (label, value) = spec.split_once('=').ok_or_else(|| {
            Error::other(format!("--field expects LABEL=VALUE, got {spec:?}"))
        })?;
        let sensitive = label.starts_with('!');
        let label = label.trim_start_matches('!').trim();
        if label.is_empty() {
            return Err(Error::other("a custom field needs a label"));
        }
        out.push(if sensitive {
            aurapass_core::model::Field::secret(label, value)
        } else {
            aurapass_core::model::Field::new(label, value)
        });
    }
    Ok(out)
}

fn cmd_add(cli: &Cli, vault: &mut UnlockedVault, args: &AddArgs) -> Result<()> {
    let mut item = Item::new(args.kind.into(), args.title.clone());
    item.username = args.username.clone();
    item.urls = args.url.clone();
    item.notes = args.notes.clone().unwrap_or_default();
    item.tags = args.tag.clone();
    item.favorite = args.favorite;
    item.fields = parse_extra_fields(&args.fields)?;
    if let Some(totp) = &args.totp {
        // Validate early: a broken secret would only surface much later.
        Totp::parse(totp)?;
        item.totp = Some(totp.clone());
    }
    if let Some(category) = &args.category {
        item.category = Some(vault.data.category_by_name_or_create(category));
    }

    let mut generated = None;
    let password = if let Some(length) = args.generate {
        let policy = PasswordPolicy {
            length,
            ..Default::default()
        };
        let value = generator::generate_password(&policy)?;
        generated = Some(value.clone());
        Some(value)
    } else if args.password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Some(line.trim_end_matches(['\n', '\r']).to_string())
    } else {
        args.password.clone()
    };
    if let Some(password) = password {
        item.set_password(password, aurapass_core::vault::PASSWORD_HISTORY_LIMIT);
    }

    let id = item.id;
    let title = item.title.clone();
    vault.data.upsert(item);
    vault
        .data
        .push_activity(aurapass_core::model::ActivityKind::Created, format!("Created “{title}”"), None);
    vault.mark_dirty();

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "id": id,
                "title": title,
                "password": generated.as_ref().filter(|_| args.show_generated),
            }))?
        );
    } else if !cli.quiet {
        println!("Added “{title}” ({})", &id.to_string()[..8]);
        if let Some(password) = generated.filter(|_| args.show_generated) {
            println!("Generated password: {password}");
        }
    }
    Ok(())
}

fn cmd_edit(cli: &Cli, vault: &mut UnlockedVault, args: &EditArgs) -> Result<()> {
    let id = resolve_item(vault, &args.item)?;
    let mut changed: Vec<&str> = Vec::new();

    if let Some(totp) = &args.totp {
        Totp::parse(totp)?;
    }
    let extra = parse_extra_fields(&args.fields)?;
    let category_id = args
        .category
        .as_ref()
        .map(|c| vault.data.category_by_name_or_create(c));

    let new_password = if let Some(password) = &args.password {
        Some(password.clone())
    } else if args.password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Some(line.trim_end_matches(['\n', '\r']).to_string())
    } else if let Some(length) = args.generate {
        Some(generator::generate_password(&PasswordPolicy {
            length,
            ..Default::default()
        })?)
    } else {
        None
    };
    let generated = new_password.clone().filter(|_| args.generate.is_some());

    let item = vault
        .data
        .get_mut(id)
        .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;

    if let Some(title) = &args.title {
        item.title = title.clone();
        changed.push("title");
    }
    if let Some(username) = &args.username {
        item.username = if username.is_empty() {
            None
        } else {
            Some(username.clone())
        };
        changed.push("username");
    }
    if let Some(password) = new_password {
        item.set_password(password, aurapass_core::vault::PASSWORD_HISTORY_LIMIT);
        changed.push("password");
    }
    if args.clear_urls {
        item.urls.clear();
        changed.push("urls");
    }
    for url in &args.url {
        if !item.urls.contains(url) {
            item.urls.push(url.clone());
        }
        changed.push("urls");
    }
    if args.clear_totp {
        item.totp = None;
        changed.push("totp");
    } else if let Some(totp) = &args.totp {
        item.totp = Some(totp.clone());
        changed.push("totp");
    }
    if let Some(notes) = &args.notes {
        item.notes = notes.clone();
        changed.push("notes");
    }
    for tag in &args.tag {
        if !item.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            item.tags.push(tag.clone());
        }
        changed.push("tags");
    }
    for tag in &args.untag {
        item.tags.retain(|t| !t.eq_ignore_ascii_case(tag));
        changed.push("tags");
    }
    if let Some(category) = category_id {
        item.category = Some(category);
        changed.push("category");
    }
    if args.favorite {
        item.favorite = true;
        changed.push("favorite");
    }
    if args.unfavorite {
        item.favorite = false;
        changed.push("favorite");
    }
    for field in extra {
        match item.fields.iter_mut().find(|f| f.label == field.label) {
            Some(existing) => *existing = field,
            None => item.fields.push(field),
        }
        changed.push("fields");
    }
    item.touch();
    let title = item.title.clone();

    if changed.is_empty() {
        if !cli.quiet {
            println!("Nothing to change.");
        }
        return Ok(());
    }
    vault.mark_dirty();
    vault.touch();

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "id": id, "title": title, "changed": changed,
                "password": generated,
            }))?
        );
    } else if !cli.quiet {
        println!("Updated “{title}” ({})", changed.join(", "));
        if let Some(password) = generated {
            println!("New password: {password}");
        }
    }
    Ok(())
}

fn cmd_rm(cli: &Cli, vault: &mut UnlockedVault, args: &RmArgs) -> Result<()> {
    let id = resolve_item(vault, &args.item)?;
    let title = vault
        .item(id)
        .map(|i| i.title.clone())
        .unwrap_or_default();
    if args.purge {
        vault.delete_item(id)?;
        if !cli.quiet {
            println!("Deleted “{title}” permanently.");
        }
    } else {
        vault.trash_item(id)?;
        if !cli.quiet {
            println!("Moved “{title}” to the bin (use --purge to delete it for good).");
        }
    }
    Ok(())
}

fn cmd_restore(cli: &Cli, vault: &mut UnlockedVault, needle: &str) -> Result<()> {
    let id = resolve_item(vault, needle)?;
    vault.restore_item(id)?;
    if !cli.quiet {
        println!("Restored “{}”.", vault.item(id).map(|i| i.title.as_str()).unwrap_or(needle));
    }
    Ok(())
}

fn cmd_empty_bin(cli: &Cli, vault: &mut UnlockedVault) -> Result<()> {
    let purged = vault.empty_bin();
    if !cli.quiet {
        println!("Removed {purged} item(s) from the bin.");
    }
    Ok(())
}

fn cmd_gen(cli: &Cli, args: &GenArgs) -> Result<()> {
    if let Some(length) = args.pin {
        let pin = generator::generate_pin(length)?;
        println!("{pin}");
        if !cli.quiet {
            eprintln!("PIN of {length} digits. Entropy: {:.0} bits.", (length as f64) * 10f64.log2());
        }
        return Ok(());
    }
    if args.passphrase {
        let phrase = generator::generate_passphrase(
            args.words,
            &args.separator,
            true,
            true,
        )?;
        println!("{phrase}");
        if !cli.quiet {
            eprintln!(
                "{} words. Entropy: ≈{:.0} bits.",
                args.words,
                generator::passphrase_entropy_bits(args.words, true)
            );
        }
        return Ok(());
    }

    let policy = PasswordPolicy {
        length: args.length,
        symbols: !args.no_symbols,
        digits: !args.no_digits,
        uppercase: !args.no_uppercase,
        exclude_ambiguous: !args.allow_ambiguous,
        ..Default::default()
    };
    let password = generator::generate_password(&policy)?;
    println!("{password}");
    if !cli.quiet {
        eprintln!(
            "{} characters. Alphabet {}, entropy ≈{:.0} bits.",
            policy.length,
            policy.alphabet().len(),
            policy.entropy_bits()
        );
    }
    Ok(())
}

fn cmd_otp(cli: &Cli, vault: &mut UnlockedVault, args: &OtpArgs) -> Result<()> {
    let id = resolve_item(vault, &args.item)?;
    let raw = vault
        .item(id)
        .and_then(|i| i.totp.clone())
        .ok_or_else(|| Error::other("that item has no one-time-password secret"))?;
    let totp = Totp::parse(&raw)?;
    vault.note_usage(id);

    if !args.watch {
        let now = aurapass_core::now_unix();
        let code = totp.code_at(now)?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "code": code,
                    "seconds_remaining": totp.seconds_remaining(now),
                    "period": totp.period,
                    "digits": totp.digits,
                }))?
            );
        } else {
            print!("{code}");
            use std::io::Write as _;
            std::io::stdout().flush()?;
        }
        return Ok(());
    }

    // Watch mode: redraw in place until interrupted.
    let mut last: Option<String> = None;
    if !cli.quiet {
        eprintln!("Watching {}. Press Ctrl-C to stop.", totp.display_name());
    }
    loop {
        let now = aurapass_core::now_unix();
        let code = totp.code_at(now)?;
        if last.as_deref() != Some(code.as_str()) {
            let remaining = totp.seconds_remaining(now);
            print!(
                "\r{code}   {remaining:>2}s remaining   {}",
                render::bar(totp.progress(now), 20)
            );
            use std::io::Write as _;
            std::io::stdout().flush()?;
            last = Some(code);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn cmd_audit(cli: &Cli, vault: &mut UnlockedVault, args: &AuditArgs) -> Result<()> {
    let mut breaches: HashMap<Uuid, u32> = HashMap::new();
    let mut breach_note = None;

    if args.breach {
        let mut client = BreachClient::new();
        // Only the first item of each distinct password is looked up; the
        // result is then propagated to every item sharing that password.
        let pairs = vault.passwords_for_breach_check();
        match breach::check_items(&mut client, pairs) {
            Ok(found) => {
                for (_password, ids) in vault.items_sharing_passwords() {
                    let count = ids
                        .iter()
                        .find_map(|id| found.get(id).copied())
                        .unwrap_or(0);
                    if count > 0 {
                        for id in ids {
                            breaches.insert(id, count);
                        }
                    }
                }
                breach_note = Some(format!(
                    "checked {} distinct password(s) in {} request(s)",
                    found.len(),
                    client.requests()
                ));
            }
            Err(e) => {
                breach_note = Some(format!("breach check skipped: {e}"));
            }
        }
    } else if args.offline {
        breach_note = Some("offline: breach checking disabled".into());
    }

    let options = AuditOptions {
        report_unused: args.unused,
        ..AuditOptions::default()
    };
    let report = vault.audit(&breaches, &options);
    vault
        .data
        .push_activity(aurapass_core::model::ActivityKind::BreachChecked, "Ran a health audit", None);
    vault.mark_dirty();

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{} health: {}/100 ({}) ", aurapass_core::APP_NAME, report.score, report.verdict());
    println!("{}", render::rule());
    println!(
        "{} items · {} passwords · {} weak · {} reused · {} breached · {} old · {} no-2FA",
        report.counts.items,
        report.counts.passwords,
        report.counts.weak,
        report.counts.reused,
        report.counts.breached,
        report.counts.stale,
        report.counts.missing_totp,
    );
    if let Some(note) = breach_note {
        println!("({note})");
    }
    if report.findings.is_empty() {
        println!("\nNothing to fix. Nice.");
        return Ok(());
    }
    println!();
    let rows: Vec<Vec<String>> = report
        .findings
        .iter()
        .map(|f| {
            vec![
                f.severity.label().to_string(),
                f.kind.label().to_string(),
                aurapass_core::util::truncate(&f.item_title, 40),
                aurapass_core::util::truncate(&f.detail, 70),
            ]
        })
        .collect();
    println!(
        "{}",
        render::table(&["SEVERITY", "ISSUE", "ITEM", "DETAIL"], &rows, render::TableOptions::default())
    );
    println!("\n{} finding(s).", report.findings.len());
    Ok(())
}

fn cmd_import(cli: &Cli, vault: &mut UnlockedVault, args: &ImportArgs) -> Result<()> {
    let path = expand_tilde(&args.file.to_string_lossy());
    let content = std::fs::read_to_string(&path).map_err(|e| {
        Error::other(format!("could not read {}: {e}", path.display()))
    })?;
    let filename = path.file_name().map(|s| s.to_string_lossy().to_string());
    let format = match args.format.into() {
        ImportFormat::Auto => importers::detect(&content, filename.as_deref()),
        other => other,
    };
    let preview = importers::parse(&content, format)?;

    if args.dry_run {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "format": format!("{:?}", preview.format),
                    "entries": preview.items.len(),
                    "skipped": preview.skipped,
                    "warnings": preview.warnings,
                    "titles": preview.items.iter().take(50).map(|i| i.title.clone()).collect::<Vec<_>>(),
                }))?
            );
        } else {
            println!("{}", preview.summary());
            for warning in &preview.warnings {
                println!("  warning: {warning}");
            }
            for item in preview.items.iter().take(20) {
                println!("  · {}", item.title);
            }
            if preview.items.len() > 20 {
                println!("  … and {} more", preview.items.len() - 20);
            }
        }
        return Ok(());
    }

    let (added, updated, skipped) =
        vault.import_items(preview.items.clone(), args.category.as_deref(), args.overwrite);

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "format": format!("{:?}", preview.format),
                "added": added,
                "updated": updated,
                "skipped": skipped,
                "warnings": preview.warnings,
            }))?
        );
    } else {
        println!("Imported from {}: {added} added, {updated} updated, {skipped} skipped.", preview.summary());
        for warning in &preview.warnings {
            println!("  warning: {warning}");
        }
    }
    Ok(())
}

fn cmd_export(cli: &Cli, vault: &mut UnlockedVault, args: &ExportArgs) -> Result<()> {
    let path = expand_tilde(&args.file.to_string_lossy());
    if args.no_clobber && path.exists() {
        return Err(Error::other(format!(
            "{} already exists (remove --no-clobber to overwrite)",
            path.display()
        )));
    }

    match args.format {
        ExportChoices::Backup => {
            vault.export_backup(&path)?;
            if !cli.quiet {
                println!("Wrote an encrypted backup to {}.", path.display());
            }
        }
        ExportChoices::Csv => {
            let items: Vec<Item> = vault.data.active().cloned().collect();
            let csv = importers::export_csv(&items);
            importers::write_export(&path, &csv)?;
            warn_plaintext(cli, &path, items.len());
        }
        ExportChoices::Json => {
            let items: Vec<Item> = vault.data.active().cloned().collect();
            let json = importers::export_json(&items, vault.name())?;
            importers::write_export(&path, &json)?;
            warn_plaintext(cli, &path, items.len());
        }
    }
    Ok(())
}

fn warn_plaintext(cli: &Cli, path: &std::path::Path, count: usize) {
    if cli.quiet {
        return;
    }
    eprintln!(
        "⚠  Wrote {count} entries to {} in PLAINTEXT (mode 0600).",
        path.display()
    );
    eprintln!("   Delete it as soon as you have finished importing it elsewhere.");
}

fn cmd_passwd(cli: &Cli, vault: &mut UnlockedVault, args: &PasswdArgs) -> Result<()> {
    let current = console::resolve_secret(
        &SecretSource {
            password_file: cli.password_file.clone(),
            password_stdin: cli.password_stdin,
            key_file: cli.key_file.clone(),
            allow_env: cli.password_env,
        },
        "Current master password: ",
    )?;

    let new_password = match &args.new_password_file {
        Some(path) => {
            let text = std::fs::read_to_string(expand_tilde(&path.to_string_lossy()))?;
            text.lines().next().unwrap_or_default().to_string()
        }
        None => console::prompt_new_password("New master password: ", "Confirm new password: ")?,
    };
    aurapass_core::vault::validate_master_password(&new_password)?;

    vault.change_password(
        &current.password,
        &new_password,
        current.keyfile_bytes(),
        args.kdf.map(Into::into),
    )?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "changed": true,
                "kdf": {
                    "memory_kib": vault.kdf().memory_kib,
                    "iterations": vault.kdf().iterations,
                },
            }))?
        );
    } else if !cli.quiet {
        println!(
            "Master password changed. Key derivation is now Argon2id {} MiB × {}.",
            vault.kdf().memory_kib / 1024,
            vault.kdf().iterations
        );
    }
    Ok(())
}

fn cmd_categories(cli: &Cli, vault: &UnlockedVault) -> Result<()> {
    let mut counts: HashMap<Uuid, usize> = HashMap::new();
    for item in vault.data.active() {
        if let Some(category) = item.category {
            *counts.entry(category).or_default() += 1;
        }
    }
    if cli.json {
        let payload: Vec<_> = vault
            .data
            .categories
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "name": c.name,
                    "items": counts.get(&c.id).copied().unwrap_or(0),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    if vault.data.categories.is_empty() {
        println!("No categories yet.");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = vault
        .data
        .categories
        .iter()
        .map(|c| {
            vec![
                c.name.clone(),
                counts.get(&c.id).copied().unwrap_or(0).to_string(),
            ]
        })
        .collect();
    println!("{}", render::table(&["CATEGORY", "ITEMS"], &rows, render::TableOptions::default()));
    Ok(())
}

fn cmd_activity(cli: &Cli, vault: &UnlockedVault, args: &ActivityArgs) -> Result<()> {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&vault.data.activity.iter().take(args.limit).collect::<Vec<_>>())?
        );
        return Ok(());
    }
    if vault.data.activity.is_empty() {
        println!("No recorded activity yet.");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = vault
        .data
        .activity
        .iter()
        .take(args.limit)
        .map(|entry| {
            vec![
                entry.at.format("%Y-%m-%d %H:%M").to_string(),
                entry.kind.label().to_string(),
                entry.subject.clone(),
                entry.detail.clone().unwrap_or_default(),
            ]
        })
        .collect();
    println!(
        "{}",
        render::table(&["WHEN", "WHAT", "SUBJECT", "DETAIL"], &rows, render::TableOptions::default())
    );
    Ok(())
}
