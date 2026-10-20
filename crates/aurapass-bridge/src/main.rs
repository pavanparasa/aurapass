//! `aurapass-bridge` — standalone browser bridge daemon.
//!
//! The desktop app runs the same server in-process; this binary exists for
//! headless machines (a home server, a VPS) where there is no GUI. It keeps an
//! encrypted vault unlocked and serves the browser extension over loopback.

use aurapass_bridge::console::{self, SecretSource};
use aurapass_bridge::{Bridge, RunningBridge};
use aurapass_core::config::AppConfig;
use aurapass_core::error::{Error, Result};
use aurapass_core::vault::VaultFile;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "aurapass-bridge",
    about = "Serves an AuraPass vault to browser extensions over localhost",
    version,
    after_help = "The bridge binds 127.0.0.1 only. Pair an extension by copying the \
                  pairing token printed by --print-token (or shown in the desktop app)."
)]
struct Args {
    /// Vault file to open. Defaults to the most recently used vault.
    #[arg(short, long, value_name = "FILE")]
    vault: Option<PathBuf>,

    /// Port to listen on (falls back to the next free port if busy).
    #[arg(short, long, default_value_t = aurapass_core::DEFAULT_BRIDGE_PORT)]
    port: u16,

    /// Read the master password from this file instead of prompting.
    #[arg(long, value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Read the master password from standard input.
    #[arg(long)]
    password_stdin: bool,

    /// Read the master password from $AURAPASS_MASTER_PASSWORD.
    #[arg(long)]
    password_env: bool,

    /// Key file required to unlock the vault.
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// Start without unlocking, and allow the extension to unlock the vault.
    ///
    /// This is off by default: with it, anyone who has the pairing token can
    /// brute-force the master password through the bridge.
    #[arg(long)]
    allow_remote_unlock: bool,

    /// Lock the vault when the last extension disconnects.
    #[arg(long)]
    lock_on_disconnect: bool,

    /// Print the pairing token and exit.
    #[arg(long)]
    print_token: bool,

    /// Rotate the pairing token, then exit.
    #[arg(long)]
    rotate_token: bool,

    /// Use a specific configuration directory.
    #[arg(long, value_name = "DIR")]
    config_dir: Option<PathBuf>,

    /// Do not remember this vault in the configuration.
    #[arg(long)]
    ephemeral: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("aurapass-bridge: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let config_dir = args.config_dir.clone();

    let mut config = match &config_dir {
        Some(dir) => AppConfig::load_from(dir),
        None => AppConfig::load(),
    };

    if args.print_token {
        println!("{}", config.bridge.token);
        println!();
        println!("Listening address: 127.0.0.1:{}", config.bridge.port);
        return Ok(());
    }
    if args.rotate_token {
        config.bridge.rotate_token();
        save_config(&config, &config_dir)?;
        println!("New pairing token: {}", config.bridge.token);
        return Ok(());
    }

    let vault_path = resolve_vault(&args, &config)?;

    let mut bridge_config = config.bridge.clone();
    bridge_config.port = args.port;
    bridge_config.require_gui = !args.allow_remote_unlock;
    bridge_config.lock_on_disconnect = args.lock_on_disconnect;

    let secret_source = SecretSource {
        password_file: args.password_file.clone(),
        password_stdin: args.password_stdin,
        key_file: args.key_file.clone(),
        allow_env: args.password_env,
    };

    let bridge = Arc::new(Bridge::new(bridge_config.clone()));
    bridge.set_vault_path(Some(vault_path.clone()));

    if !args.allow_remote_unlock {
        // Unlock eagerly so the extension has something to talk to.
        let secret = console::resolve_secret(&secret_source, "Master password: ")?;
        let file = VaultFile::load(&vault_path)?;
        let vault = file.unlock(&secret.password, secret.keyfile_bytes())?;
        println!(
            "Unlocked “{}” ({} items)",
            vault.name(),
            vault.stats().items
        );
        bridge.set_vault(Some(vault));

        if !args.ephemeral {
            let name = bridge
                .status_name()
                .unwrap_or_else(|| "AuraPass".to_string());
            config.remember_vault(&vault_path, name);
            save_config(&config, &config_dir)?;
        }
    } else {
        println!("Starting locked; the extension may unlock this vault remotely.");
    }

    let running: RunningBridge = aurapass_bridge::start(bridge.clone(), args.port)?;
    println!("Bridge listening on ws://{}", running.address());
    println!("Pairing token:  {}", bridge.token());
    println!("Press Ctrl-C to stop.");

    // Sleep forever; Ctrl-C terminates the process.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
        if let Err(e) = bridge.flush_if_dirty() {
            eprintln!("aurapass-bridge: could not save the vault: {e}");
        }
    }
}

/// Persist the config, honouring an explicit `--config-dir` when given.
fn save_config(config: &AppConfig, dir: &Option<PathBuf>) -> Result<()> {
    match dir {
        Some(dir) => config.save_to_dir(dir),
        None => config.save(),
    }
}

fn resolve_vault(args: &Args, config: &AppConfig) -> Result<PathBuf> {
    if let Some(path) = &args.vault {
        if !path.exists() {
            return Err(Error::other(format!(
                "no such vault file: {}",
                path.display()
            )));
        }
        return Ok(path.clone());
    }
    // Most recently used vault from the config.
    if let Some(recent) = config.pinned_vaults().first() {
        if recent.path.exists() {
            return Ok(recent.path.clone());
        }
        return Err(Error::other(format!(
            "the most recent vault ({}) has moved; pass --vault",
            recent.path.display()
        )));
    }
    Err(Error::other(
        "no vault selected: pass --vault <file>, or open one in the desktop app first",
    ))
}
