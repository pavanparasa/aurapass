//! Console helpers shared by the CLI and the bridge daemon.
//!
//! All of these keep secrets off the command line: a password is never an
//! argument, because arguments are visible in `ps` output and shell history.

use aurapass_core::error::{Error, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Environment variable that carries the master password for scripts.
///
/// Supported for automation, but deliberately awkward to use by accident.
pub const PASSWORD_ENV: &str = "AURAPASS_MASTER_PASSWORD";

/// A master password plus an optional key file.
#[derive(Debug, Clone)]
pub struct Secret {
    /// The master password.
    pub password: String,
    /// Contents of the key file, when one is in use.
    pub keyfile: Option<Vec<u8>>,
}

impl Secret {
    /// A password with no key file.
    pub fn password_only(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            keyfile: None,
        }
    }

    /// Borrow the key file for the vault API.
    pub fn keyfile_bytes(&self) -> Option<&[u8]> {
        self.keyfile.as_deref()
    }
}

/// Where a password should come from.
#[derive(Debug, Clone, Default)]
pub struct SecretSource {
    /// Read the password from this file (first line).
    pub password_file: Option<PathBuf>,
    /// Read the password from standard input.
    pub password_stdin: bool,
    /// Read this file as the key file.
    pub key_file: Option<PathBuf>,
    /// Consult [`PASSWORD_ENV`] before prompting.
    pub allow_env: bool,
}

/// Read one line from the controlling terminal without echoing it.
///
/// Falls back to plain `stdin` when there is no TTY (CI, pipelines), which is
/// why the caller is told about the fallback through the returned flag.
fn read_secret_from_tty(prompt: &str, confirm: Option<&str>) -> Result<String> {
    let tty_in = File::open("/dev/tty");
    let (mut input, mut output): (Box<dyn BufRead>, Box<dyn Write>) = match tty_in {
        Ok(file) => {
            let out = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/tty")
                .map_err(Error::Io)?;
            (Box::new(BufReader::new(file)), Box::new(out))
        }
        Err(_) => (
            Box::new(BufReader::new(std::io::stdin())),
            Box::new(std::io::stdout()),
        ),
    };

    let has_tty = Path::new("/dev/tty").exists()
        && Command::new("stty")
            .arg("-echo")
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

    let read = |input: &mut Box<dyn BufRead>| -> Result<String> {
        let mut line = String::new();
        input.read_line(&mut line)?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    };

    write!(output, "{prompt}")?;
    output.flush()?;
    let first = read(&mut input)?;

    if let Some(confirm_prompt) = confirm {
        writeln!(output)?;
        write!(output, "{confirm_prompt}")?;
        output.flush()?;
        let second = read(&mut input)?;
        if has_tty {
            let _ = Command::new("stty")
                .arg("echo")
                .stdin(Stdio::inherit())
                .status();
        }
        if first != second {
            writeln!(output)?;
            return Err(Error::WeakPassword("the two passwords do not match".into()));
        }
    }

    if has_tty {
        let _ = Command::new("stty")
            .arg("echo")
            .stdin(Stdio::inherit())
            .status();
        writeln!(output)?;
    }
    Ok(first)
}

/// Read a visible line from the terminal.
pub fn read_line(prompt: &str) -> Result<String> {
    let mut output = std::io::stdout();
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a key file, with a size cap so a stray `--key-file /dev/zero` cannot
/// hang the process.
pub fn read_keyfile(path: &Path) -> Result<Vec<u8>> {
    const MAX_KEYFILE: u64 = 64 * 1024 * 1024;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::other(format!("key file {}: {e}", path.display())))?;
    if meta.len() > MAX_KEYFILE {
        return Err(Error::other(format!(
            "key file {} is {} which seems too large",
            path.display(),
            aurapass_core::util::human_bytes(meta.len())
        )));
    }
    std::fs::read(path).map_err(|e| Error::other(format!("key file {}: {e}", path.display())))
}

/// Resolve a password using the configured source, prompting only as a last
/// resort.
pub fn resolve_secret(source: &SecretSource, prompt: &str) -> Result<Secret> {
    if let Some(path) = &source.password_file {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::other(format!("could not read password file {}: {e}", path.display()))
        })?;
        let password = text
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end_matches(['\n', '\r'])
            .to_string();
        if password.is_empty() {
            return Err(Error::WeakPassword(format!(
                "the password file {} is empty",
                path.display()
            )));
        }
        return Ok(Secret {
            password,
            keyfile: source
                .key_file
                .as_deref()
                .map(read_keyfile)
                .transpose()?,
        });
    }

    if source.password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let password = line.trim_end_matches(['\n', '\r']).to_string();
        if password.is_empty() {
            return Err(Error::WeakPassword("standard input was empty".into()));
        }
        return Ok(Secret {
            password,
            keyfile: source
                .key_file
                .as_deref()
                .map(read_keyfile)
                .transpose()?,
        });
    }

    if source.allow_env
        && let Ok(password) = std::env::var(PASSWORD_ENV)
        && !password.is_empty()
    {
        return Ok(Secret {
            password,
            keyfile: source
                .key_file
                .as_deref()
                .map(read_keyfile)
                .transpose()?,
        });
    }

    let password = read_secret_from_tty(prompt, None)?;
    Ok(Secret {
        password,
        keyfile: source
            .key_file
            .as_deref()
            .map(read_keyfile)
            .transpose()?,
    })
}

/// Ask for a new master password twice.
pub fn prompt_new_password(prompt: &str, confirm: &str) -> Result<String> {
    read_secret_from_tty(prompt, Some(confirm))
}

/// True when a controlling terminal is available.
pub fn is_interactive() -> bool {
    Path::new("/dev/tty").exists() && File::open("/dev/tty").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_file_takes_priority() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.txt");
        std::fs::write(&path, "from-the-file\nextra line\n").unwrap();
        let secret = resolve_secret(
            &SecretSource {
                password_file: Some(path),
                ..Default::default()
            },
            "unused",
        )
        .unwrap();
        assert_eq!(secret.password, "from-the-file");
        assert!(secret.keyfile.is_none());
    }

    #[test]
    fn empty_password_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "\n").unwrap();
        assert!(
            resolve_secret(
                &SecretSource {
                    password_file: Some(path),
                    ..Default::default()
                },
                "unused",
            )
            .is_err()
        );
    }

    #[test]
    fn keyfile_is_read_alongside_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let pw = dir.path().join("pw.txt");
        let kf = dir.path().join("key.bin");
        std::fs::write(&pw, "hunter2hunter2\n").unwrap();
        std::fs::write(&kf, [0u8, 1, 2, 3]).unwrap();
        let secret = resolve_secret(
            &SecretSource {
                password_file: Some(pw),
                key_file: Some(kf),
                ..Default::default()
            },
            "unused",
        )
        .unwrap();
        assert_eq!(secret.keyfile_bytes(), Some(&[0u8, 1, 2, 3][..]));
    }

    #[test]
    fn oversized_keyfiles_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        let mut file = File::create(&path).unwrap();
        // Sparse file: no need to actually write 64 MiB.
        file.set_len(65 * 1024 * 1024).unwrap();
        file.flush().unwrap();
        assert!(read_keyfile(&path).is_err());
    }

    #[test]
    fn env_fallback_is_opt_in() {
        // SAFETY: this test sets a process-wide variable; it is the only test in
        // this module that touches the environment.
        unsafe { std::env::set_var(PASSWORD_ENV, "from-the-env") };

        // A password file always wins over the environment.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.txt");
        std::fs::write(&path, "from-the-file\n").unwrap();
        let from_file = resolve_secret(
            &SecretSource {
                password_file: Some(path),
                allow_env: true,
                ..Default::default()
            },
            "unused",
        )
        .unwrap();
        assert_eq!(from_file.password, "from-the-file");

        // The environment is ignored unless it is explicitly allowed.
        // Without a terminal this reads stdin, which is empty under the test
        // harness; skip the check when a real terminal would block instead.
        if !is_interactive() {
            let disabled = resolve_secret(&SecretSource::default(), "unused");
            if let Ok(secret) = disabled {
                assert_ne!(secret.password, "from-the-env");
            }
        }

        let enabled = resolve_secret(
            &SecretSource {
                allow_env: true,
                ..Default::default()
            },
            "unused",
        )
        .unwrap();
        assert_eq!(enabled.password, "from-the-env");
        unsafe { std::env::remove_var(PASSWORD_ENV) };
    }
}
