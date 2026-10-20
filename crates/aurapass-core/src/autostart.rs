//! Per-user XDG autostart integration.
//!
//! The setting is stored in [`crate::config::AppConfig`], but the desktop
//! session only knows about a `.desktop` file in `~/.config/autostart`. This
//! module keeps that file in sync. It never writes to `/etc` or touches another
//! user's profile, so enabling or disabling the option needs no privileges.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::APP_NAME;
use crate::config::CONFIG_DIR_ENV;
use crate::util::atomic_write;

/// File name used in the desktop's autostart directory.
pub const FILE_NAME: &str = "aurapass.desktop";

/// The directory the desktop session reads autostart entries from.
///
/// `AURAPASS_CONFIG_DIR` relocates the whole profile for portable installs and
/// tests, so the autostart entry follows it instead of leaking into the real
/// home directory.
pub fn autostart_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CONFIG_DIR_ENV)
        && !dir.trim().is_empty()
    {
        return PathBuf::from(dir).join("autostart");
    }

    directories::BaseDirs::new()
        .map(|dirs| dirs.config_dir().join("autostart"))
        .unwrap_or_else(|| PathBuf::from(".config/autostart"))
}

/// Full path of AuraPass's autostart entry.
pub fn path() -> PathBuf {
    path_in(&autostart_dir())
}

/// Full path of AuraPass's entry inside an explicit autostart directory.
pub fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// Whether the entry currently exists.
pub fn is_enabled() -> bool {
    is_enabled_in(&autostart_dir())
}

/// Whether an entry exists in an explicit autostart directory.
pub fn is_enabled_in(dir: &Path) -> bool {
    path_in(dir).is_file()
}

/// Write (or rewrite) the autostart entry for the running executable.
pub fn enable() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    enable_at(&autostart_dir(), &executable)
}

/// Write the autostart entry into `dir` for `executable`.
///
/// Exposed separately so tests can use a temporary directory without changing
/// the process environment.
pub fn enable_at(dir: &Path, executable: &Path) -> io::Result<PathBuf> {
    let destination = path_in(dir);
    let entry = desktop_entry(executable);
    atomic_write(&destination, entry.as_bytes(), 0o644)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(destination)
}

/// Remove the autostart entry, if present.
pub fn disable() -> io::Result<()> {
    disable_in(&autostart_dir())
}

/// Remove the autostart entry from an explicit autostart directory.
pub fn disable_in(dir: &Path) -> io::Result<()> {
    match fs::remove_file(path_in(dir)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The `.desktop` entry written to the autostart directory.
fn desktop_entry(executable: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.0\n\
         Name={APP_NAME}\n\
         GenericName=Password Manager\n\
         Comment=Open AuraPass when you log in\n\
         Exec={}\n\
         Icon=aurapass\n\
         Terminal=false\n\
         Categories=Utility;Security;\n\
         StartupNotify=false\n\
         X-GNOME-Autostart-enabled=true\n\
         X-GNOME-Autostart-Delay=3\n",
        exec_value(executable)
    )
}

/// Quote an executable path for the desktop entry `Exec` key.
///
/// The spec reserves `"`, `` ` ``, `$` and `\` inside double quotes. Quoting
/// also makes paths containing spaces safe.
fn exec_value(executable: &Path) -> String {
    let mut value = String::from("\"");
    for character in executable.to_string_lossy().chars() {
        if matches!(character, '"' | '`' | '$' | '\\') {
            value.push('\\');
        }
        value.push(character);
    }
    value.push('"');
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn writes_a_valid_autostart_entry_and_removes_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let executable = Path::new("/usr/bin/aurapass-desktop");

        let path = enable_at(temp.path(), executable).expect("enable");
        assert_eq!(path, path_in(temp.path()));
        assert!(is_enabled_in(temp.path()));

        let entry = fs::read_to_string(&path).expect("read entry");
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert!(entry.contains("Exec=\"/usr/bin/aurapass-desktop\"\n"));
        assert!(entry.contains("X-GNOME-Autostart-enabled=true\n"));
        assert!(entry.contains("X-GNOME-Autostart-Delay=3\n"));
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o644
        );

        disable_in(temp.path()).expect("disable");
        assert!(!path.exists());
        assert!(!is_enabled_in(temp.path()));
        // Removing a missing entry is harmless.
        disable_in(temp.path()).expect("disable twice");
    }

    #[test]
    fn quotes_paths_with_spaces_and_reserved_characters() {
        let value = exec_value(Path::new("/opt/Aura Pass/$bin/aurapass-desktop"));
        assert_eq!(value, "\"/opt/Aura Pass/\\$bin/aurapass-desktop\"");
    }
}
