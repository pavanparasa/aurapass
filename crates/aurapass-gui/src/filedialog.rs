//! Native file choosers.
//!
//! AuraPass draws its own UI and links no toolkit, so it borrows the desktop's
//! file dialog instead of shipping a worse one: `zenity` on GNOME/Ubuntu,
//! `kdialog` on KDE, then a plain fallback where the caller keeps its text
//! field. The helper runs on its own thread, so the window stays live while the
//! dialog is open, and its answer arrives as a normal message.

use std::path::{Path, PathBuf};

use iced::Task;

/// One entry in the dialog's file-type filter.
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    /// Label shown in the dialog, e.g. `Password exports`.
    pub label: &'static str,
    /// Space-separated globs, e.g. `*.csv *.json`.
    pub globs: &'static str,
}

/// Ask the desktop for a file to open.
pub fn open_file(
    title: &str,
    start: Option<&Path>,
    filter: Option<Filter>,
) -> Task<Option<PathBuf>> {
    run(Kind::Open, title, start, "", filter)
}

/// Ask the desktop where to save a file.
pub fn save_file(
    title: &str,
    start: Option<&Path>,
    file_name: &str,
    filter: Option<Filter>,
) -> Task<Option<PathBuf>> {
    run(Kind::Save, title, start, file_name, filter)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Open,
    Save,
}

fn run(
    kind: Kind,
    title: &str,
    start: Option<&Path>,
    file_name: &str,
    filter: Option<Filter>,
) -> Task<Option<PathBuf>> {
    let title = title.to_string();
    let start = start.map(Path::to_path_buf);
    let file_name = file_name.to_string();
    Task::perform(
        async move {
            // A blocking process waits here, never on the UI thread.
            let (tx, rx) = futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                let _ = tx.send(ask(kind, &title, start.as_deref(), &file_name, filter));
            });
            rx.await.ok().flatten()
        },
        |picked| picked,
    )
}

fn ask(
    kind: Kind,
    title: &str,
    start: Option<&Path>,
    file_name: &str,
    filter: Option<Filter>,
) -> Option<PathBuf> {
    match via_zenity(kind, title, start, file_name, filter) {
        Answer::Picked(path) => Some(path),
        Answer::Cancelled => None,
        Answer::Unavailable => match via_kdialog(kind, title, start, file_name, filter) {
            Answer::Picked(path) => Some(path),
            _ => None,
        },
    }
}

/// What a dialog helper told us.
enum Answer {
    /// The user chose a path.
    Picked(PathBuf),
    /// The dialog opened and was dismissed.
    Cancelled,
    /// The helper is not installed.
    Unavailable,
}

fn via_zenity(
    kind: Kind,
    title: &str,
    start: Option<&Path>,
    file_name: &str,
    filter: Option<Filter>,
) -> Answer {
    use std::process::Command;

    let mut command = Command::new("zenity");
    command.arg("--file-selection");
    command.arg(format!("--title={title}"));

    if let Some(filter) = filter {
        command.arg(format!("--file-filter={} | {}", filter.label, filter.globs));
    }

    if kind == Kind::Save {
        command.arg("--save");
        command.arg("--confirm-overwrite");
    }
    if let Some(path) = suggested_path(start, file_name) {
        command.arg(format!("--filename={}", path.display()));
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Answer::Unavailable,
        Err(_) => return Answer::Unavailable,
    };
    if !output.status.success() {
        return Answer::Cancelled;
    }
    let answer = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if answer.is_empty() {
        Answer::Cancelled
    } else {
        Answer::Picked(PathBuf::from(answer))
    }
}

/// KDE's dialog, for desktops without zenity.
fn via_kdialog(
    kind: Kind,
    title: &str,
    start: Option<&Path>,
    file_name: &str,
    filter: Option<Filter>,
) -> Answer {
    use std::process::Command;

    let mut command = Command::new("kdialog");
    command.arg(format!("--title={title}"));
    command.arg(match kind {
        Kind::Open => "--getopenfilename",
        Kind::Save => "--getsavefilename",
    });
    command.arg(
        suggested_path(start, file_name)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| ".".to_string()),
    );
    if let Some(filter) = filter {
        command.arg(format!("{} | {}", filter.globs, filter.label));
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(_) => return Answer::Unavailable,
    };
    if !output.status.success() {
        return Answer::Cancelled;
    }
    let answer = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if answer.is_empty() {
        Answer::Cancelled
    } else {
        Answer::Picked(PathBuf::from(answer))
    }
}

/// Start in the given directory (or the user's home) with a suggested name.
fn suggested_path(start: Option<&Path>, file_name: &str) -> Option<PathBuf> {
    let base = match start {
        Some(path) if path.is_dir() => path.to_path_buf(),
        Some(path) => path.parent()?.to_path_buf(),
        None => return (!file_name.is_empty()).then(|| PathBuf::from(file_name)),
    };
    if file_name.is_empty() {
        Some(base)
    } else {
        Some(base.join(file_name))
    }
}
