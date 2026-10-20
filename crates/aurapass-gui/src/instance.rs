//! One desktop process per user profile.
//!
//! A second launch (dock click, menu entry, `aurapass-desktop`) does not start
//! another copy. It connects to the running instance's Unix socket, asks it to
//! come to the front, and exits. The socket therefore doubles as the single
//! instance lock and as the activation channel.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use aurapass_core::config::AppConfig;

/// Set by the listener thread when another process asks us to show the window.
static SHOW_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Keeps the listening socket alive for the lifetime of the app.
pub struct Guard {
    socket: Option<PathBuf>,
}

impl Guard {
    fn disabled() -> Self {
        Self { socket: None }
    }

    fn listening(socket: PathBuf, listener: UnixListener) -> Self {
        // The accept loop is tiny and only runs until the process exits.
        let _ = thread::Builder::new()
            .name("aurapass-instance".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else {
                        continue;
                    };
                    // Never let a client that connects and stalls keep the
                    // activation channel busy.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut request = [0u8; 32];
                    let _ = stream.read(&mut request);
                    SHOW_REQUESTED.store(true, Ordering::SeqCst);
                }
            });
        Self {
            socket: Some(socket),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(path) = &self.socket {
            let _ = fs::remove_file(path);
        }
    }
}

/// Try to become the one running instance.
///
/// `None` means another AuraPass is already running; it has been asked to show
/// its window and this process should exit. `Some` must be kept alive for the
/// whole lifetime of the application.
pub fn acquire() -> Option<Guard> {
    let dir = AppConfig::config_dir();
    if fs::create_dir_all(&dir).is_err() {
        // A read-only home should not prevent the app from starting at all.
        return Some(Guard::disabled());
    }

    let socket = socket_path(&dir);
    match bind(&socket) {
        Ok(listener) => Some(Guard::listening(socket, listener)),
        Err(_) => {
            if wake(&socket) {
                return None;
            }
            // No one answered: a previous process crashed and left the socket
            // behind. Remove it and take over.
            let _ = fs::remove_file(&socket);
            match bind(&socket) {
                Ok(listener) => Some(Guard::listening(socket, listener)),
                Err(_) => Some(Guard::disabled()),
            }
        }
    }
}

/// Whether another launch asked this instance to come to the front.
pub fn take_show_request() -> bool {
    SHOW_REQUESTED.swap(false, Ordering::SeqCst)
}

fn bind(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(listener)
}

/// Wake a running instance. Retries briefly so a simultaneous start does not
/// lose the race while the first process is still binding its socket.
fn wake(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_millis(900);
    loop {
        if let Ok(mut stream) = UnixStream::connect(path) {
            let _ = stream.write_all(b"show\n");
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(40));
    }
}

/// Unix sockets have a short path limit. The config directory normally fits;
/// fall back to a stable name under `/tmp` when it does not.
fn socket_path(dir: &Path) -> PathBuf {
    let candidate = dir.join("instance.sock");
    if candidate.as_os_str().as_bytes().len() < 100 {
        return candidate;
    }
    let mut hash = 0xcbf29ce484222325u64;
    for byte in dir.as_os_str().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    PathBuf::from(format!("/tmp/aurapass-{hash:016x}.sock"))
}
