//! Terminal prompts. Secrets are read from /dev/tty with echo off, never from arguments.
//! For automation (CI, tests) DOPPELKEY_PASSPHRASE supplies the vault passphrase.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, IsTerminal, Write};

pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal()
        && OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
}

/// Read a line from the terminal without echo.
pub fn secret(prompt: &str) -> Result<String, String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "no terminal to ask on".to_string())?;
    use std::os::unix::io::AsRawFd;
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let have_termios = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if have_termios {
        let mut new = old;
        new.c_lflag &= !libc::ECHO;
        new.c_lflag |= libc::ECHONL;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &new) };
    }
    let mut w = &tty;
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    let r = BufReader::new(&tty).read_line(&mut line);
    if have_termios {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    }
    r.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

pub fn passphrase(prompt: &str) -> Result<String, String> {
    if let Ok(p) = std::env::var("DOPPELKEY_PASSPHRASE") {
        return Ok(p);
    }
    secret(prompt).map_err(|_| "a passphrase is needed but there is no terminal (set DOPPELKEY_PASSPHRASE for automation)".into())
}

pub fn new_passphrase() -> Result<String, String> {
    if let Ok(p) = std::env::var("DOPPELKEY_PASSPHRASE") {
        return Ok(p);
    }
    loop {
        let a = secret("New vault passphrase: ")?;
        if a.len() < 8 {
            eprintln!("Use at least 8 characters.");
            continue;
        }
        let b = secret("Repeat passphrase: ")?;
        if a == b {
            return Ok(a);
        }
        eprintln!("Passphrases didn't match. Try again.");
    }
}

pub fn yes_no(prompt: &str) -> bool {
    if !is_interactive() {
        return false;
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}
