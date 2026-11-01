//! Prompts the keeper shows a human: per-key `confirm = true` (like `ssh-add -c`), and approval
//! of eject or policy loosening on vaults without a passphrase (see admin.rs). The keeper runs
//! the prompt itself, so it appears outside any agent's terminal.
//!
//! Program, first match wins: $DOPPELKEY_ASKPASS (exit 0 = allow) where the caller allows it,
//! macOS `/usr/bin/osascript`, Linux `/usr/bin/zenity` or `/usr/bin/kdialog`. Programs are run
//! by absolute path from a directory a same-user process can't write, so a fake `osascript`
//! earlier on PATH can't answer. With none available the request is refused.

use std::process::{Command, Stdio};

pub enum Answer {
    Allow,
    Deny,
    Unavailable,
}

pub fn ask(prompt: &str, allow_askpass: bool) -> Answer {
    let run = |mut c: Command| -> Option<bool> {
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c.status().ok().map(|s| s.success())
    };
    if let Some(prog) = std::env::var_os("DOPPELKEY_ASKPASS").filter(|_| allow_askpass) {
        let mut c = Command::new(prog);
        c.arg(prompt);
        return match run(c) {
            Some(true) => Answer::Allow,
            Some(false) => Answer::Deny,
            None => Answer::Unavailable,
        };
    }
    if cfg!(target_os = "macos") {
        let script = format!(
            "display dialog \"{}\" with title \"doppelkey\" buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" giving up after 60",
            prompt.replace('\\', "\\\\").replace('"', "\\\"")
        );
        // Only an explicit click on Allow counts. A timeout ("gave up:true") also exits 0.
        return match Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                if out.status.success()
                    && text.contains("button returned:Allow")
                    && !text.contains("gave up:true")
                {
                    Answer::Allow
                } else {
                    Answer::Deny
                }
            }
            Err(_) => Answer::Unavailable,
        };
    }
    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        for (prog, args) in [
            (
                "/usr/bin/zenity",
                vec!["--question", "--title=doppelkey", "--timeout=60"],
            ),
            ("/usr/bin/kdialog", vec!["--title", "doppelkey", "--yesno"]),
        ] {
            let mut c = Command::new(prog);
            c.args(&args);
            if prog.ends_with("zenity") {
                c.arg(format!("--text={prompt}"));
            } else {
                c.arg(prompt);
            }
            if let Some(ok) = run(c) {
                return if ok { Answer::Allow } else { Answer::Deny };
            }
        }
    }
    Answer::Unavailable
}
