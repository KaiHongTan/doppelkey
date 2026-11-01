//! Human confirmation for keys with `confirm = true` (like `ssh-add -c`). The keeper runs the
//! prompt itself, so it appears outside any agent's terminal.
//!
//! Program, first match wins: $DOPPELKEY_ASKPASS (exit 0 = allow), macOS `osascript`,
//! Linux `zenity` or `kdialog`. With none available the request is refused.

use std::process::{Command, Stdio};

pub enum Answer {
    Allow,
    Deny,
    Unavailable,
}

pub fn ask(prompt: &str) -> Answer {
    let run = |mut c: Command| -> Option<bool> {
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c.status().ok().map(|s| s.success())
    };
    if let Some(prog) = std::env::var_os("DOPPELKEY_ASKPASS") {
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
        return match Command::new("osascript")
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
                "zenity",
                vec!["--question", "--title=doppelkey", "--timeout=60"],
            ),
            ("kdialog", vec!["--title", "doppelkey", "--yesno"]),
        ] {
            let mut c = Command::new(prog);
            c.args(&args);
            if prog == "zenity" {
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
