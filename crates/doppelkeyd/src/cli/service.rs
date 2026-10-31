//! Install the keeper as a user service, started outside any agent's process tree:
//! systemd (Linux) or launchd (macOS). Falls back to a detached process where neither exists.

use crate::paths;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const UNIT: &str = "doppelkeyd.service";
const LABEL: &str = "dev.doppelkey.keeper";

pub fn keeper_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let p = exe.with_file_name("doppelkeyd");
    if p.exists() {
        Ok(fs::canonicalize(&p).unwrap_or(p))
    } else {
        Err(format!("doppelkeyd not found next to {}", exe.display()))
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

pub fn unit_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".config"))
            .join("systemd/user")
            .join(UNIT)
    }
}

pub fn systemd_unit(bin: &str) -> String {
    format!(
        "[Unit]\nDescription=doppelkey keeper (holds app keys; never exports them)\nDocumentation=https://github.com/KaiHongTan/dopplekey\n\n[Service]\nType=simple\nExecStart={bin} serve\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=yes\nLockPersonality=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nPrivateTmp=yes\nUnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT\n\n[Install]\nWantedBy=default.target\n"
    )
}

pub fn launchd_plist(bin: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{LABEL}</string>\n  <key>ProgramArguments</key><array><string>{bin}</string><string>serve</string></array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ProcessType</key><string>Background</string>\n  <key>StandardErrorPath</key><string>{}</string>\n</dict>\n</plist>\n",
        paths::state_dir().join("doppelkeyd.log").display()
    )
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Install and start. Returns a description of what was done.
pub fn install() -> Result<String, String> {
    let bin = keeper_binary()?;
    let bin_s = bin.display().to_string();
    let unit = unit_path();
    fs::create_dir_all(unit.parent().unwrap()).map_err(|e| e.to_string())?;
    if cfg!(target_os = "macos") {
        fs::create_dir_all(paths::state_dir()).map_err(|e| e.to_string())?;
        fs::write(&unit, launchd_plist(&bin_s)).map_err(|e| e.to_string())?;
        let uid = unsafe { libc::getuid() };
        let _ = run("launchctl", &["bootout", &format!("gui/{uid}/{LABEL}")]);
        run(
            "launchctl",
            &[
                "bootstrap",
                &format!("gui/{uid}"),
                &unit.display().to_string(),
            ],
        )?;
        return Ok(format!("installed launchd agent {}", unit.display()));
    }
    fs::write(&unit, systemd_unit(&bin_s)).map_err(|e| e.to_string())?;
    match run("systemctl", &["--user", "daemon-reload"])
        .and_then(|_| run("systemctl", &["--user", "enable", "--now", UNIT]))
    {
        Ok(()) => Ok(format!("installed systemd user service {}", unit.display())),
        Err(e) => {
            let how = start_detached()?;
            Ok(format!(
                "wrote {} but systemd is not available ({e}); {how}",
                unit.display()
            ))
        }
    }
}

pub fn uninstall() -> Result<String, String> {
    let unit = unit_path();
    if cfg!(target_os = "macos") {
        let uid = unsafe { libc::getuid() };
        let _ = run("launchctl", &["bootout", &format!("gui/{uid}/{LABEL}")]);
    } else {
        let _ = run("systemctl", &["--user", "disable", "--now", UNIT]);
    }
    let _ = stop_detached();
    if unit.exists() {
        fs::remove_file(&unit).map_err(|e| e.to_string())?;
        Ok(format!("removed {}", unit.display()))
    } else {
        Ok("no service was installed".into())
    }
}

fn pid_file() -> PathBuf {
    paths::state_dir().join("doppelkeyd.pid")
}

/// Start the keeper as a detached session leader (no systemd/launchd available).
pub fn start_detached() -> Result<String, String> {
    use std::os::unix::process::CommandExt;
    let bin = keeper_binary()?;
    fs::create_dir_all(paths::state_dir()).map_err(|e| e.to_string())?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths::state_dir().join("doppelkeyd.log"))
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&bin);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log);
    for v in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "NODE_OPTIONS",
    ] {
        cmd.env_remove(v);
    }
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", bin.display()))?;
    let _ = fs::write(pid_file(), child.id().to_string());
    for _ in 0..50 {
        if std::os::unix::net::UnixStream::connect(paths::socket_path()).is_ok() {
            return Ok(format!(
                "started doppelkeyd (pid {}) in the background",
                child.id()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!(
        "doppelkeyd did not start; see {}",
        paths::state_dir().join("doppelkeyd.log").display()
    ))
}

pub fn stop_detached() -> Result<(), String> {
    let pid: i32 = fs::read_to_string(pid_file())
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "bad pid file".to_string())?;
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let _ = fs::remove_file(pid_file());
    Ok(())
}

pub fn installed() -> bool {
    unit_path().exists()
}
