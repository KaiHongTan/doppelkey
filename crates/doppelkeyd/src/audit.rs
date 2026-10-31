//! Append-only JSON Lines audit log: one line per request, never any key material.

use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Audit {
    path: Option<PathBuf>,
    lock: Mutex<()>,
}

pub struct Peer {
    pub pid: Option<i32>,
    pub exe: Option<String>,
}

impl Audit {
    pub fn new(path: Option<PathBuf>) -> Audit {
        if let Some(p) = &path {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
        }
        Audit {
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn record(
        &self,
        op: &str,
        key: Option<&str>,
        ok: bool,
        code: Option<&str>,
        scope: Option<&str>,
        peer: &Peer,
    ) {
        let Some(path) = &self.path else { return };
        let mut e = json!({ "ts": now_rfc3339(), "op": op, "ok": ok });
        let o = e.as_object_mut().unwrap();
        if let Some(k) = key {
            o.insert("key".into(), Value::from(k));
        }
        if let Some(c) = code {
            o.insert("code".into(), Value::from(c));
        }
        if let Some(s) = scope {
            o.insert("scope".into(), Value::from(s));
        }
        if let Some(p) = peer.pid {
            o.insert("pid".into(), Value::from(p));
        }
        if let Some(x) = &peer.exe {
            o.insert("exe".into(), Value::from(x.as_str()));
        }
        let _g = self.lock.lock();
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{e}");
        }
    }
}

/// UTC timestamp, RFC 3339 with milliseconds, without a date-time dependency.
pub fn now_rfc3339() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil-from-days (Howard Hinnant).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

pub fn peer_exe(pid: Option<i32>) -> Option<String> {
    let pid = pid?;
    if cfg!(target_os = "linux") {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.display().to_string())
    } else {
        None
    }
}
