//! Where doppelkey keeps things. Overridable with DOPPELKEY_HOME (config + data + state).

use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Config and data (vault, key-encryption-key file).
pub fn config_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("DOPPELKEY_HOME") {
        return PathBuf::from(h);
    }
    if cfg!(target_os = "macos") {
        return home().join("Library/Application Support/doppelkey");
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("doppelkey")
}

/// Audit log location.
pub fn state_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("DOPPELKEY_HOME") {
        return PathBuf::from(h);
    }
    if cfg!(target_os = "macos") {
        return home().join("Library/Logs/doppelkey");
    }
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"))
        .join("doppelkey")
}

pub fn vault_file() -> PathBuf {
    config_dir().join("vault.dk")
}

pub fn audit_file() -> PathBuf {
    state_dir().join("audit.jsonl")
}

/// Same resolution as the shims (docs/protocol.md).
pub fn socket_path() -> PathBuf {
    if let Some(s) = std::env::var_os("DOPPELKEY_SOCK") {
        return PathBuf::from(s);
    }
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(x).join("doppelkey/doppelkeyd.sock");
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    tmp.join(format!("doppelkey-{}", unsafe { libc::getuid() }))
        .join("doppelkeyd.sock")
}
