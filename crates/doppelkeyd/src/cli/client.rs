//! Blocking client for the keeper socket (CLI side).

use crate::paths;
use doppelkey_proto::wire;
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct Client {
    stream: UnixStream,
    next: u64,
}

#[derive(Debug)]
pub struct KeeperError {
    pub code: String,
    pub message: String,
    pub hint: Option<String>,
}

impl std::fmt::Display for KeeperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(h) = &self.hint {
            if h.starts_with("doppelkey ") {
                write!(f, ". Run \"{h}\".")?;
            } else {
                write!(f, ". {h}")?;
            }
        }
        Ok(())
    }
}

impl Client {
    pub fn connect() -> Result<Client, KeeperError> {
        let sock = paths::socket_path();
        let stream = UnixStream::connect(&sock).map_err(|_| KeeperError {
            code: "keeper_unreachable".into(),
            message: format!("keeper not running (no keeper at {})", sock.display()),
            hint: Some("doppelkey service install".into()),
        })?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
        Ok(Client { stream, next: 1 })
    }

    pub fn call(&mut self, op: &str, mut params: Value) -> Result<Value, KeeperError> {
        let id = self.next;
        self.next += 1;
        if !params.is_object() {
            params = json!({});
        }
        params["v"] = json!(1);
        params["id"] = json!(id);
        params["op"] = json!(op);
        let io = |e: std::io::Error| KeeperError {
            code: "keeper_unreachable".into(),
            message: format!("keeper connection failed: {e}"),
            hint: Some("doppelkey doctor".into()),
        };
        wire::write_frame(&mut self.stream, &params).map_err(io)?;
        loop {
            let reply = wire::read_frame(&mut self.stream).map_err(io)?;
            if reply.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if reply.get("ok") == Some(&Value::Bool(true)) {
                return Ok(reply.get("result").cloned().unwrap_or(Value::Null));
            }
            let e = reply.get("error").cloned().unwrap_or_default();
            return Err(KeeperError {
                code: e
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("error")
                    .into(),
                message: e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("keeper error")
                    .into(),
                hint: e.get("hint").and_then(Value::as_str).map(str::to_string),
            });
        }
    }
}

/// Ask a running keeper to re-read the vault. Ok(false) if no keeper is running.
pub fn reload_keeper() -> Result<bool, KeeperError> {
    match Client::connect() {
        Err(_) => Ok(false),
        Ok(mut c) => match c.call("reload", json!({})) {
            Ok(_) => Ok(true),
            Err(e) if e.code == "locked" => Ok(true), // passphrase vault, locked: picks it up at unlock
            Err(e) => Err(e),
        },
    }
}
