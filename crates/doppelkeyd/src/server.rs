//! The keeper's socket server (tokio). One task per connection; requests run on the blocking
//! pool so a slow op (PBKDF2, a confirm prompt) never stalls other clients. Replies carry the
//! request id and may be sent out of order.

use crate::audit::{peer_exe, Audit, Peer};
use crate::confirm;
use crate::ops::{self, Precheck};
use crate::state::State;
use crate::store;
use doppelkey_proto::wire::{self, MAX_FRAME};
use doppelkey_proto::ErrorCode;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// Where the keeper's keys come from (for unlock / reload).
pub enum Source {
    /// Insecure JSON vault of fake secrets (compatibility tests only).
    TestVault(PathBuf),
    /// The encrypted vault; `kek` is held in memory while unlocked.
    Vault {
        path: PathBuf,
        kek: Mutex<Option<crate::state::LockedKey>>,
    },
}

pub struct Shared {
    pub state: Mutex<State>,
    pub audit: Audit,
    pub source: Source,
}

impl Shared {
    /// Re-read keys from the source (after the CLI changed the vault).
    fn reload(&self, passphrase: Option<&str>) -> Result<(), String> {
        let new_state = match &self.source {
            Source::TestVault(p) => store::load_test_vault(p)?,
            Source::Vault { path, kek } => {
                let mut guard = kek.lock().unwrap();
                if guard.is_none() || passphrase.is_some() {
                    let (header, _, _) = store::read_header(path)?;
                    *guard = Some(store::kek_for(&header, passphrase)?);
                }
                let (_, data) = store::open(path, guard.as_ref().unwrap().bytes())?;
                data.to_state()?
            }
        };
        *self.state.lock().unwrap() = new_state;
        Ok(())
    }

    fn lock_keys(&self) {
        self.state.lock().unwrap().wipe();
        if let Source::Vault { kek, .. } = &self.source {
            *kek.lock().unwrap() = None;
        }
    }
}

/// Load keys from the source now (used at startup for key-file and keychain vaults).
pub fn reload_now(shared: &Shared) -> Result<(), String> {
    shared.reload(None)
}

/// Bind the socket (0600 in a 0700 directory) and serve forever.
pub async fn serve(
    sock: &Path,
    shared: Arc<Shared>,
    ready: impl FnOnce(&Path),
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = sock.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if sock.exists() {
        if UnixStream::connect(sock).await.is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("another keeper is already listening on {}", sock.display()),
            ));
        }
        std::fs::remove_file(sock)?;
    }
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
    ready(sock);
    loop {
        let (stream, _) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move { connection(stream, shared).await });
    }
}

async fn connection(stream: UnixStream, shared: Arc<Shared>) {
    let cred = stream.peer_cred().ok();
    let me = unsafe { libc::geteuid() };
    let pid = cred.as_ref().and_then(|c| c.pid());
    let (mut rd, mut wr) = stream.into_split();
    if cred.as_ref().map(|c| c.uid()) != Some(me) {
        // Refuse other users outright (the socket mode should already prevent this).
        let _ = wr
            .write_all(&wire::encode_frame(&wire::err(
                0,
                ErrorCode::OpNotAllowed,
                "connections from other users are refused",
                None,
            )))
            .await;
        return;
    }
    let peer = Arc::new(Peer {
        pid,
        exe: peer_exe(pid),
    });
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    loop {
        let mut len = [0u8; 4];
        if rd.read_exact(&mut len).await.is_err() {
            break;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            break;
        }
        let mut body = vec![0u8; n];
        if rd.read_exact(&mut body).await.is_err() {
            break;
        }
        let (shared, peer, tx) = (shared.clone(), peer.clone(), tx.clone());
        tokio::spawn(async move {
            let reply = tokio::task::spawn_blocking(move || dispatch(&shared, &body, &peer))
                .await
                .unwrap_or_else(|_| wire::err(0, ErrorCode::BadRequest, "internal error", None));
            let _ = tx.send(wire::encode_frame(&reply));
        });
    }
    drop(tx);
    let _ = writer.await;
}

/// Handle one request frame and return the reply. Never panics on bad input.
pub fn dispatch(shared: &Shared, body: &[u8], peer: &Peer) -> Value {
    let req: Value = match serde_json::from_slice(body) {
        Ok(v @ Value::Object(_)) => v,
        _ => {
            return wire::err(
                0,
                ErrorCode::BadRequest,
                "request must be a JSON object",
                None,
            )
        }
    };
    let id = req.get("id").and_then(Value::as_u64).unwrap_or(0);
    let op = req
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if req.get("v").and_then(Value::as_u64) != Some(1) {
        return wire::err(
            id,
            ErrorCode::VersionMismatch,
            &format!(
                "protocol version {} is not supported (this keeper speaks v1)",
                req.get("v").unwrap_or(&Value::Null)
            ),
            Some("doppelkey doctor"),
        );
    }
    let fail = |code: ErrorCode, msg: &str, hint: Option<&str>, key: Option<&str>| {
        shared
            .audit
            .record(&op, key, false, Some(code.as_str()), None, peer);
        wire::err(id, code, msg, hint)
    };

    // Admin ops. None of them return key material.
    match op.as_str() {
        "unlock" => {
            let pass = req.get("passphrase").and_then(Value::as_str);
            return match shared.reload(pass) {
                Ok(()) => {
                    shared.audit.record(&op, None, true, None, None, peer);
                    wire::ok(id, json!({ "unlocked": true }))
                }
                Err(e) => fail(ErrorCode::BadRequest, &e, None, None),
            };
        }
        "reload" => {
            return match shared.reload(None) {
                Ok(()) => {
                    shared.audit.record(&op, None, true, None, None, peer);
                    wire::ok(id, json!({ "reloaded": true }))
                }
                Err(e) => fail(ErrorCode::Locked, &e, Some("doppelkey unlock"), None),
            };
        }
        "confirm" => {
            // Human gate for CLI actions that weaken protection (eject, loosening a policy).
            // The keeper writes the prompt and runs it with its own environment, so the
            // program asking (possibly an agent) can't approve itself.
            let detail: String = req
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            let what = match req.get("action").and_then(Value::as_str) {
                Some("eject") => "write real secret values back to disk (doppelkey eject)",
                Some("loosen_policy") => "loosen a key's policy (doppelkey policy)",
                _ => return wire::err(id, ErrorCode::BadRequest, "unknown confirm action", None),
            };
            let who = peer
                .exe
                .clone()
                .unwrap_or_else(|| format!("pid {}", peer.pid.unwrap_or(0)));
            let prompt = format!("A program ({who}) wants to {what}: {detail}. Allow?");
            let allowed = matches!(confirm::ask(&prompt), confirm::Answer::Allow);
            shared.audit.record(
                &op,
                None,
                allowed,
                if allowed {
                    None
                } else {
                    Some("confirm_denied")
                },
                None,
                peer,
            );
            return wire::ok(id, json!({ "allowed": allowed }));
        }
        "lock" => {
            shared.lock_keys();
            shared.audit.record(&op, None, true, None, None, peer);
            return wire::ok(id, json!({ "locked": true }));
        }
        _ => {}
    }

    let key_name = ops::audit_key(&shared.state.lock().unwrap(), &req);
    let pre = ops::precheck(&mut shared.state.lock().unwrap(), &req);
    match pre {
        Err(e) => return fail(e.code, &e.message, e.hint.as_deref(), key_name.as_deref()),
        Ok(Precheck::Confirm { key, prompt }) => match confirm::ask(&prompt) {
            confirm::Answer::Allow => shared.state.lock().unwrap().approve(&key),
            confirm::Answer::Deny => return fail(ErrorCode::ConfirmDenied, &format!("use of {key} was denied"), None, Some(&key)),
            confirm::Answer::Unavailable => {
                return fail(ErrorCode::ConfirmDenied, &format!("{key} needs confirmation but no prompt program is available"), Some("Set DOPPELKEY_ASKPASS for the keeper, or run \"doppelkey policy <NAME> --no-confirm\"."), Some(&key))
            }
        },
        Ok(Precheck::Ready) => {}
    }
    let result = ops::run(&mut shared.state.lock().unwrap(), &req);
    match result {
        Ok((value, info)) => {
            shared.audit.record(
                &op,
                info.key.as_deref().or(key_name.as_deref()),
                true,
                None,
                info.scope.as_deref(),
                peer,
            );
            wire::ok(id, value)
        }
        Err(e) => fail(e.code, &e.message, e.hint.as_deref(), key_name.as_deref()),
    }
}
