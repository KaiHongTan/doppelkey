//! Vault management, done by the keeper. The CLI never decrypts the vault: it asks the keeper
//! to create it, import keys, store file backups, change policies and eject. Anything that
//! reveals values (`eject`) or widens what a key can do (loosening a policy) needs a human,
//! and the keeper decides whether one approved: either the vault passphrase, which it checks
//! itself, or a prompt it shows itself. A program running as the user, an agent included, can
//! run the CLI with any arguments, environment or terminal, so nothing the CLI does can count
//! as approval.

use crate::audit::Peer;
use crate::confirm;
use crate::server::{Shared, Source};
use crate::state::{Policy, ALL_OPS};
use crate::store::{self, KekKind, StoredKey, VaultData};
use base64::Engine;
use doppelkey_proto::{handle, ErrorCode, Form};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub const OPS: &[&str] = &[
    "vault_create",
    "import",
    "backup_put",
    "policies",
    "set_policy",
    "eject",
    "forget",
];

pub struct AdminErr {
    pub code: ErrorCode,
    pub message: String,
    pub hint: Option<String>,
}

fn err(code: ErrorCode, message: impl Into<String>, hint: Option<&str>) -> AdminErr {
    AdminErr {
        code,
        message: message.into(),
        hint: hint.map(str::to_string),
    }
}

fn bad(message: impl Into<String>) -> AdminErr {
    err(ErrorCode::BadRequest, message, None)
}

type AR = Result<(Value, Option<String>), AdminErr>;

/// Handle one admin op. Returns the reply and the key name to record in the audit log.
pub fn handle(shared: &Shared, op: &str, req: &Value, peer: &Peer) -> AR {
    match op {
        "vault_create" => vault_create(shared, req),
        "import" => import(shared, req),
        "backup_put" => backup_put(shared, req),
        "policies" => policies(shared, req),
        "set_policy" => set_policy(shared, req, peer),
        "eject" => eject(shared, req, peer),
        "forget" => forget(shared, req),
        _ => Err(bad(format!("unknown admin op {op}"))),
    }
}

fn str_of<'a>(req: &'a Value, k: &str) -> Option<&'a str> {
    req.get(k).and_then(Value::as_str)
}

fn ids_of(req: &Value) -> Vec<String> {
    req.get("ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn vault_path(shared: &Shared) -> Result<&std::path::Path, AdminErr> {
    match &shared.source {
        Source::Vault { path, .. } => Ok(path),
        Source::TestVault(_) => Err(err(
            ErrorCode::OpNotAllowed,
            "the test keeper has no vault to manage",
            None,
        )),
    }
}

/// Read the vault with the keeper's key, let `f` change it, and save it if `f` succeeds.
fn with_vault<T>(
    shared: &Shared,
    save: bool,
    f: impl FnOnce(&mut VaultData) -> Result<T, AdminErr>,
) -> Result<T, AdminErr> {
    let Source::Vault { path, kek } = &shared.source else {
        return Err(err(
            ErrorCode::OpNotAllowed,
            "the test keeper has no vault to manage",
            None,
        ));
    };
    let guard = kek.lock().unwrap();
    let Some(k) = guard.as_ref() else {
        return Err(if path.exists() {
            err(
                ErrorCode::Locked,
                "the keeper is locked",
                Some("doppelkey unlock"),
            )
        } else {
            err(
                ErrorCode::BadRequest,
                "no vault yet",
                Some("doppelkey init"),
            )
        });
    };
    let (header, mut data) = store::open(path, k.bytes()).map_err(bad)?;
    let out = f(&mut data)?;
    if save {
        store::save(path, &header, k.bytes(), &data).map_err(bad)?;
    }
    Ok(out)
}

fn vault_create(shared: &Shared, req: &Value) -> AR {
    let Source::Vault { path, kek } = &shared.source else {
        return Err(err(
            ErrorCode::OpNotAllowed,
            "the test keeper has no vault to manage",
            None,
        ));
    };
    let kind: KekKind = str_of(req, "protect")
        .unwrap_or("passphrase")
        .parse()
        .map_err(bad)?;
    let mut guard = kek.lock().unwrap();
    if path.exists() {
        return Err(bad(format!("a vault already exists at {}", path.display())));
    }
    // Created here, not in the CLI, so that on macOS the Keychain item trusts doppelkeyd only.
    let k = store::create(path, kind, str_of(req, "passphrase")).map_err(bad)?;
    let (_, data) = store::open(path, k.bytes()).map_err(bad)?;
    *shared.state.lock().unwrap() = data.to_state().map_err(bad)?;
    *guard = Some(k);
    Ok((json!({ "created": true }), None))
}

#[derive(Deserialize)]
struct ImportReq {
    name: String,
    value_b64: String,
    form: Form,
    #[serde(default)]
    prefix: String,
    policy: Policy,
    project: Option<String>,
    file: Option<String>,
    original: Option<String>,
}

/// Store a new key and return its id and the handle text to write. Importing reveals nothing:
/// the caller already has the value. The same value in the same project gets the same handle.
fn import(shared: &Shared, req: &Value) -> AR {
    let r: ImportReq = serde_json::from_value(req.clone()).map_err(|e| bad(e.to_string()))?;
    for a in &r.policy.allow {
        if !ALL_OPS.contains(&a.as_str()) {
            return Err(bad(format!("unknown operation \"{a}\"")));
        }
    }
    let key = zeroize::Zeroizing::new(
        B64.decode(&r.value_b64)
            .map_err(|_| bad("value_b64 is not base64"))?,
    );
    if key.is_empty() {
        return Err(bad("empty value"));
    }
    let name = r.name.clone();
    let (id, written, inserted) = with_vault(shared, true, |data| {
        if let Some((id, k)) = data
            .keys
            .iter()
            .find(|(_, k)| k.value == r.value_b64 && k.project == r.project)
        {
            let written = match &k.written {
                Some(w) => w.clone(),
                None => handle::env_value(id, r.form, &r.prefix, key.len(), false).map_err(bad)?,
            };
            return Ok((id.clone(), written, false));
        }
        let id = loop {
            let id = handle::new_id(crate::crypto::random_bytes::<6>());
            if !data.keys.contains_key(&id) {
                break id;
            }
        };
        let written = handle::env_value(&id, r.form, &r.prefix, key.len(), false).map_err(bad)?;
        data.keys.insert(
            id.clone(),
            StoredKey {
                name: r.name.clone(),
                value: r.value_b64.clone(),
                policy: r.policy.clone(),
                form: r.form,
                project: r.project.clone(),
                file: r.file.clone(),
                original: r.original.clone(),
                written: Some(written.clone()),
                created: crate::audit::now_rfc3339(),
            },
        );
        Ok((id, written, true))
    })?;
    if inserted {
        let mut st = shared.state.lock().unwrap();
        if !st.locked {
            st.insert_root(id.clone(), r.name, key.to_vec(), r.policy);
        }
    }
    Ok((json!({ "id": id, "written": written }), Some(name)))
}

/// Keep the original contents of a project file `init` is about to change (for `eject`).
fn backup_put(shared: &Shared, req: &Value) -> AR {
    let path = str_of(req, "path").ok_or_else(|| bad("path is required"))?;
    let content = str_of(req, "content_b64").ok_or_else(|| bad("content_b64 is required"))?;
    B64.decode(content)
        .map_err(|_| bad("content_b64 is not base64"))?;
    with_vault(shared, true, |data| {
        data.backups
            .entry(path.to_string())
            .or_insert_with(|| content.to_string());
        Ok(())
    })?;
    Ok((json!({ "stored": true }), None))
}

/// Names and policies (never values), optionally filtered by name or ids.
fn policies(shared: &Shared, req: &Value) -> AR {
    let name = str_of(req, "name");
    let ids = ids_of(req);
    let list = with_vault(shared, false, |data| {
        Ok(data
            .keys
            .iter()
            .filter(|(id, k)| {
                name.is_none_or(|n| k.name == n) && (ids.is_empty() || ids.contains(id))
            })
            .map(|(id, k)| json!({ "id": id, "name": k.name, "policy": k.policy }))
            .collect::<Vec<_>>())
    })?;
    Ok((json!({ "keys": list }), None))
}

/// A change to a key's policy, as sent by `doppelkey policy`.
#[derive(Deserialize, Default)]
pub struct PolicyEdit {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    pub rate: Option<u32>,
    #[serde(default)]
    pub no_rate: bool,
    #[serde(default)]
    pub confirm: bool,
    #[serde(default)]
    pub no_confirm: bool,
    #[serde(default)]
    pub allow_service: Vec<String>,
    #[serde(default)]
    pub deny_service: Vec<String>,
}

impl PolicyEdit {
    pub fn apply(&self, p: &mut Policy) -> Result<(), String> {
        for a in &self.allow {
            if a == "sigv2" {
                p.sigv2 = true;
            } else if !ALL_OPS.contains(&a.as_str()) {
                return Err(format!(
                    "unknown operation \"{a}\" (one of: {}, sigv2)",
                    ALL_OPS.join(", ")
                ));
            } else if !p.allow.contains(a) {
                p.allow.push(a.clone());
            }
        }
        p.allow.retain(|a| !self.deny.contains(a));
        if self.deny.iter().any(|d| d == "sigv2") {
            p.sigv2 = false;
        }
        if let Some(r) = self.rate {
            p.rate_per_minute = Some(r);
        }
        if self.no_rate {
            p.rate_per_minute = None;
        }
        if self.confirm {
            p.confirm = true;
        }
        if self.no_confirm {
            p.confirm = false;
        }
        if !self.allow_service.is_empty() || !self.deny_service.is_empty() {
            let mut s = p.services.clone().unwrap_or_default();
            for x in &self.allow_service {
                if !s.contains(x) {
                    s.push(x.clone());
                }
            }
            s.retain(|x| !self.deny_service.contains(x));
            p.services = Some(s);
        }
        Ok(())
    }
}

/// Does `after` let the key do anything `before` didn't? Those changes need a human.
pub fn loosens(before: &Policy, after: &Policy) -> bool {
    let new_op = after.allow.iter().any(|a| !before.allow.contains(a));
    let rate = match (before.rate_per_minute, after.rate_per_minute) {
        (Some(_), None) => true,
        (Some(b), Some(a)) => a > b,
        _ => false,
    };
    let services = match (&before.services, &after.services) {
        (Some(_), None) => true,
        (Some(b), Some(a)) => a.iter().any(|s| !b.contains(s)),
        _ => false,
    };
    new_op
        || rate
        || services
        || (after.sigv2 && !before.sigv2)
        || (before.confirm && !after.confirm)
        || after.confirm_ttl_secs.unwrap_or(0) > before.confirm_ttl_secs.unwrap_or(0)
}

fn set_policy(shared: &Shared, req: &Value, peer: &Peer) -> AR {
    let ids = ids_of(req);
    if ids.is_empty() {
        return Err(bad("ids is required"));
    }
    let edit: PolicyEdit = serde_json::from_value(req.get("edit").cloned().unwrap_or_default())
        .map_err(|e| bad(e.to_string()))?;
    // Work out the change first, so a human prompt never holds the vault lock.
    let (name, loosen) = with_vault(shared, false, |data| {
        let mut loosen = false;
        let mut name = String::new();
        for id in &ids {
            let k = data
                .keys
                .get(id)
                .ok_or_else(|| bad(format!("no key with id {id}")))?;
            let mut after = k.policy.clone();
            edit.apply(&mut after).map_err(bad)?;
            loosen |= loosens(&k.policy, &after);
            name = k.name.clone();
        }
        Ok((name, loosen))
    })?;
    if loosen {
        human_gate(
            shared,
            "loosen a key's policy (doppelkey policy)",
            &format!("loosen the policy for {name}"),
            str_of(req, "passphrase"),
            peer,
        )?;
    }
    let updated = with_vault(shared, true, |data| {
        let mut out = Vec::new();
        for id in &ids {
            if let Some(k) = data.keys.get_mut(id) {
                edit.apply(&mut k.policy).map_err(bad)?;
                out.push((id.clone(), k.name.clone(), k.policy.clone()));
            }
        }
        Ok(out)
    })?;
    let mut st = shared.state.lock().unwrap();
    for (id, _, p) in &updated {
        if let Some(e) = st.keys.get_mut(id) {
            e.policy = p.clone();
        }
    }
    let list: Vec<Value> = updated
        .into_iter()
        .map(|(id, name, policy)| json!({ "id": id, "name": name, "policy": policy }))
        .collect();
    Ok((json!({ "keys": list }), Some(name)))
}

/// After a human approves, put the real values back into the files they came from. The
/// keeper writes them itself, to the paths recorded at import, so no key material ever crosses
/// the socket and the caller can't choose where secrets land. Also returns the backups of
/// other project files `init` changed (their pre-init contents, which hold no vault secret).
/// Keys stay in the vault until the CLI calls `forget`, so a failed restore loses nothing.
fn eject(shared: &Shared, req: &Value, peer: &Peer) -> AR {
    let ids = ids_of(req);
    let paths: Vec<String> = req
        .get("paths")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let project = str_of(req, "project").unwrap_or("this project");
    human_gate(
        shared,
        "write real secret values back to disk (doppelkey eject)",
        &format!(
            "write the real values of {} secret(s) back into the .env files of {project}",
            ids.len()
        ),
        str_of(req, "passphrase"),
        peer,
    )?;
    // Where to write: the manifest's (id, file) pairs if given, else the file recorded at import.
    // A file must be the recorded one or inside the key's project directory.
    let targets: Vec<(String, Option<String>)> = match req.get("targets").and_then(Value::as_array)
    {
        Some(t) => t
            .iter()
            .filter_map(|x| {
                Some((
                    x["id"].as_str()?.to_string(),
                    x["file"].as_str().map(str::to_string),
                ))
            })
            .collect(),
        None => ids.iter().map(|id| (id.clone(), None)).collect(),
    };
    let (restored, problems, backups) = with_vault(shared, false, |data| {
        let mut by_file: std::collections::BTreeMap<String, Vec<(&String, &StoredKey)>> =
            Default::default();
        let mut problems = Vec::new();
        for (id, file) in &targets {
            let Some(k) = data.keys.get(id) else {
                problems.push(format!("key {id} is not in the vault"));
                continue;
            };
            let in_project = |f: &str| {
                k.file.as_deref() == Some(f)
                    || k.project.as_deref().is_some_and(|p| {
                        std::path::Path::new(f).starts_with(p) && !f.contains("/../")
                    })
            };
            match file.as_deref().or(k.file.as_deref()) {
                Some(f) if in_project(f) => by_file.entry(f.to_string()).or_default().push((id, k)),
                Some(f) => problems.push(format!(
                    "{f}: outside the project {} was protected in",
                    k.name
                )),
                None => problems.push(format!("{}: no file recorded for it", k.name)),
            }
        }
        let mut restored = Vec::new();
        for (file, keys) in by_file {
            let mut text = match std::fs::read_to_string(&file) {
                Ok(t) => t,
                Err(e) => {
                    problems.push(format!("cannot read {file}: {e}"));
                    continue;
                }
            };
            let mut names = Vec::new();
            for (id, k) in keys {
                let (Some(w), Some(o)) = (&k.written, &k.original) else {
                    continue;
                };
                if text.contains(w.as_str()) {
                    text = text.replace(w.as_str(), o);
                    names.push(json!({ "id": id, "name": k.name, "file": file }));
                } else {
                    problems.push(format!(
                        "{file}: the handle for {} was not found (edited by hand?)",
                        k.name
                    ));
                }
            }
            if let Err(e) = std::fs::write(&file, text.as_bytes()) {
                problems.push(format!("cannot write {file}: {e}"));
                continue;
            }
            restored.extend(names);
        }
        // Backups are pre-init file contents. Never hand one back if it holds a vault secret.
        let secrets: Vec<&str> = data
            .keys
            .values()
            .filter_map(|k| k.original.as_deref())
            .filter(|o| o.len() >= 8)
            .collect();
        let backups: serde_json::Map<String, Value> = paths
            .iter()
            .filter_map(|p| data.backups.get(p).map(|b| (p, b)))
            .filter(|(_, b)| {
                let bytes = B64.decode(b).unwrap_or_default();
                let text = String::from_utf8_lossy(&bytes);
                !secrets.iter().any(|s| text.contains(s))
            })
            .map(|(p, b)| (p.clone(), json!(b)))
            .collect();
        Ok((restored, problems, backups))
    })?;
    let mut ej = shared.ejected.lock().unwrap();
    for r in &restored {
        if let Some(id) = r["id"].as_str() {
            ej.insert(id.to_string());
        }
    }
    Ok((
        json!({ "restored": restored, "problems": problems, "backups": backups }),
        None,
    ))
}

/// Remove keys after a successful eject (only keys this keeper just ejected), and backups.
fn forget(shared: &Shared, req: &Value) -> AR {
    let ids = ids_of(req);
    {
        let ejected = shared.ejected.lock().unwrap();
        if let Some(id) = ids.iter().find(|id| !ejected.contains(*id)) {
            return Err(err(
                ErrorCode::OpNotAllowed,
                format!("key {id} was not ejected, so it can't be removed"),
                Some("doppelkey eject"),
            ));
        }
    }
    let paths: Vec<String> = req
        .get("paths")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    with_vault(shared, true, |data| {
        for id in &ids {
            data.keys.remove(id);
        }
        for p in &paths {
            data.backups.remove(p);
        }
        Ok(())
    })?;
    let mut st = shared.state.lock().unwrap();
    let mut ejected = shared.ejected.lock().unwrap();
    for id in &ids {
        st.keys.remove(id);
        ejected.remove(id);
    }
    Ok((json!({ "removed": ids.len() }), None))
}

/// The kind of vault this keeper serves, if any.
pub fn vault_kind(shared: &Shared) -> Option<KekKind> {
    let path = vault_path(shared).ok()?;
    store::read_header(path).ok().map(|(h, _, _)| h.kek)
}

/// Decide whether a human approved `what`.
///
/// - Passphrase vault: only the vault passphrase counts, checked here. It works without a
///   display, and nothing an agent can plant (DOPPELKEY_ASKPASS or DISPLAY in the service file,
///   a fake prompt program) can stand in for it.
/// - Keychain vault (macOS): only the system dialog, run from /usr/bin/osascript.
/// - Key-file vault: no protection at rest anyway, so any prompt, including DOPPELKEY_ASKPASS.
fn human_gate(
    shared: &Shared,
    what: &str,
    detail: &str,
    passphrase: Option<&str>,
    peer: &Peer,
) -> Result<(), AdminErr> {
    let kind = vault_kind(shared);
    if kind == Some(KekKind::Passphrase) {
        let Some(pass) = passphrase else {
            return Err(err(
                ErrorCode::ConfirmDenied,
                "this needs a human: run the command yourself in a terminal and enter the vault passphrase. Nothing changed",
                None,
            ));
        };
        let path = vault_path(shared)?;
        let ok = store::read_header(path)
            .and_then(|(h, _, _)| store::kek_for(&h, Some(pass)))
            .and_then(|k| store::open(path, k.bytes()))
            .is_ok();
        if ok {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1)); // slow down guessing
        return Err(err(
            ErrorCode::ConfirmDenied,
            "wrong vault passphrase. Nothing changed",
            None,
        ));
    }
    let who = peer
        .exe
        .clone()
        .unwrap_or_else(|| format!("pid {}", peer.pid.unwrap_or(0)));
    let detail: String = detail
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let prompt = format!("A program ({who}) wants to {what}: {detail}. Allow?");
    match confirm::ask(&prompt, kind != Some(KekKind::Keychain)) {
        confirm::Answer::Allow => Ok(()),
        confirm::Answer::Deny => Err(err(
            ErrorCode::ConfirmDenied,
            "denied in the keeper's prompt. Nothing changed",
            None,
        )),
        confirm::Answer::Unavailable => Err(err(
            ErrorCode::ConfirmDenied,
            "this needs a human, but the keeper has no way to show a prompt here (no display). Nothing changed",
            Some("Use a passphrase vault on machines without a display (see SECURITY.md)."),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(allow: &[&str]) -> Policy {
        Policy {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn edited(before: &Policy, edit: PolicyEdit) -> Policy {
        let mut after = before.clone();
        edit.apply(&mut after).unwrap();
        after
    }

    #[test]
    fn loosening_is_detected() {
        let base = Policy {
            rate_per_minute: Some(10),
            confirm: true,
            services: Some(vec!["s3".into()]),
            ..pol(&["hmac"])
        };
        let loosening = [
            PolicyEdit {
                allow: vec!["aes_gcm".into()],
                ..Default::default()
            },
            PolicyEdit {
                allow: vec!["sigv2".into()],
                ..Default::default()
            },
            PolicyEdit {
                no_rate: true,
                ..Default::default()
            },
            PolicyEdit {
                rate: Some(11),
                ..Default::default()
            },
            PolicyEdit {
                no_confirm: true,
                ..Default::default()
            },
            PolicyEdit {
                allow_service: vec!["sts".into()],
                ..Default::default()
            },
        ];
        for e in loosening {
            assert!(loosens(&base, &edited(&base, e)));
        }
        let tightening = [
            PolicyEdit {
                deny: vec!["hmac".into()],
                ..Default::default()
            },
            PolicyEdit {
                rate: Some(5),
                ..Default::default()
            },
            PolicyEdit {
                confirm: true,
                ..Default::default()
            },
            PolicyEdit {
                deny_service: vec!["s3".into()],
                ..Default::default()
            },
            PolicyEdit {
                allow: vec!["hmac".into()],
                ..Default::default()
            },
        ];
        for e in tightening {
            assert!(!loosens(&base, &edited(&base, e)));
        }
        // Limiting an unrestricted key to one service, or adding a first rate limit, tightens it.
        let open = pol(&["hmac"]);
        assert!(!loosens(
            &open,
            &edited(
                &open,
                PolicyEdit {
                    allow_service: vec!["s3".into()],
                    ..Default::default()
                }
            )
        ));
        assert!(!loosens(
            &open,
            &edited(
                &open,
                PolicyEdit {
                    rate: Some(5),
                    ..Default::default()
                }
            )
        ));
    }

    #[test]
    fn unknown_ops_are_rejected() {
        let mut p = pol(&["hmac"]);
        assert!(PolicyEdit {
            allow: vec!["export".into()],
            ..Default::default()
        }
        .apply(&mut p)
        .is_err());
    }
}
