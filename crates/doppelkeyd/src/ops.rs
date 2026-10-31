//! Protocol v1 operations. A port of `compat/test-keeper/keeper.mjs` with the same behaviour and
//! messages, so one compatibility suite covers both keepers. No op returns key material.

use crate::crypto::{self, CryptoFail, Hash};
use crate::state::{Policy, State};
use base64::Engine;
use doppelkey_proto::{handle::parse_handle, ErrorCode};
use serde_json::{json, Value};
use std::time::Duration;
use zeroize::Zeroizing;

pub const VERSION: &str = concat!("doppelkeyd-", env!("CARGO_PKG_VERSION"));

#[derive(Debug)]
pub struct KErr {
    pub code: ErrorCode,
    pub message: String,
    pub hint: Option<String>,
}

fn kerr(code: ErrorCode, message: impl Into<String>) -> KErr {
    KErr {
        code,
        message: message.into(),
        hint: None,
    }
}
fn bad(message: impl Into<String>) -> KErr {
    kerr(ErrorCode::BadRequest, message)
}

impl From<CryptoFail> for KErr {
    fn from(f: CryptoFail) -> KErr {
        match f {
            CryptoFail::Bad(m) => bad(m),
            CryptoFail::Auth => kerr(
                ErrorCode::CryptoError,
                "authentication or padding check failed",
            ),
        }
    }
}

/// Extra fields for the audit log.
#[derive(Default)]
pub struct AuditInfo {
    pub key: Option<String>,
    pub scope: Option<String>,
}

/// What a request needs before it can run (checked without blocking on a human).
pub enum Precheck {
    Ready,
    /// The key's policy asks for a human confirmation first.
    Confirm {
        key: String,
        prompt: String,
    },
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn b64(req: &Value, field: &str) -> Result<Vec<u8>, KErr> {
    match req.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => B64
            .decode(s)
            .map_err(|_| bad(format!("{field} must be base64"))),
        _ => Err(bad(format!("{field} must be base64"))),
    }
}
fn hash_field(req: &Value, field: &str) -> Result<Hash, KErr> {
    let s = req.get(field).and_then(Value::as_str).unwrap_or("");
    Hash::parse(s).ok_or_else(|| {
        bad(format!(
            "{field} \"{s}\" is not supported (sha1, sha256, sha384, sha512)"
        ))
    })
}
fn length(req: &Value) -> Result<usize, KErr> {
    match req.get("length").and_then(Value::as_u64) {
        Some(n) if (1..=1024).contains(&n) => Ok(n as usize),
        _ => Err(bad("length must be an integer between 1 and 1024")),
    }
}
fn str_field<'a>(req: &'a Value, field: &str) -> &'a str {
    req.get(field).and_then(Value::as_str).unwrap_or("")
}

/// A resolved key: bytes to use (owned copy, wiped on drop) plus the policy and names.
struct Resolved {
    key: Zeroizing<Vec<u8>>,
    name: String,
    root_name: String,
    policy: Policy,
    ids: Vec<String>,
    prefix: String,
    sigv4_stage: u8,
    scope: Vec<String>,
}

fn op_allowed(policy: &Policy, op: &str) -> bool {
    policy.allow.iter().any(|a| a == op)
        || (op == "hash_derive" && policy.allow.iter().any(|a| a == "hmac"))
}

fn resolve(state: &State, req: &Value, op: &str) -> Result<Resolved, KErr> {
    let handle = str_field(req, "handle");
    let ids = parse_handle(handle).ok_or_else(|| KErr {
        code: ErrorCode::UnknownHandle,
        message: "not a valid doppelkey handle".into(),
        hint: Some("doppelkey doctor".into()),
    })?;
    let mut parts = Vec::new();
    for id in &ids {
        parts.push(state.keys.get(id).ok_or_else(|| KErr {
            code: ErrorCode::UnknownHandle,
            message: "this handle is not in the keeper".into(),
            hint: Some("doppelkey doctor".into()),
        })?);
    }
    let (name, root_name, policy, mut key) = if parts.len() == 1 {
        let e = parts[0];
        (
            e.name.clone(),
            e.root.clone().unwrap_or_else(|| e.name.clone()),
            e.policy.clone(),
            Zeroizing::new(e.key.bytes().to_vec()),
        )
    } else {
        let name = parts
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join("+");
        let allow: Vec<String> = parts[0]
            .policy
            .allow
            .iter()
            .filter(|op| parts.iter().all(|p| p.policy.allow.contains(op)))
            .cloned()
            .collect();
        let mut k = Zeroizing::new(Vec::new());
        for p in &parts {
            k.extend_from_slice(p.key.bytes());
        }
        (
            name.clone(),
            parts[0].root.clone().unwrap_or(name),
            Policy {
                allow,
                ..Default::default()
            },
            k,
        )
    };
    if !op_allowed(&policy, op) {
        return Err(KErr {
            code: ErrorCode::OpNotAllowed,
            message: format!("{op} is not allowed for {name}"),
            hint: Some(format!("doppelkey policy {name} --allow {op}")),
        });
    }
    match req.get("key_encoding").and_then(Value::as_str) {
        None => {}
        Some("hex") => {
            key = Zeroizing::new(
                key.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .into_bytes(),
            )
        }
        Some("base64") => key = Zeroizing::new(B64.encode(&*key).into_bytes()),
        Some(_) => return Err(bad("key_encoding must be \"hex\" or \"base64\"")),
    }
    let prefix = String::from_utf8_lossy(&b64(req, "prefix")?).into_owned();
    if !prefix.is_empty() {
        let vendor = policy.prefix.as_deref() == Some(prefix.as_str());
        let sigv4 =
            policy.profile.as_deref() == Some("aws-sigv4") && prefix == "AWS4" && op == "hmac";
        if !vendor && !sigv4 {
            return Err(kerr(
                ErrorCode::OpNotAllowed,
                format!("a key of the form <prefix><handle> is not allowed for {name}"),
            ));
        }
        // Encoded forms store the decoded bytes without the vendor prefix; the text key is prefix + encoding.
        if req.get("key_encoding").is_some() {
            key = Zeroizing::new([prefix.as_bytes(), key.as_slice()].concat());
        }
    }
    let (stage, scope) = if parts.len() == 1 {
        (parts[0].sigv4_stage, parts[0].scope.clone())
    } else {
        (0, Vec::new())
    };
    Ok(Resolved {
        key,
        name,
        root_name,
        policy,
        ids,
        prefix,
        sigv4_stage: stage,
        scope,
    })
}

/// Policy checks that don't need the human: rate limits; and whether a confirm prompt is due.
pub fn precheck(state: &mut State, req: &Value) -> Result<Precheck, KErr> {
    let op = str_field(req, "op");
    if state.locked && !matches!(op, "status" | "unlock") {
        return Err(KErr {
            code: ErrorCode::Locked,
            message: "the keeper is locked".into(),
            hint: Some("doppelkey unlock".into()),
        });
    }
    if req.get("handle").is_none() {
        return Ok(Precheck::Ready);
    }
    let Some(ids) = parse_handle(str_field(req, "handle")) else {
        return Ok(Precheck::Ready);
    };
    // Policy lives on root keys; derived keys inherit their root's rate limit and confirm setting.
    let Some(e) = state.keys.get(&ids[0]) else {
        return Ok(Precheck::Ready);
    };
    let root_name = e.root.clone().unwrap_or_else(|| e.name.clone());
    let root_policy = state
        .keys
        .values()
        .find(|x| x.name == root_name && x.root.is_none())
        .map(|x| x.policy.clone())
        .unwrap_or_else(|| e.policy.clone());
    if !state.rate_ok(&root_name, root_policy.rate_per_minute) {
        return Err(KErr {
            code: ErrorCode::RateLimited,
            message: format!(
                "{root_name} is over its limit of {} operations per minute",
                root_policy.rate_per_minute.unwrap_or(0)
            ),
            hint: Some(format!("doppelkey policy {root_name} --rate <per-minute>")),
        });
    }
    if root_policy.confirm
        && !state.approved(
            &root_name,
            Duration::from_secs(root_policy.confirm_ttl_secs.unwrap_or(300)),
        )
    {
        return Ok(Precheck::Confirm {
            key: root_name.clone(),
            prompt: format!("Allow a program to use {root_name} ({op})?"),
        });
    }
    Ok(Precheck::Ready)
}

const SIGV4_STAGES: [&str; 4] = ["date", "region", "service", "aws4_request"];

fn sigv4_step(
    state: &mut State,
    r: &Resolved,
    alg: Hash,
    msg: &[u8],
    stage: u8,
) -> Result<String, KErr> {
    if alg != Hash::Sha256 {
        return Err(bad("SigV4 uses sha256"));
    }
    let text = String::from_utf8_lossy(msg).into_owned();
    if SIGV4_STAGES[stage as usize - 1] == "service" {
        if let Some(services) = &r.policy.services {
            if !services.contains(&text) {
                return Err(KErr {
                    code: ErrorCode::OpNotAllowed,
                    message: format!(
                        "service \"{text}\" is not allowed for {} (allowed: {})",
                        r.root_name,
                        services.join(", ")
                    ),
                    hint: Some(format!(
                        "doppelkey policy {} --allow-service {text}",
                        r.root_name
                    )),
                });
            }
        }
    }
    if stage == 4 && text != "aws4_request" {
        return Err(kerr(ErrorCode::OpNotAllowed, "not a SigV4 key derivation"));
    }
    let key: Zeroizing<Vec<u8>> = if stage == 1 {
        Zeroizing::new([b"AWS4".as_slice(), &r.key].concat())
    } else {
        r.key.clone()
    };
    let out = Zeroizing::new(crypto::hmac(Hash::Sha256, &key, msg));
    let mut scope = r.scope.clone();
    scope.push(text.clone());
    let policy = Policy {
        allow: vec!["hmac".into()],
        services: r.policy.services.clone(),
        ..Default::default()
    };
    state
        .new_handle(
            &out,
            &format!("sigv4|{}|{text}", r.ids.join("+")),
            Some(r.root_name.clone()),
            Some((stage, scope, policy)),
        )
        .map_err(bad)
}

fn check_aes(key: &[u8], req: &Value) -> Result<(), KErr> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(bad(format!(
            "key is {} bytes; AES needs 16, 24 or 32",
            key.len()
        )));
    }
    if let Some(bits) = req.get("key_bits").and_then(Value::as_u64) {
        if bits as usize != key.len() * 8 {
            return Err(bad(format!(
                "AES-{bits} requested but the key is {} bits",
                key.len() * 8
            )));
        }
    }
    Ok(())
}

fn mode(req: &Value) -> Result<bool, KErr> {
    match str_field(req, "mode") {
        "encrypt" => Ok(true),
        "decrypt" => Ok(false),
        _ => Err(bad("mode must be \"encrypt\" or \"decrypt\"")),
    }
}

/// Run one key operation. The caller has done `precheck` (and any confirmation).
pub fn run(state: &mut State, req: &Value) -> Result<(Value, AuditInfo), KErr> {
    let op = str_field(req, "op").to_string();
    let seed_extra =
        |r: &Resolved| format!("{}|{}", r.ids.join("+"), str_field(req, "key_encoding"));
    match op.as_str() {
        "status" => {
            let mut ids: Vec<&String> = state
                .keys
                .iter()
                .filter(|(_, e)| e.root.is_none() && !e.name.starts_with("derived:"))
                .map(|(id, _)| id)
                .collect();
            ids.sort();
            Ok((
                json!({ "version": VERSION, "protocol": 1, "locked": state.locked, "keys": state.root_names(), "ids": ids, "non_dumpable": crate::harden::is_non_dumpable() }),
                AuditInfo::default(),
            ))
        }
        "hmac" => {
            let alg = hash_field(req, "alg")?;
            let r = resolve(state, req, "hmac")?;
            let msg = b64(req, "data")?;
            let mut info = AuditInfo {
                key: Some(r.root_name.clone()),
                scope: None,
            };
            let aws = r.policy.profile.as_deref() == Some("aws-sigv4");
            if r.prefix == "AWS4" && aws {
                return Ok((
                    json!({ "handle": sigv4_step(state, &r, alg, &msg, 1)? }),
                    info,
                ));
            }
            if r.sigv4_stage > 0 && r.sigv4_stage < 4 {
                return Ok((
                    json!({ "handle": sigv4_step(state, &r, alg, &msg, r.sigv4_stage + 1)? }),
                    info,
                ));
            }
            if aws
                && Some(String::from_utf8_lossy(&msg).as_ref()) != r.policy.access_key_id.as_deref()
            {
                let text = String::from_utf8_lossy(&msg);
                let v2 = ["GET\n", "PUT\n", "HEAD\n", "POST\n", "DELETE\n"]
                    .iter()
                    .any(|m| text.starts_with(m));
                if !v2 {
                    return Err(kerr(ErrorCode::OpNotAllowed, format!("raw HMAC with {} is only allowed over its access key ID (the SDK's cache key)", r.name)));
                }
                if !r.policy.sigv2 {
                    return Err(KErr {
                        code: ErrorCode::OpNotAllowed,
                        message: format!("legacy SigV2 signing is refused for {}", r.name),
                        hint: Some(format!("Use signature_version=\"s3v4\", or run \"doppelkey policy {} --allow sigv2\".", r.name)),
                    });
                }
                info.scope = Some("sigv2".into());
            }
            if r.sigv4_stage == 4 {
                info.scope = Some(r.scope.join("/"));
            }
            Ok((
                json!({ "digest": B64.encode(crypto::hmac(alg, &r.key, &msg)) }),
                info,
            ))
        }
        "hash_derive" => {
            let h = hash_field(req, "hash")?;
            let r = resolve(state, req, "hash_derive")?;
            let full = crypto::digest(
                h,
                &[
                    b64(req, "prefix_data")?.as_slice(),
                    &r.key,
                    &b64(req, "suffix_data")?,
                ]
                .concat(),
            );
            let len = if req.get("length").is_some() {
                length(req)?
            } else {
                full.len()
            };
            if len > full.len() {
                return Err(bad(format!(
                    "length {len} exceeds the {} output",
                    str_field(req, "hash")
                )));
            }
            let seed = format!(
                "hash|{}|{}|{}|{}|{len}",
                seed_extra(&r),
                str_field(req, "hash"),
                str_field(req, "prefix_data"),
                str_field(req, "suffix_data")
            );
            let handle = state
                .new_handle(&full[..len], &seed, Some(r.root_name.clone()), None)
                .map_err(bad)?;
            Ok((
                json!({ "handle": handle }),
                AuditInfo {
                    key: Some(r.root_name),
                    scope: None,
                },
            ))
        }
        "hkdf" => {
            let h = hash_field(req, "hash")?;
            let r = resolve(state, req, "hkdf")?;
            let len = length(req)?;
            let out = crypto::hkdf(h, &r.key, &b64(req, "salt")?, &b64(req, "info")?, len)
                .map_err(bad)?;
            let seed = format!(
                "hkdf|{}|{}|{}|{}|{len}",
                seed_extra(&r),
                str_field(req, "hash"),
                str_field(req, "salt"),
                str_field(req, "info")
            );
            let handle = state
                .new_handle(&out, &seed, Some(r.root_name.clone()), None)
                .map_err(bad)?;
            Ok((
                json!({ "handle": handle }),
                AuditInfo {
                    key: Some(r.root_name),
                    scope: None,
                },
            ))
        }
        "pbkdf2" => {
            let h = hash_field(req, "hash")?;
            let r = resolve(state, req, "pbkdf2")?;
            let len = length(req)?;
            let iterations = match req.get("iterations").and_then(Value::as_u64) {
                Some(n) if (1..=10_000_000).contains(&n) => n as u32,
                _ => return Err(bad("iterations must be an integer between 1 and 10000000")),
            };
            let out = crypto::pbkdf2(h, &r.key, &b64(req, "salt")?, iterations, len);
            let seed = format!(
                "pbkdf2|{}|{}|{}|{iterations}|{len}",
                seed_extra(&r),
                str_field(req, "hash"),
                str_field(req, "salt")
            );
            let handle = state
                .new_handle(&out, &seed, Some(r.root_name.clone()), None)
                .map_err(bad)?;
            Ok((
                json!({ "handle": handle }),
                AuditInfo {
                    key: Some(r.root_name),
                    scope: None,
                },
            ))
        }
        "aes_gcm" => {
            let r = resolve(state, req, "aes_gcm")?;
            check_aes(&r.key, req)?;
            let iv = b64(req, "iv")?;
            if iv.len() != 12 {
                return Err(bad("AES-GCM needs a 12-byte IV in protocol v1"));
            }
            let enc = mode(req)?;
            let data = b64(req, "data")?;
            if !enc && data.len() < 16 {
                return Err(kerr(
                    ErrorCode::CryptoError,
                    "ciphertext shorter than the tag",
                ));
            }
            let out = crypto::aes_gcm(enc, &r.key, &iv, &data, &b64(req, "aad")?).map_err(|e| {
                if matches!(e, CryptoFail::Auth) {
                    kerr(ErrorCode::CryptoError, "AES-GCM authentication failed")
                } else {
                    e.into()
                }
            })?;
            Ok((
                json!({ "out": B64.encode(out) }),
                AuditInfo {
                    key: Some(r.root_name),
                    scope: None,
                },
            ))
        }
        "aes_cbc" => {
            let r = resolve(state, req, "aes_cbc")?;
            check_aes(&r.key, req)?;
            let iv = b64(req, "iv")?;
            if iv.len() != 16 {
                return Err(bad("AES-CBC needs a 16-byte IV"));
            }
            let enc = mode(req)?;
            let padding = req.get("padding").and_then(Value::as_bool).unwrap_or(true);
            let out =
                crypto::aes_cbc(enc, &r.key, &iv, &b64(req, "data")?, padding).map_err(|e| {
                    if matches!(e, CryptoFail::Auth) {
                        kerr(ErrorCode::CryptoError, "AES-CBC decryption failed")
                    } else {
                        e.into()
                    }
                })?;
            Ok((
                json!({ "out": B64.encode(out) }),
                AuditInfo {
                    key: Some(r.root_name),
                    scope: None,
                },
            ))
        }
        other => Err(bad(format!("unknown op \"{other}\""))),
    }
}

/// Name of the key a request refers to, for the audit log (never fails).
pub fn audit_key(state: &State, req: &Value) -> Option<String> {
    let ids = parse_handle(str_field(req, "handle"))?;
    Some(
        ids.iter()
            .map(|id| {
                state
                    .keys
                    .get(id)
                    .map(|e| e.root.clone().unwrap_or_else(|| e.name.clone()))
                    .unwrap_or_else(|| format!("unknown:{id}"))
            })
            .collect::<Vec<_>>()
            .join("+"),
    )
}
