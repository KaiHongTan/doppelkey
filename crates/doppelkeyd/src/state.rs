//! The keeper's in-memory key table, per-key policy and derived-handle bookkeeping.

use crate::crypto::{self, Hash, Secret};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Per-key policy. Stored alongside the key in the vault; editable with `doppelkey policy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    /// Allowed ops: hmac, hash_derive, hkdf, pbkdf2, aes_gcm, aes_cbc.
    pub allow: Vec<String>,
    /// Vendor prefix that is part of the real value (e.g. "whsec_").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Special handling profile: "aws-sigv4".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// AWS services this key may sign for (None = any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    /// Allow legacy AWS SigV2 (signs with the raw secret).
    #[serde(default, skip_serializing_if = "is_false")]
    pub sigv2: bool,
    /// Maximum operations per minute (None = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_minute: Option<u32>,
    /// Ask the human before use (approval is cached for `confirm_ttl_secs`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub confirm: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_ttl_secs: Option<u64>,
}
fn is_false(b: &bool) -> bool {
    !*b
}

pub const ALL_OPS: &[&str] = &[
    "hmac",
    "hash_derive",
    "hkdf",
    "pbkdf2",
    "aes_gcm",
    "aes_cbc",
];
pub const DERIVED_ALLOW: &[&str] = &["hmac", "aes_gcm", "aes_cbc"];

/// A key held in memory: wiped on drop, and locked into RAM where the OS allows (no swap).
pub struct LockedKey(Secret);

impl LockedKey {
    pub fn new(bytes: Vec<u8>) -> LockedKey {
        let k = LockedKey(Zeroizing::new(bytes));
        #[cfg(unix)]
        if !k.0.is_empty() {
            // Best effort: RLIMIT_MEMLOCK may be small. Never fatal.
            unsafe { libc::mlock(k.0.as_ptr() as *const libc::c_void, k.0.len()) };
        }
        k
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(unix)]
        if self.0.capacity() > 0 {
            unsafe { libc::munlock(self.0.as_ptr() as *const libc::c_void, self.0.capacity()) };
        }
    }
}

pub struct Entry {
    /// Env var name for root keys ("JWT_SECRET"); "derived:<id>" for derived keys.
    pub name: String,
    pub key: LockedKey,
    pub policy: Policy,
    /// For derived keys: the root key's name (for audit and policy messages).
    pub root: Option<String>,
    /// AWS SigV4 chain position (1..=4) and scope so far.
    pub sigv4_stage: u8,
    pub scope: Vec<String>,
}

pub struct State {
    pub keys: HashMap<String, Entry>,
    /// Secret salt for deterministic derived-handle ids. Persisted in the vault.
    pub salt: LockedKey,
    pub locked: bool,
    rate: HashMap<String, VecDeque<Instant>>,
    approvals: HashMap<String, Instant>,
}

impl State {
    pub fn new(salt: Vec<u8>) -> State {
        State {
            keys: HashMap::new(),
            salt: LockedKey::new(salt),
            locked: false,
            rate: HashMap::new(),
            approvals: HashMap::new(),
        }
    }

    pub fn locked() -> State {
        let mut s = State::new(Vec::new());
        s.locked = true;
        s
    }

    pub fn insert_root(&mut self, id: String, name: String, key: Vec<u8>, policy: Policy) {
        self.keys.insert(
            id,
            Entry {
                name,
                key: LockedKey::new(key),
                policy,
                root: None,
                sigv4_stage: 0,
                scope: Vec::new(),
            },
        );
    }

    /// Drop every key (wiped by LockedKey::drop).
    pub fn wipe(&mut self) {
        self.keys.clear();
        self.salt = LockedKey::new(Vec::new());
        self.rate.clear();
        self.approvals.clear();
        self.locked = true;
    }

    pub fn root_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .keys
            .values()
            .filter(|e| e.root.is_none() && !e.name.starts_with("derived:"))
            .map(|e| e.name.clone())
            .collect();
        v.sort();
        v
    }

    fn id_for(&self, seed: &str) -> String {
        let mac = crypto::hmac(Hash::Sha256, self.salt.bytes(), seed.as_bytes());
        mac[..6].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Store derived key bytes and return the handle that names them. A key of 64+ bytes
    /// (even length) becomes two half-length handles, because libraries split such keys.
    pub fn new_handle(
        &mut self,
        bytes: &[u8],
        seed: &str,
        root: Option<String>,
        meta: Option<(u8, Vec<String>, Policy)>,
    ) -> Result<String, String> {
        let len = bytes.len();
        if len < doppelkey_proto::handle::COMPACT_LEN {
            return Err(format!(
                "a derived key of {len} bytes is too short to carry a handle (minimum 20)"
            ));
        }
        let pad = |core: String, n: usize| format!("{core:.<n$}");
        if len >= 64 && len.is_multiple_of(2) {
            let half = len / 2;
            let (a, b) = (
                self.id_for(&format!("{seed}|A")),
                self.id_for(&format!("{seed}|B")),
            );
            for (id, part) in [(&a, &bytes[..half]), (&b, &bytes[half..])] {
                self.keys.insert(
                    id.clone(),
                    Entry {
                        name: format!("derived:{id}"),
                        key: LockedKey::new(part.to_vec()),
                        policy: derived_policy(),
                        root: root.clone(),
                        sigv4_stage: 0,
                        scope: Vec::new(),
                    },
                );
            }
            return Ok(pad(doppelkey_proto::handle::compact_core(&a), half)
                + &pad(doppelkey_proto::handle::compact_core(&b), half));
        }
        let id = self.id_for(seed);
        let (stage, scope, policy) = meta.unwrap_or((0, Vec::new(), derived_policy()));
        self.keys.insert(
            id.clone(),
            Entry {
                name: format!("derived:{id}"),
                key: LockedKey::new(bytes.to_vec()),
                policy,
                root,
                sigv4_stage: stage,
                scope,
            },
        );
        Ok(pad(doppelkey_proto::handle::compact_core(&id), len))
    }

    /// Sliding one-minute window. Returns false if the key is over its limit.
    pub fn rate_ok(&mut self, key: &str, limit: Option<u32>) -> bool {
        let Some(limit) = limit else { return true };
        let now = Instant::now();
        let q = self.rate.entry(key.to_string()).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() as u32 >= limit {
            return false;
        }
        q.push_back(now);
        true
    }

    pub fn approved(&self, key: &str, ttl: Duration) -> bool {
        self.approvals.get(key).is_some_and(|t| t.elapsed() < ttl)
    }

    pub fn approve(&mut self, key: &str) {
        self.approvals.insert(key.to_string(), Instant::now());
    }
}

pub fn derived_policy() -> Policy {
    Policy {
        allow: DERIVED_ALLOW.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}
