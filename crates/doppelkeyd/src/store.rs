//! The vault: real key values and their policies, encrypted at rest.
//!
//! File layout: `DKV1\n` + header JSON + `\n` + XChaCha20-Poly1305(ciphertext of vault JSON),
//! with the header bytes as associated data. The key-encryption key (KEK) comes from:
//!
//! - `passphrase`: Argon2id(passphrase). The keeper starts locked; `doppelkey unlock` asks the
//!   human. Recommended on Linux, where the Secret Service is readable by any same-user process.
//! - `keychain`: a random KEK in the macOS Keychain (feature `macos-keychain`); the Keychain ACL
//!   binds it to the signed doppelkey binary.
//! - `file`: a random KEK in a 0600 file next to the vault. Convenient for headless dev boxes,
//!   but a same-user agent can read both files: no protection at rest.

use crate::crypto;
use crate::paths;
use crate::state::LockedKey as LockedKeyBytes;
use crate::state::{Policy, State};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"DKV1\n";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KekKind {
    Passphrase,
    Keychain,
    File,
}

impl std::str::FromStr for KekKind {
    type Err = String;
    fn from_str(s: &str) -> Result<KekKind, String> {
        match s {
            "passphrase" => Ok(KekKind::Passphrase),
            "keychain" => Ok(KekKind::Keychain),
            "file" => Ok(KekKind::File),
            _ => Err(format!(
                "unknown key protection \"{s}\" (passphrase, keychain, file)"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kdf {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub format: String,
    pub version: u32,
    pub kek: KekKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Kdf>,
    pub nonce: String,
}

/// One protected secret. `value` is base64 of the real key bytes.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub name: String,
    pub value: String,
    #[serde(flatten)]
    pub policy: Policy,
    pub form: doppelkey_proto::Form,
    /// Project directory and file the secret came from (for `eject`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Exact text that was replaced in the file, and the handle text written in its place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written: Option<String>,
    pub created: String,
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.value.zeroize();
        if let Some(o) = &mut self.original {
            o.zeroize();
        }
    }
}

impl StoredKey {
    pub fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        B64.decode(&self.value)
            .map(Zeroizing::new)
            .map_err(|_| format!("vault entry {} is corrupt", self.name))
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    /// Base64 salt for derived-handle ids (keeps derived handles stable across restarts).
    pub salt: String,
    pub keys: BTreeMap<String, StoredKey>,
    /// Original contents (base64) of project files `init` modified, by absolute path, so
    /// `eject` can restore them byte for byte. Kept here because they may hold other secrets.
    #[serde(default)]
    pub backups: BTreeMap<String, String>,
}

impl VaultData {
    pub fn new() -> VaultData {
        VaultData {
            version: 1,
            salt: B64.encode(crypto::random_bytes::<32>()),
            keys: BTreeMap::new(),
            backups: BTreeMap::new(),
        }
    }

    pub fn to_state(&self) -> Result<State, String> {
        let mut s = State::new(
            B64.decode(&self.salt)
                .map_err(|_| "vault salt is corrupt")?,
        );
        for (id, k) in &self.keys {
            s.insert_root(
                id.clone(),
                k.name.clone(),
                k.key_bytes()?.to_vec(),
                k.policy.clone(),
            );
        }
        Ok(s)
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

pub fn read_header(path: &Path) -> Result<(Header, Vec<u8>, Vec<u8>), String> {
    let raw = fs::read(path).map_err(|e| format!("cannot read vault {}: {e}", path.display()))?;
    if !raw.starts_with(MAGIC) {
        return Err(format!("{} is not a doppelkey vault", path.display()));
    }
    let rest = &raw[MAGIC.len()..];
    let nl = rest
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("vault header is truncated")?;
    let header_bytes = rest[..nl].to_vec();
    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("vault header is corrupt: {e}"))?;
    Ok((header, header_bytes, rest[nl + 1..].to_vec()))
}

/// Derive or fetch the KEK for a vault header. `passphrase` is needed for passphrase vaults.
pub fn kek_for(header: &Header, passphrase: Option<&str>) -> Result<LockedKeyBytes, String> {
    match header.kek {
        KekKind::Passphrase => {
            let pass = passphrase.ok_or("this vault is protected by a passphrase")?;
            let kdf = header
                .kdf
                .as_ref()
                .ok_or("vault header has no KDF parameters")?;
            argon2_kek(pass, kdf)
        }
        KekKind::File => {
            let p = kek_file();
            let b =
                fs::read(&p).map_err(|e| format!("cannot read key file {}: {e}", p.display()))?;
            if b.len() != 32 {
                return Err(format!("key file {} is corrupt", p.display()));
            }
            Ok(LockedKeyBytes::new(b))
        }
        KekKind::Keychain => keychain_get(),
    }
}

fn argon2_kek(pass: &str, kdf: &Kdf) -> Result<LockedKeyBytes, String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let salt = B64.decode(&kdf.salt).map_err(|_| "bad KDF salt")?;
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
        .map_err(|e| format!("bad KDF parameters: {e}"))?;
    let mut out = vec![0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), &salt, &mut out)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(LockedKeyBytes::new(out))
}

pub fn kek_file() -> PathBuf {
    paths::config_dir().join("kek")
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
fn keychain_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new("doppelkey", "vault-kek").map_err(|e| format!("keychain: {e}"))
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
fn keychain_get() -> Result<LockedKeyBytes, String> {
    let s = keychain_entry()?
        .get_secret()
        .map_err(|e| format!("keychain: {e}"))?;
    Ok(LockedKeyBytes::new(s))
}

#[cfg(all(target_os = "macos", feature = "macos-keychain"))]
fn keychain_set(kek: &[u8]) -> Result<(), String> {
    keychain_entry()?
        .set_secret(kek)
        .map_err(|e| format!("keychain: {e}"))
}

#[cfg(not(all(target_os = "macos", feature = "macos-keychain")))]
fn keychain_get() -> Result<LockedKeyBytes, String> {
    Err("keychain protection needs a macOS build with the macos-keychain feature; use --protect passphrase or file".into())
}

#[cfg(not(all(target_os = "macos", feature = "macos-keychain")))]
fn keychain_set(_: &[u8]) -> Result<(), String> {
    keychain_get().map(|_| ())
}

/// Create a new, empty vault. Returns its KEK.
pub fn create(
    path: &Path,
    kind: KekKind,
    passphrase: Option<&str>,
) -> Result<LockedKeyBytes, String> {
    if path.exists() {
        return Err(format!("a vault already exists at {}", path.display()));
    }
    let (kdf, kek) = match kind {
        KekKind::Passphrase => {
            let pass = passphrase
                .filter(|p| !p.is_empty())
                .ok_or("a passphrase is required")?;
            let kdf = Kdf {
                alg: "argon2id".into(),
                m_kib: 65536,
                t: 3,
                p: 1,
                salt: B64.encode(crypto::random_bytes::<16>()),
            };
            let kek = argon2_kek(pass, &kdf)?;
            (Some(kdf), kek)
        }
        KekKind::File => {
            let kek = crypto::random_bytes::<32>().to_vec();
            write_private(&kek_file(), &kek)?;
            (None, LockedKeyBytes::new(kek))
        }
        KekKind::Keychain => {
            let kek = crypto::random_bytes::<32>().to_vec();
            keychain_set(&kek)?;
            (None, LockedKeyBytes::new(kek))
        }
    };
    let header = Header {
        format: "doppelkey-vault".into(),
        version: 1,
        kek: kind,
        kdf,
        nonce: String::new(),
    };
    save(path, &header, kek.bytes(), &VaultData::new())?;
    Ok(kek)
}

pub fn open(path: &Path, kek: &[u8]) -> Result<(Header, VaultData), String> {
    let (header, header_bytes, ct) = read_header(path)?;
    let nonce = B64
        .decode(&header.nonce)
        .map_err(|_| "vault nonce is corrupt")?;
    let pt = Zeroizing::new(
        crypto::xchacha(false, kek, &nonce, &ct, &header_bytes).map_err(|_| match header.kek {
            KekKind::Passphrase => "wrong passphrase (or the vault is corrupt)".to_string(),
            _ => "cannot decrypt the vault: wrong key or corrupt file".to_string(),
        })?,
    );
    let data: VaultData =
        serde_json::from_slice(&pt).map_err(|e| format!("vault contents are corrupt: {e}"))?;
    Ok((header, data))
}

/// Encrypt and atomically replace the vault file (fresh nonce every time).
pub fn save(path: &Path, header: &Header, kek: &[u8], data: &VaultData) -> Result<(), String> {
    let mut h = header.clone();
    let nonce = crypto::random_bytes::<24>();
    h.nonce = B64.encode(nonce);
    let header_bytes = serde_json::to_vec(&h).map_err(|e| e.to_string())?;
    let pt = Zeroizing::new(serde_json::to_vec(data).map_err(|e| e.to_string())?);
    let ct = crypto::xchacha(true, kek, &nonce, &pt, &header_bytes)
        .map_err(|_| "vault encryption failed")?;
    let mut out = Vec::with_capacity(MAGIC.len() + header_bytes.len() + 1 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_bytes);
    out.push(b'\n');
    out.extend_from_slice(&ct);
    write_private(path, &out)
}

/// Write a file readable only by the owner, atomically (temp file + rename).
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path.parent().ok_or("bad path")?;
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

/// Load the insecure JSON test vault used by the compatibility suite (fake secrets only).
pub fn load_test_vault(path: &Path) -> Result<State, String> {
    #[derive(Deserialize)]
    struct TestKey {
        id: String,
        value: Option<String>,
        value_b64: Option<String>,
        #[serde(flatten)]
        policy: Policy,
    }
    #[derive(Deserialize)]
    struct TestVault {
        salt: Option<String>,
        keys: BTreeMap<String, TestKey>,
    }
    let v: TestVault = serde_json::from_slice(
        &fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
    )
    .map_err(|e| format!("bad test vault: {e}"))?;
    let salt = match &v.salt {
        Some(s) => B64.decode(s).map_err(|_| "bad salt")?,
        None => crypto::random_bytes::<32>().to_vec(),
    };
    let mut s = State::new(salt);
    for (name, k) in v.keys {
        let bytes = match (&k.value, &k.value_b64) {
            (_, Some(b)) => B64
                .decode(b)
                .map_err(|_| format!("{name}: bad value_b64"))?,
            (Some(t), None) => t.as_bytes().to_vec(),
            _ => return Err(format!("{name}: no value")),
        };
        s.insert_root(k.id.clone(), name, bytes, k.policy.clone());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_round_trip_and_wrong_passphrase() {
        let dir = std::env::temp_dir().join(format!("dk-vault-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("vault.dk");
        let kek = create(&path, KekKind::Passphrase, Some("correct horse")).unwrap();
        let (h, mut data) = open(&path, kek.bytes()).unwrap();
        data.keys.insert(
            "a1b2c3d4e5f6".into(),
            StoredKey {
                name: "JWT_SECRET".into(),
                value: B64.encode(b"fake"),
                policy: Policy {
                    allow: vec!["hmac".into()],
                    ..Default::default()
                },
                form: doppelkey_proto::Form::Long,
                project: None,
                file: None,
                original: None,
                written: None,
                created: "now".into(),
            },
        );
        save(&path, &h, kek.bytes(), &data).unwrap();
        let kek2 = kek_for(&h, Some("correct horse")).unwrap();
        let (_, back) = open(&path, kek2.bytes()).unwrap();
        assert_eq!(back.keys["a1b2c3d4e5f6"].name, "JWT_SECRET");
        let bad = kek_for(&h, Some("wrong")).unwrap();
        assert!(matches!(open(&path, bad.bytes()), Err(e) if e.contains("wrong passphrase")));
        let raw = fs::read(&path).unwrap();
        assert!(!raw
            .windows(4)
            .any(|w| w == b"fake".as_slice() || w == B64.encode(b"fake").as_bytes()));
        fs::remove_dir_all(&dir).unwrap();
    }
}
