//! Handle format v1.
//!
//! A core is `dk1:NOT-A-SECRET-load-doppelkey-shim:<id12>:<crc4>` (long, 58 bytes) or
//! `dk1:<id12><crc4>` (compact, 20 bytes). `crc4` is the first 4 hex chars of
//! SHA-256("dk1:" + id). A handle is one or more cores, each optionally followed by `.` padding.

use base64::Engine;
use sha2::{Digest, Sha256};

pub const LABEL: &str = "NOT-A-SECRET-load-doppelkey-shim";
pub const MARK: &str = "dk1:";
pub const ID_LEN: usize = 12;
pub const COMPACT_LEN: usize = 20;
pub const LONG_LEN: usize = 58;
pub const MAX_PREFIX: usize = 8;

/// Checksum of an id: first 4 hex characters of SHA-256("dk1:" + id).
pub fn crc(id: &str) -> String {
    let d = Sha256::digest(format!("{MARK}{id}").as_bytes());
    hex(&d[..2])
}

pub fn long_core(id: &str) -> String {
    format!("{MARK}{LABEL}:{id}:{}", crc(id))
}

pub fn compact_core(id: &str) -> String {
    format!("{MARK}{id}{}", crc(id))
}

/// A fresh random id (48 bits).
pub fn new_id(random: [u8; 6]) -> String {
    hex(&random)
}

pub fn is_id(s: &str) -> bool {
    s.len() == ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Split a handle (padded cores back to back, nothing else) into ids. None if invalid.
pub fn parse_handle(s: &str) -> Option<Vec<String>> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut ids = Vec::new();
    while i < b.len() {
        if !s[i..].starts_with(MARK) {
            return None;
        }
        i += MARK.len();
        let id;
        let label = format!("{LABEL}:");
        if s[i..].starts_with(&label) {
            i += label.len();
            id = s.get(i..i + ID_LEN)?;
            i += ID_LEN;
            if b.get(i) != Some(&b':') {
                return None;
            }
            i += 1;
        } else {
            id = s.get(i..i + ID_LEN)?;
            i += ID_LEN;
        }
        let sum = s.get(i..i + 4)?;
        i += 4;
        if !is_id(id) || sum.len() != 4 || crc(id) != sum {
            return None;
        }
        while b.get(i) == Some(&b'.') {
            i += 1;
        }
        ids.push(id.to_string());
    }
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

/// How a key given to a crypto call relates to a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    /// Bytes before the handle (at most 8), e.g. `AWS4` or `whsec_`.
    pub prefix: Vec<u8>,
    /// The handle text: one or more padded cores.
    pub handle: String,
    pub ids: Vec<String>,
    /// `Some("hex" | "base64")` when the key was the encoded text of a handle.
    pub key_encoding: Option<&'static str>,
}

/// Recognise a handle in key bytes, as a shim does. Mirrors `shims/node/src/handle.ts`.
pub fn recognise(key: &[u8]) -> Option<KeyRef> {
    if let Some(pos) = find(key, MARK.as_bytes()) {
        if pos <= MAX_PREFIX {
            // The prefix is the shortest one that leaves a valid handle.
            for p in 0..=pos {
                let rest = &key[p..];
                if let Ok(text) = std::str::from_utf8(rest) {
                    if let Some(ids) = parse_handle(text) {
                        return Some(KeyRef {
                            prefix: key[..p].to_vec(),
                            handle: text.to_string(),
                            ids,
                            key_encoding: None,
                        });
                    }
                }
            }
        }
        return None;
    }
    let text = std::str::from_utf8(key).ok()?;
    let (enc, decoded): (&'static str, Vec<u8>) = if text.starts_with("646b313a")
        && text.len().is_multiple_of(2)
        && text
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        (
            "hex",
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
                .collect::<Result<_, _>>()
                .ok()?,
        )
    } else if text.starts_with("ZGsxO") {
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .ok()?,
        )
    } else {
        return None;
    };
    let inner = std::str::from_utf8(&decoded).ok()?;
    let ids = parse_handle(inner)?;
    Some(KeyRef {
        prefix: Vec::new(),
        handle: inner.to_string(),
        ids,
        key_encoding: Some(enc),
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// How a secret is written into `.env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Form {
    /// `dk1:NOT-A-SECRET-load-doppelkey-shim:<id>:<crc>`: self-explaining default.
    Long,
    /// Compact core padded with `.` to the secret's length (for length-checked secrets).
    Compact,
    /// Hex of the padded compact core (for secrets the app hex-decodes).
    Hex,
    /// Base64 of the padded compact core (for secrets the app base64-decodes).
    Base64,
}

/// The `.env` value for a secret. `key_len` is the length of the real key bytes (decoded for
/// hex/base64 forms); `prefix` is a vendor prefix kept in front (e.g. `whsec_`).
pub fn env_value(
    id: &str,
    form: Form,
    prefix: &str,
    key_len: usize,
    pad_long: bool,
) -> Result<String, String> {
    if form == Form::Long {
        let core = long_core(id);
        let body_len = key_len.saturating_sub(prefix.len());
        let body = if pad_long && body_len > core.len() {
            format!("{core:.<body_len$}")
        } else {
            core
        };
        return Ok(format!("{prefix}{body}"));
    }
    let body_len = if form == Form::Compact {
        key_len.saturating_sub(prefix.len())
    } else {
        key_len
    };
    if body_len < COMPACT_LEN {
        return Err(format!(
            "a {body_len}-byte secret is too short to hold a handle (minimum {COMPACT_LEN})"
        ));
    }
    let padded = format!("{:.<body_len$}", compact_core(id));
    Ok(match form {
        Form::Hex => format!("{prefix}{}", hex(padded.as_bytes())),
        Form::Base64 => format!(
            "{prefix}{}",
            base64::engine::general_purpose::STANDARD.encode(padded.as_bytes())
        ),
        _ => format!("{prefix}{padded}"),
    })
}

/// Find every handle id mentioned in a text (e.g. a whole `.env` file), in any form.
pub fn ids_in_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in
        text.split(|c: char| c.is_whitespace() || c == '=' || c == '"' || c == '\'' || c == '`')
    {
        let t = token.trim_end_matches(',');
        if let Some(r) = recognise(t.as_bytes()) {
            out.extend(r.ids);
        } else if let Some(i) = t.find(MARK) {
            if let Some(r) = recognise(&t.as_bytes()[i..]) {
                out.extend(r.ids);
            }
        } else {
            // vendor prefix + encoded form, e.g. whsec_<base64>
            for p in 1..=MAX_PREFIX.min(t.len()) {
                if let Some(r) = recognise(&t.as_bytes()[p..]) {
                    if r.key_encoding.is_some() {
                        out.extend(r.ids);
                        break;
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vectors {
        vectors: Vec<V>,
    }
    #[derive(serde::Deserialize)]
    struct V {
        input: String,
        valid: bool,
        handle: Option<String>,
        prefix: Option<String>,
        key_encoding: Option<String>,
        ids: Option<Vec<String>>,
        note: String,
    }

    #[test]
    fn shared_vectors() {
        let v: Vectors = serde_json::from_str(include_str!("../vectors/handles.json")).unwrap();
        for x in v.vectors {
            let got = recognise(x.input.as_bytes());
            if !x.valid {
                assert!(
                    got.is_none(),
                    "{}: expected no handle, got {:?}",
                    x.note,
                    got
                );
                continue;
            }
            let got = got.unwrap_or_else(|| panic!("{}: not recognised", x.note));
            assert_eq!(Some(got.handle.clone()), x.handle, "{}", x.note);
            assert_eq!(
                String::from_utf8(got.prefix).unwrap(),
                x.prefix.unwrap(),
                "{}",
                x.note
            );
            assert_eq!(
                got.key_encoding.map(str::to_string),
                x.key_encoding,
                "{}",
                x.note
            );
            assert_eq!(Some(got.ids), x.ids, "{}", x.note);
        }
    }

    #[test]
    fn env_forms_round_trip() {
        let id = "a1b2c3d4e5f6";
        assert_eq!(
            env_value(id, Form::Long, "", 40, false).unwrap(),
            long_core(id)
        );
        assert_eq!(
            env_value(id, Form::Long, "whsec_", 40, false).unwrap(),
            format!("whsec_{}", long_core(id))
        );
        let c = env_value(id, Form::Compact, "", 32, false).unwrap();
        assert_eq!(c.len(), 32);
        assert_eq!(recognise(c.as_bytes()).unwrap().ids, vec![id]);
        let h = env_value(id, Form::Hex, "", 32, false).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(recognise(h.as_bytes()).unwrap().key_encoding, Some("hex"));
        let b = env_value(id, Form::Base64, "whsec_", 24, false).unwrap();
        assert!(b.starts_with("whsec_ZGsxO"));
        assert_eq!(
            ids_in_text(&format!("A={c}\nB=\"{h}\"\nC={b}\n")),
            vec![id, id, id]
        );
        assert!(env_value(id, Form::Compact, "", 16, false).is_err());
    }
}
