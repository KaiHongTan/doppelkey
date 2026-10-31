//! Decide which .env values are in-process keys doppelkey should protect, and how.
//!
//! doppelkey covers keys an app *computes with*: signing, webhook and encryption secrets, and
//! AWS secret keys. Credentials that only travel over the network (API keys, tokens, database
//! passwords) are left alone; a placeholder proxy (e.g. Veil, Infisical Agent Proxy) covers them.

use crate::state::Policy;
use base64::Engine;
use doppelkey_proto::Form;

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Protect(Plan),
    Skip(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub form: Form,
    /// Vendor prefix kept visible in front of the handle (e.g. "whsec_", "base64:").
    pub prefix: String,
    /// Real key bytes the keeper will hold.
    pub key: Vec<u8>,
    pub policy: Policy,
    pub kind: &'static str,
}

const NETWORK_NAME_PARTS: &[&str] = &[
    "API_KEY",
    "APIKEY",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "REFRESH_TOKEN",
    "PASSWORD",
    "PASSWD",
    "DATABASE_URL",
    "_DSN",
    "_URL",
    "_URI",
    "CLIENT_ID",
    "PUBLISHABLE",
    "PUBLIC_",
    "_HOST",
    "_PORT",
    "_USER",
    "USERNAME",
];
const NETWORK_VALUE_PREFIXES: &[&str] = &[
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "pk_live_",
    "pk_test_",
    "sk-ant-",
    "sk-proj-",
    "sk-",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "glpat-",
    "AKIA",
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb",
    "redis://",
    "https://",
    "http://",
];
const SECRET_NAME_PARTS: &[&str] = &[
    "SECRET",
    "SIGNING_KEY",
    "SIGNATURE_KEY",
    "ENCRYPTION_KEY",
    "ENC_KEY",
    "CRYPT_KEY",
    "HMAC_KEY",
    "JWT_KEY",
    "SESSION_KEY",
    "SESSION_PASSWORD",
    "COOKIE_KEY",
    "COOKIE_PASSWORD",
    "IRON_PASSWORD",
    "MASTER_KEY",
    "PRIVATE_KEY",
    "CIPHER_KEY",
    "DATA_KEY",
    "WEBHOOK_KEY",
];
/// Languages without a doppelkey shim yet: protecting these would break the app.
const UNSUPPORTED: &[(&str, &str)] = &[
    ("SECRET_KEY_BASE", "Rails"),
    ("RAILS_MASTER_KEY", "Rails"),
    ("APP_KEY", "Laravel"),
];

fn allow(ops: &[&str]) -> Vec<String> {
    ops.iter().map(|s| s.to_string()).collect()
}

fn canonical_b64(s: &str) -> Option<Vec<u8>> {
    let e = base64::engine::general_purpose::STANDARD;
    let d = e.decode(s).ok()?;
    (e.encode(&d) == s).then_some(d)
}

fn lower_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty()
        || !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Choose the handle form that keeps the value's shape, so apps that decode it still work.
fn shape(value: &str) -> (Form, String, Vec<u8>) {
    for prefix in ["whsec_", "base64:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            if let Some(b) = canonical_b64(rest).filter(|b| b.len() >= 20) {
                return (Form::Base64, prefix.into(), b);
            }
            return (Form::Long, prefix.into(), value.as_bytes().to_vec());
        }
    }
    if let Some(b) = lower_hex(value).filter(|b| b.len() >= 20) {
        return (Form::Hex, String::new(), b);
    }
    if let Some(b) = canonical_b64(value).filter(|b| b.len() >= 20) {
        return (Form::Base64, String::new(), b);
    }
    (Form::Long, String::new(), value.as_bytes().to_vec())
}

/// `others` are the other variables in the same file (e.g. AWS_ACCESS_KEY_ID).
pub fn classify(name: &str, value: &str, others: &[(String, String)]) -> Decision {
    let upper = name.to_ascii_uppercase();
    if value.is_empty() {
        return Decision::Skip("empty".into());
    }
    if !doppelkey_proto::handle::ids_in_text(value).is_empty() {
        return Decision::Skip("already a doppelkey handle".into());
    }
    if let Some((_, lang)) = UNSUPPORTED.iter().find(|(n, _)| upper == *n) {
        return Decision::Skip(format!("{lang} has no doppelkey shim yet"));
    }
    if upper == "AWS_SECRET_ACCESS_KEY" {
        let akid = others
            .iter()
            .find(|(n, _)| n == "AWS_ACCESS_KEY_ID")
            .map(|(_, v)| v.clone());
        let policy = Policy {
            allow: allow(&["hmac"]),
            profile: Some("aws-sigv4".into()),
            access_key_id: akid,
            ..Default::default()
        };
        return Decision::Protect(Plan {
            form: Form::Long,
            prefix: String::new(),
            key: value.as_bytes().to_vec(),
            policy,
            kind: "AWS secret key (SigV4)",
        });
    }
    if let Some(p) = NETWORK_VALUE_PREFIXES
        .iter()
        .find(|p| value.starts_with(**p))
    {
        return Decision::Skip(format!(
            "network credential ({p}…): use a placeholder proxy for it"
        ));
    }
    if NETWORK_NAME_PARTS.iter().any(|p| upper.contains(p)) && !upper.contains("SECRET") {
        return Decision::Skip("looks like a network credential or setting".into());
    }
    if !SECRET_NAME_PARTS.iter().any(|p| upper.contains(p)) && !value.starts_with("whsec_") {
        return Decision::Skip("not a signing or encryption secret".into());
    }
    if value.len() < 8 {
        return Decision::Skip("too short to be a real secret".into());
    }
    if value.contains("-----BEGIN") {
        return Decision::Skip("PEM private keys need crypto.sign support (not yet)".into());
    }
    let (form, prefix, key) = shape(value);
    let (ops, kind): (&[&str], &str) = if upper.contains("ENCRYPT")
        || upper.contains("CIPHER")
        || upper.contains("CRYPT_KEY")
        || upper.contains("DATA_KEY")
        || upper.contains("MASTER_KEY")
    {
        (
            &["aes_gcm", "aes_cbc", "hkdf", "pbkdf2", "hmac"],
            "encryption key",
        )
    } else if value.starts_with("whsec_") || upper.contains("WEBHOOK") {
        (&["hmac"], "webhook signing secret")
    } else if upper.contains("PASSWORD") || upper.contains("IRON") {
        (&["pbkdf2", "hmac"], "session password")
    } else if matches!(
        upper.as_str(),
        "AUTH_SECRET" | "NEXTAUTH_SECRET" | "BETTER_AUTH_SECRET"
    ) {
        (&["hkdf", "hmac", "pbkdf2"], "auth secret (key derivation)")
    } else {
        (&["hmac", "hkdf", "pbkdf2"], "signing secret")
    };
    let policy = Policy {
        allow: allow(ops),
        prefix: (!prefix.is_empty()).then(|| prefix.clone()),
        ..Default::default()
    };
    Decision::Protect(Plan {
        form,
        prefix,
        key,
        policy,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(name: &str, v: &str) -> Plan {
        match classify(name, v, &[]) {
            Decision::Protect(p) => p,
            Decision::Skip(r) => panic!("{name} skipped: {r}"),
        }
    }
    fn skip(name: &str, v: &str) -> bool {
        matches!(classify(name, v, &[]), Decision::Skip(_))
    }

    #[test]
    fn protects_in_process_keys() {
        assert_eq!(
            plan("JWT_SECRET", "a-long-random-jwt-secret-with-dashes").form,
            Form::Long
        );
        assert_eq!(
            plan(
                "SESSION_SECRET",
                "3f9c1e7a5b2d8c4e6f1a9b3d7e5c2a8f3f9c1e7a5b2d8c4e"
            )
            .form,
            Form::Hex
        );
        assert_eq!(
            plan("AUTH_SECRET", "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=").form,
            Form::Base64
        );
        let w = plan(
            "STRIPE_WEBHOOK_SECRET",
            "whsec_realStripeB64Secret0123456789abc",
        );
        assert_eq!((w.form, w.prefix.as_str()), (Form::Base64, "whsec_"));
        assert_eq!(
            plan(
                "ENCRYPTION_KEY",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .policy
            .allow[0],
            "aes_gcm"
        );
        let aws = match classify(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            &[("AWS_ACCESS_KEY_ID".into(), "AKIAX".into())],
        ) {
            Decision::Protect(p) => p,
            _ => panic!(),
        };
        assert_eq!(aws.policy.access_key_id.as_deref(), Some("AKIAX"));
    }

    #[test]
    fn skips_network_credentials_and_unsupported() {
        assert!(skip("OPENAI_API_KEY", "sk-proj-abc123abc123abc123"));
        assert!(skip("STRIPE_SECRET_KEY", "sk_live_abc123abc123"));
        assert!(skip("DATABASE_URL", "postgres://u:p@h/db"));
        assert!(skip("DB_PASSWORD", "hunter2hunter2"));
        assert!(skip("SECRET_KEY_BASE", "abcdef0123456789abcdef"));
        assert!(skip("NODE_ENV", "development"));
        assert!(skip(
            "JWT_SECRET",
            "dk1:NOT-A-SECRET-load-doppelkey-shim:a1b2c3d4e5f6:d3ae"
        ));
    }
}
