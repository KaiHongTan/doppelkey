//! Cryptographic primitives over raw key bytes (RustCrypto). Nothing here knows about handles,
//! policy or the wire; `ops` composes these. Every function returns an owned output; key
//! material is only borrowed.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

pub type Secret = Zeroizing<Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn parse(s: &str) -> Option<Hash> {
        match s {
            "sha1" => Some(Hash::Sha1),
            "sha256" => Some(Hash::Sha256),
            "sha384" => Some(Hash::Sha384),
            "sha512" => Some(Hash::Sha512),
            _ => None,
        }
    }
    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
}

macro_rules! with_hash {
    ($h:expr, $T:ident => $body:expr) => {
        match $h {
            Hash::Sha1 => {
                type $T = Sha1;
                $body
            }
            Hash::Sha256 => {
                type $T = Sha256;
                $body
            }
            Hash::Sha384 => {
                type $T = Sha384;
                $body
            }
            Hash::Sha512 => {
                type $T = Sha512;
                $body
            }
        }
    };
}

pub fn hmac(h: Hash, key: &[u8], data: &[u8]) -> Vec<u8> {
    with_hash!(h, D => {
        let mut m = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    })
}

pub fn digest(h: Hash, data: &[u8]) -> Secret {
    Zeroizing::new(with_hash!(h, D => D::digest(data).to_vec()))
}

pub fn hkdf(h: Hash, ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Secret, String> {
    let mut out = Zeroizing::new(vec![0u8; len]);
    with_hash!(h, D => {
        // An empty salt is the same as no salt (a block of zeros), as in RFC 5869 and Node.
        let k = hkdf::Hkdf::<D>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
        k.expand(info, &mut out).map_err(|_| format!("length {len} is too long for HKDF with this hash"))?;
    });
    Ok(out)
}

pub fn pbkdf2(h: Hash, password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Secret {
    let mut out = Zeroizing::new(vec![0u8; len]);
    with_hash!(h, D => pbkdf2::pbkdf2_hmac::<D>(password, salt, iterations, &mut out));
    out
}

fn aes_key_ok(key: &[u8]) -> Result<(), String> {
    if matches!(key.len(), 16 | 24 | 32) {
        Ok(())
    } else {
        Err(format!(
            "key is {} bytes; AES needs 16, 24 or 32",
            key.len()
        ))
    }
}

/// AES-GCM with a 12-byte nonce and 16-byte tag. Encrypt returns ciphertext || tag.
pub fn aes_gcm(
    encrypt: bool,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoFail> {
    aes_key_ok(key).map_err(CryptoFail::Bad)?;
    if iv.len() != 12 {
        return Err(CryptoFail::Bad(
            "AES-GCM needs a 12-byte IV in protocol v1".into(),
        ));
    }
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(iv)
        .map_err(|_| CryptoFail::Bad("bad IV".into()))?;
    let payload = Payload { msg: data, aad };
    macro_rules! run {
        ($C:ty) => {{
            let c = <$C>::new_from_slice(key).map_err(|_| CryptoFail::Bad("bad key".into()))?;
            if encrypt {
                c.encrypt(&nonce, payload)
                    .map_err(|_| CryptoFail::Bad("encryption failed".into()))
            } else {
                c.decrypt(&nonce, payload).map_err(|_| CryptoFail::Auth)
            }
        }};
    }
    match key.len() {
        16 => run!(aes_gcm::Aes128Gcm),
        24 => run!(aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>),
        _ => run!(aes_gcm::Aes256Gcm),
    }
}

/// AES-CBC with PKCS#7 padding (or none). `iv` must be 16 bytes.
pub fn aes_cbc(
    encrypt: bool,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    padding: bool,
) -> Result<Vec<u8>, CryptoFail> {
    use cbc::cipher::{
        block_padding::{NoPadding, Pkcs7},
        BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    };
    aes_key_ok(key).map_err(CryptoFail::Bad)?;
    if iv.len() != 16 {
        return Err(CryptoFail::Bad("AES-CBC needs a 16-byte IV".into()));
    }
    if !padding && !data.len().is_multiple_of(16) {
        return Err(if encrypt {
            CryptoFail::Bad("data is not a multiple of the block size".into())
        } else {
            CryptoFail::Auth
        });
    }
    macro_rules! run {
        ($A:ty) => {{
            if encrypt {
                let e = cbc::Encryptor::<$A>::new_from_slices(key, iv)
                    .map_err(|_| CryptoFail::Bad("bad key".into()))?;
                Ok(if padding {
                    e.encrypt_padded_vec::<Pkcs7>(data)
                } else {
                    e.encrypt_padded_vec::<NoPadding>(data)
                })
            } else {
                let d = cbc::Decryptor::<$A>::new_from_slices(key, iv)
                    .map_err(|_| CryptoFail::Bad("bad key".into()))?;
                if padding {
                    d.decrypt_padded_vec::<Pkcs7>(data)
                        .map_err(|_| CryptoFail::Auth)
                } else {
                    d.decrypt_padded_vec::<NoPadding>(data)
                        .map_err(|_| CryptoFail::Auth)
                }
            }
        }};
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        _ => run!(aes::Aes256),
    }
}

/// XChaCha20-Poly1305 (24-byte nonce). Encrypt returns ciphertext || tag. Used for the vault.
pub fn xchacha(
    encrypt: bool,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoFail> {
    use chacha20poly1305::XChaCha20Poly1305;
    if key.len() != 32 || nonce.len() != 24 {
        return Err(CryptoFail::Bad(
            "XChaCha20-Poly1305 needs a 32-byte key and 24-byte nonce".into(),
        ));
    }
    let c =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoFail::Bad("bad key".into()))?;
    let n = chacha20poly1305::XNonce::try_from(nonce)
        .map_err(|_| CryptoFail::Bad("bad nonce".into()))?;
    let p = Payload { msg: data, aad };
    if encrypt {
        c.encrypt(&n, p)
            .map_err(|_| CryptoFail::Bad("encryption failed".into()))
    } else {
        c.decrypt(&n, p).map_err(|_| CryptoFail::Auth)
    }
}

#[derive(Debug)]
pub enum CryptoFail {
    /// Bad parameters (bad_request).
    Bad(String),
    /// Authentication or padding failure (crypto_error).
    Auth,
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc4231_hmac_sha256_case2() {
        assert_eq!(
            hx(&hmac(
                Hash::Sha256,
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
    #[test]
    fn rfc5869_hkdf_case1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=12).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        assert_eq!(
            hx(&hkdf(Hash::Sha256, &ikm, &salt, &info, 42).unwrap()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
    #[test]
    fn rfc6070_pbkdf2_sha1() {
        assert_eq!(
            hx(&pbkdf2(Hash::Sha1, b"password", b"salt", 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
    }
    #[test]
    fn aes_round_trips_and_tamper() {
        let k = [7u8; 32];
        let ct = aes_gcm(true, &k, &[1; 12], b"hi", b"aad").unwrap();
        assert_eq!(aes_gcm(false, &k, &[1; 12], &ct, b"aad").unwrap(), b"hi");
        assert!(matches!(
            aes_gcm(false, &k, &[1; 12], &ct, b"x"),
            Err(CryptoFail::Auth)
        ));
        let c = aes_cbc(true, &k[..16], &[2; 16], b"hello", true).unwrap();
        assert_eq!(c.len(), 16);
        assert_eq!(
            aes_cbc(false, &k[..16], &[2; 16], &c, true).unwrap(),
            b"hello"
        );
        let x = xchacha(true, &k, &[3; 24], b"vault", b"").unwrap();
        assert_eq!(xchacha(false, &k, &[3; 24], &x, b"").unwrap(), b"vault");
    }
}
