//! Framing and messages for protocol v1: a 4-byte big-endian length, then UTF-8 JSON.

use serde_json::{json, Value};
use std::io::{self, Read, Write};

pub const PROTOCOL_VERSION: u64 = 1;
pub const MAX_FRAME: usize = 16 << 20;

/// Error codes (docs/protocol.md). Shims add keeper_unreachable, keeper_timeout and unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    UnknownHandle,
    OpNotAllowed,
    RateLimited,
    ConfirmDenied,
    BadRequest,
    CryptoError,
    VersionMismatch,
    Locked,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownHandle => "unknown_handle",
            ErrorCode::OpNotAllowed => "op_not_allowed",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::ConfirmDenied => "confirm_denied",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::CryptoError => "crypto_error",
            ErrorCode::VersionMismatch => "version_mismatch",
            ErrorCode::Locked => "locked",
        }
    }
}

pub fn ok(id: u64, result: Value) -> Value {
    json!({ "v": PROTOCOL_VERSION, "id": id, "ok": true, "result": result })
}

pub fn err(id: u64, code: ErrorCode, message: &str, hint: Option<&str>) -> Value {
    let mut e = json!({ "code": code.as_str(), "message": message });
    if let Some(h) = hint {
        e["hint"] = Value::String(h.to_string());
    }
    json!({ "v": PROTOCOL_VERSION, "id": id, "ok": false, "error": e })
}

pub fn encode_frame(msg: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(msg).expect("json");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Blocking frame write (CLI side).
pub fn write_frame<W: Write>(w: &mut W, msg: &Value) -> io::Result<()> {
    w.write_all(&encode_frame(msg))?;
    w.flush()
}

/// Blocking frame read (CLI side).
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
