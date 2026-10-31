//! doppelkey wire protocol v1 and handle format v1. See `docs/protocol.md`.
//!
//! This crate has no knowledge of key material: it parses and formats handles, frames
//! messages, and names error codes. The keeper (`doppelkeyd`) and the CLI build on it.

pub mod handle;
pub mod wire;

pub use handle::{Form, KeyRef};
pub use wire::{ErrorCode, PROTOCOL_VERSION};
