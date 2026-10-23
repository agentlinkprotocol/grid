//! Canonical encoding.
//!
//! Rules (shared with every SDK, see `docs/spec/encoding`):
//! * structs are CBOR maps with text keys **in declaration order** (never sorted);
//! * integers in shortest form, no floats inside signed objects;
//! * fixed byte arrays as `bstr`;
//! * `Option::None` is `null`; enums are externally tagged (`{"variant": value}`), unit variants are text;
//! * a signature covers `blake3(domain || cbor(object without its signature fields))`.

use serde::{de::DeserializeOwned, Serialize};

use crate::error::{Error, Result};

pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    ciborium::ser::into_writer(value, &mut out).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(out)
}

pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::de::from_reader(bytes).map_err(|e| Error::Encoding(e.to_string()))
}

/// blake3(domain || payload)
pub fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(payload);
    *h.finalize().as_bytes()
}

/// Hash that a signature covers: blake3(domain || cbor(unsigned view)).
pub fn signing_hash<T: Serialize>(domain: &[u8], unsigned: &T) -> Result<[u8; 32]> {
    Ok(domain_hash(domain, &to_cbor(unsigned)?))
}

/// blake3 of arbitrary bytes.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
