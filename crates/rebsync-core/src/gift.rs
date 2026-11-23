//! Gift signatures, format `ed25519-jcs-v1` (ragbaz-common
//! `docs/GIFT-SIGNATURE.md`): a detached Ed25519 signature over
//! `"ragbaz.gift.ed25519-jcs-v1\n" || JCS(envelope without "signature")`.
//!
//! Verification only: rbq never holds a gift signing key here. A valid result
//! says the holder of `sender_public_key` signed exactly this envelope, now
//! within its window, for the listed recipients. It does not establish who
//! holds the key, the sender's authority, or acceptance of the gift.
//!
//! The JavaScript implementation in ragbaz-common and this one must agree on
//! `contracts/vendor/gift-signature.v1.vectors.json`.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{NaiveDateTime, TimeZone, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use std::collections::HashSet;

pub const FORMAT: &str = "ed25519-jcs-v1";
pub const KEY_FORMAT: &str = "ed25519";
pub const DOMAIN: &str = "ragbaz.gift.ed25519-jcs-v1\n";
pub const MAX_SKEW_SECONDS: i64 = 300;
pub const MAX_LIFETIME_SECONDS: i64 = 400 * 24 * 3600;
pub const MAX_CANONICAL_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

const ENVELOPE_KEYS: &[&str] = &[
    "id",
    "subject",
    "sender_public_key",
    "recipient_public_keys",
    "artifact",
    "signature",
    "invitation",
    "delivery_policy",
    "issued_at",
    "expires_at",
];
const REQUIRED_KEYS: &[&str] = &[
    "id",
    "subject",
    "sender_public_key",
    "recipient_public_keys",
    "artifact",
    "signature",
    "issued_at",
    "expires_at",
];

/// Canonical encodings of the eight small-order points.
const SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

/// Why a gift was refused, in the specification's order of checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    UnsupportedFormat,
    InvalidKey,
    NotYetValid,
    Expired,
    NotARecipient,
    BadSignature,
}

impl Refusal {
    /// The stable reason code shared with the JavaScript verifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedFormat => "unsupported_format",
            Self::InvalidKey => "invalid_key",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::NotARecipient => "not_a_recipient",
            Self::BadSignature => "bad_signature",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Refusal {}

/// RFC 8785 canonical JSON for the subset gifts use: safe integers only, at
/// most 32 levels deep, members in UTF-16 code unit order.
pub fn canonical_json(value: &Value) -> anyhow::Result<String> {
    let mut out = String::new();
    write_canonical(value, 0, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, depth: usize, out: &mut String) -> anyhow::Result<()> {
    anyhow::ensure!(depth <= MAX_DEPTH, "canonical_json_too_deep");
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let n = n
                .as_i64()
                .filter(|n| n.unsigned_abs() <= MAX_SAFE_INTEGER as u64)
                .ok_or_else(|| anyhow::anyhow!("canonical_json_unsupported_number"))?;
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_canonical(&map[key], depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// ECMAScript JSON.stringify string escaping, which is JCS's.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The exact bytes an `ed25519-jcs-v1` signature covers.
pub fn signing_bytes(envelope: &Map<String, Value>) -> anyhow::Result<Vec<u8>> {
    let mut unsigned = envelope.clone();
    unsigned.remove("signature");
    let mut bytes = DOMAIN.as_bytes().to_vec();
    bytes.extend_from_slice(canonical_json(&Value::Object(unsigned))?.as_bytes());
    anyhow::ensure!(bytes.len() <= MAX_CANONICAL_BYTES, "gift_too_large");
    Ok(bytes)
}

/// Strict unpadded base64url of exactly `N` bytes; the engine refuses padding
/// and non-zero trailing bits, so each byte string has one spelling.
fn decode_exact<const N: usize>(text: &Value) -> Option<[u8; N]> {
    let text = text.as_str()?;
    if text.len() != (N * 4).div_ceil(3) {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()
}

/// Canonical (y < p) and not one of the small-order points.
fn strong_point(bytes: &[u8; 32]) -> bool {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    if SMALL_ORDER.contains(&hex.as_str()) {
        return false;
    }
    let top = bytes[31] & 0x7f;
    if top != 0x7f || bytes[1..31].iter().any(|b| *b != 0xff) {
        return true;
    }
    bytes[0] < 0xed
}

fn public_key(value: &Value) -> Option<[u8; 32]> {
    let object = value.as_object()?;
    if object.len() != 2 || object.get("format")?.as_str()? != KEY_FORMAT {
        return None;
    }
    let bytes = decode_exact::<32>(object.get("value")?)?;
    strong_point(&bytes).then_some(bytes)
}

fn seconds(value: &Value) -> Option<i64> {
    let text = value.as_str()?;
    let parsed = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%SZ").ok()?;
    // Round-trip: only the canonical whole-second UTC spelling is accepted.
    (parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string() == text)
        .then(|| Utc.from_utc_datetime(&parsed).timestamp())
}

/// Verify a gift envelope at unix time `now`. `recipient`, when given, is the
/// verifying party's `{format, value}` key and must be listed.
pub fn verify(envelope: &Value, now: i64, recipient: Option<&Value>) -> Result<(), Refusal> {
    use Refusal::*;
    let map = envelope.as_object().ok_or(Malformed)?;
    if map.keys().any(|k| !ENVELOPE_KEYS.contains(&k.as_str()))
        || REQUIRED_KEYS.iter().any(|k| !map.contains_key(*k))
    {
        return Err(Malformed);
    }
    let signature = map["signature"].as_object().ok_or(Malformed)?;
    if signature.len() != 2 || !signature.contains_key("value") {
        return Err(Malformed);
    }
    if signature.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(if signature.get("format").is_some_and(Value::is_string) {
            UnsupportedFormat
        } else {
            Malformed
        });
    }
    let sender = public_key(&map["sender_public_key"]).ok_or(InvalidKey)?;
    let recipients = map["recipient_public_keys"].as_array().ok_or(Malformed)?;
    if recipients.is_empty() || recipients.len() > 100 {
        return Err(Malformed);
    }
    let mut listed = HashSet::new();
    for key in recipients {
        listed.insert(public_key(key).ok_or(InvalidKey)?);
    }
    if listed.len() != recipients.len() {
        return Err(Malformed);
    }
    let issued = seconds(&map["issued_at"]).ok_or(Malformed)?;
    let expires = seconds(&map["expires_at"]).ok_or(Malformed)?;
    if expires <= issued || expires - issued > MAX_LIFETIME_SECONDS {
        return Err(Malformed);
    }
    if issued > now + MAX_SKEW_SECONDS {
        return Err(NotYetValid);
    }
    if expires <= now {
        return Err(Expired);
    }
    if let Some(recipient) = recipient
        && !public_key(recipient).is_some_and(|key| listed.contains(&key))
    {
        return Err(NotARecipient);
    }
    let signature = decode_exact::<64>(&signature["value"]).ok_or(BadSignature)?;
    let r: [u8; 32] = signature[..32].try_into().expect("64-byte signature");
    if !strong_point(&r) {
        return Err(BadSignature);
    }
    let message = signing_bytes(map).map_err(|_| Malformed)?;
    let key = VerifyingKey::from_bytes(&sender).map_err(|_| InvalidKey)?;
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_escape_like_ecmascript() {
        let mut out = String::new();
        write_string("\"\\\u{8}\u{c}\n\r\t\u{1}\u{1f}/\u{2028}ä", &mut out);
        assert_eq!(out, "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f/\u{2028}ä\"");
    }

    #[test]
    fn non_canonical_points_are_weak() {
        let mut p = [0xff_u8; 32];
        p[0] = 0xed;
        p[31] = 0x7f; // y = p, a second spelling of y = 0
        assert!(!strong_point(&p));
        p[0] = 0xec; // y = p - 1, canonical but small-order
        assert!(!strong_point(&p));
    }
}
