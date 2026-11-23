//! The rbq repository wire contract shared with Dash.
//!
//! Source of truth: `contracts/rbq-repository.v1.json` in this repository. Dash
//! (RAGBAZ/ragbaz-dash) vendors a pinned copy and derives its server limits and
//! validators from it. `tests/rbq_contract.rs` keeps the constants and
//! validators below equal to that file, so change the contract first; both
//! sides then fail their tests until they follow. Always compiled (no feature),
//! so the CLI can use the defaults without the HTTP client.
pub use crate::storage::{MAX_KEY_BYTES, MAX_SEGMENT_BYTES, ObjectKey, validate_prefix};

pub const SCHEMA: &str = "ragbaz.rbq-repository.v1";
pub const ENDPOINT_PATH_PREFIX: &str = "/api/rbq/";
pub const CONTENT_SHA256_HEADER: &str = "x-content-sha256";
pub const MAX_OBJECT_BYTES: usize = 262144;
pub const LIST_LIMIT_MAX: usize = 100;
pub const LIST_LIMIT_DEFAULT: usize = 20;

/// `rbm_` (MCP credential) or `rbs_` (paired sync credential) followed by 64
/// lowercase hex digits, as Dash issues them.
pub fn valid_token(token: &str) -> bool {
    ["rbm_", "rbs_"]
        .iter()
        .find_map(|prefix| token.strip_prefix(prefix))
        .is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// A lowercase hyphenated UUID, the repository endpoint identifier.
pub fn valid_endpoint_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}
