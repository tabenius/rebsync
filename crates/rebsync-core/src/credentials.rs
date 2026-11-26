//! Device-local credential boundary. Metadata is not issuer verification.
//! No backend is selected implicitly and secrets are never serializable DTOs.
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod files;
#[cfg(all(feature = "secret-service", target_os = "linux"))]
pub mod secret_service;

/// Trusted native adapters may expose bytes only for an authorized operation.
/// Intentionally neither Clone nor Serialize; Debug never reveals contents.
/// This type does not promise locked memory or zeroization.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    DashBearer,
    Peer,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Describe,
    List,
    Read,
    Append,
    /// Existing Rebekah instance connector only; no object-storage authority.
    Connector,
}

/// An exact, opaque binding established by enrollment, never a URL prefix match.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    pub endpoint: String,
    pub account_id: String,
    pub repository_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub id: String,
    pub kind: CredentialKind,
    pub audience: Audience,
    pub scopes: Vec<Scope>,
    /// Unix seconds. Expiry is mandatory; unknown expiry cannot authorize use.
    pub created_at: u64,
    pub expires_at: u64,
    pub disabled: bool,
}

impl Descriptor {
    /// Local policy check only. The issuer still checks current revocation and
    /// membership. Never authorize from metadata imported by replication alone.
    pub fn permits(&self, audience: &Audience, scope: &Scope, now: u64) -> bool {
        !self.id.is_empty()
            && !self.audience.endpoint.is_empty()
            && !self.audience.account_id.is_empty()
            && !self.audience.repository_id.is_empty()
            && !self.disabled
            && self.created_at <= now
            && now < self.expires_at
            && &self.audience == audience
            && self.scopes.contains(scope)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Locked,
    Unavailable,
    NotFound,
    Conflict,
    Denied,
    Invalid,
}

/// Implementations own policy and native handles. They must not trust a caller's
/// descriptor in `use_secret`: load the authoritative local grant by ID.
/// Create is no-clobber and atomic/recoverable across metadata + secret storage.
/// Disable must durably prevent new uses before returning success; revoking at
/// the remote issuer is a separate operation. No default plaintext fallback.
pub trait CredentialStore {
    fn list(&self) -> Result<Vec<Descriptor>, StoreError>;
    fn create(&self, descriptor: Descriptor, secret: Secret) -> Result<(), StoreError>;
    fn disable(&self, id: &str) -> Result<(), StoreError>;
    fn use_secret(
        &self,
        id: &str,
        audience: &Audience,
        scope: &Scope,
        now: u64,
    ) -> Result<Secret, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Descriptor {
        Descriptor {
            id: "device-credential".into(),
            kind: CredentialKind::DashBearer,
            audience: Audience {
                endpoint: "https://dash.example/api/rbq/repository".into(),
                account_id: "account".into(),
                repository_id: "repository".into(),
            },
            scopes: vec![Scope::Describe, Scope::Read],
            created_at: 100,
            expires_at: 200,
            disabled: false,
        }
    }

    #[test]
    fn expiry_disabling_and_scope_are_fail_closed() {
        let mut entry = descriptor();
        assert!(entry.permits(&entry.audience, &Scope::Read, 100));
        for now in [0, 99, 200, u64::MAX] {
            assert!(!entry.permits(&entry.audience, &Scope::Read, now));
        }
        assert!(!entry.permits(&entry.audience, &Scope::Append, 150));
        entry.disabled = true;
        assert!(!entry.permits(&entry.audience, &Scope::Read, 150));
    }

    #[test]
    fn bindings_are_exact_not_prefixes_or_matching_names() {
        let entry = descriptor();
        let mut other = entry.audience.clone();
        other.endpoint.push_str("/other");
        assert!(!entry.permits(&other, &Scope::Read, 150));
        other = entry.audience.clone();
        other.account_id = "another-account".into();
        assert!(!entry.permits(&other, &Scope::Read, 150));
        other = entry.audience.clone();
        other.repository_id = "another-repository".into();
        assert!(!entry.permits(&other, &Scope::Read, 150));
    }

    #[test]
    fn empty_identity_never_authorizes() {
        for field in 0..4 {
            let mut entry = descriptor();
            match field {
                0 => entry.id.clear(),
                1 => entry.audience.endpoint.clear(),
                2 => entry.audience.account_id.clear(),
                _ => entry.audience.repository_id.clear(),
            }
            assert!(!entry.permits(&entry.audience, &Scope::Read, 150));
        }
    }

    #[test]
    fn debug_is_redacted_and_metadata_contains_no_secret() {
        let secret = Secret::new(b"private-token".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        assert_eq!(secret.expose(), b"private-token");
        let encoded = serde_json::to_string(&descriptor()).unwrap();
        assert!(!encoded.contains("private-token"));
        assert_eq!(
            serde_json::from_str::<Descriptor>(&encoded).unwrap(),
            descriptor()
        );
    }
}
