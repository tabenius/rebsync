//! Primitives shared by every rbq exchange (LAN peers, the local transport and
//! Dash-hosted repositories): bounded reads, SHA-256 digests, owner-only secret
//! files and the no-redirect HTTP client. One implementation keeps the safety
//! rules identical across transports.
use sha2::{Digest, Sha256};
use std::io::{self, Read};

/// Read at most `max` bytes. `Ok(None)` means the input was larger than `max`;
/// I/O errors are returned unchanged so callers keep their retry classification.
pub fn read_bounded(reader: impl Read, max: u64) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    reader.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= max).then_some(bytes))
}

/// Lowercase hexadecimal SHA-256, the digest form used on the wire and on disk.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// True when no group or other permission bits are set. Always false where
/// POSIX permissions do not exist, so callers can decide how to degrade.
pub fn is_owner_only(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Refuse a credential file that other local users could read (Unix only).
pub fn ensure_private_file(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    anyhow::ensure!(
        is_owner_only(metadata),
        "token file {} must not be group- or world-readable (chmod 600)",
        path.display()
    );
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

#[cfg(feature = "peer-http")]
pub mod http {
    use std::time::Duration;

    /// HTTP client for rbq: redirects are never followed, so a bearer token is
    /// only ever sent to the origin it was configured for.
    pub fn agent(connect: Duration, total: Duration) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout_connect(connect)
            .timeout(total)
            .redirects(0)
            .build()
    }

    /// Bearer authentication in the header (never the URL) plus the rbq user agent.
    pub fn authorize(request: ureq::Request, token: &str) -> ureq::Request {
        request
            .set("Authorization", &format!("Bearer {token}"))
            .set("User-Agent", concat!("rbq/", env!("CARGO_PKG_VERSION")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reads_accept_the_limit_and_refuse_one_more_byte() {
        assert_eq!(
            read_bounded(&b"abcd"[..], 4).unwrap(),
            Some(b"abcd".to_vec())
        );
        assert_eq!(read_bounded(&b"abcde"[..], 4).unwrap(), None);
        assert_eq!(read_bounded(&b""[..], 0).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn digest_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
