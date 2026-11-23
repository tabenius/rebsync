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

/// Standard base64 (RFC 4648, `+/`, optional `=` padding). ASCII whitespace
/// is ignored; any other character makes the input invalid.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits, mut padding) = (0u32, 0u32, false);
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            c if c.is_ascii_whitespace() => continue,
            _ => return None,
        } as u32;
        if padding {
            return None;
        }
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
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

/// Refuse a secret file (token or password) that other local users could read
/// (Unix only).
pub fn ensure_private_file(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    anyhow::ensure!(
        is_owner_only(metadata),
        "{} must not be group- or world-readable (chmod 600)",
        path.display()
    );
    #[cfg(not(unix))]
    let _ = (path, metadata);
    Ok(())
}

/// Read a secret (password or token) from a file only its owner can read:
/// at most 4 KiB of UTF-8, trailing newline removed.
pub fn read_secret_file(path: &std::path::Path) -> anyhow::Result<String> {
    use anyhow::Context;
    let file = std::fs::File::open(path)
        .with_context(|| format!("open secret file {}", path.display()))?;
    ensure_private_file(path, &file.metadata()?)?;
    let bytes =
        read_bounded(file, 4096)?.with_context(|| format!("{} exceeds 4 KiB", path.display()))?;
    let text =
        String::from_utf8(bytes).with_context(|| format!("{} must be UTF-8", path.display()))?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

/// Percent-encode everything except RFC 3986 unreserved characters.
pub fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
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
    fn base64_round_trips_and_rejects_garbage() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YW\nJj").unwrap(), b"abc");
        assert!(base64_decode("YQ==YQ").is_none());
        assert!(base64_decode("a*b").is_none());
    }

    #[test]
    fn digest_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
