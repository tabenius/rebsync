//! Dash-hosted private repositories: HTTPS, no tokens in URLs, no redirects,
//! bounded responses, hash-verified reads and immutable append. No terminal I/O.
//!
//! Constants and validators of the wire contract are in [`crate::rbq_contract`].
use crate::wire::{self, http};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{io::Read, path::Path, time::Duration};

pub use crate::rbq_contract::*;
const MAX_JSON_BYTES: usize = 262144;

pub struct Repository {
    base: url::Url,
    token: String,
    agent: ureq::Agent,
}

fn bounded(reader: impl Read, max: usize) -> Result<Vec<u8>> {
    wire::read_bounded(reader, max as u64)?
        .context("repository response or input exceeds its size limit")
}

impl Repository {
    pub fn connect(endpoint: &str, token: &str) -> Result<Self> {
        // Never include invalid input or server error bodies in diagnostics.
        let mut base =
            url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid repository URL"))?;
        let local = base.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        ensure!(
            base.scheme() == "https" || (base.scheme() == "http" && local),
            "repository URL requires HTTPS (HTTP allowed only on loopback for local testing)"
        );
        ensure!(
            base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "repository URL must not contain credentials, query or fragment"
        );
        let path = base.path().trim_end_matches('/').to_owned();
        let id = path.strip_prefix(ENDPOINT_PATH_PREFIX).unwrap_or("");
        ensure!(
            valid_endpoint_id(id),
            "use the /api/rbq/ID endpoint returned by rbq_get_repository"
        );
        ensure!(valid_token(token), "invalid Dash bearer token");
        base.set_path(&path);
        Ok(Self {
            base,
            token: token.into(),
            agent: http::agent(Duration::from_secs(10), Duration::from_secs(60)),
        })
    }

    pub fn from_token_file(endpoint: &str, path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).context("open private repository token file")?;
        wire::ensure_private_file(path, &file.metadata()?)?;
        let token = bounded(file, 256)?;
        let token = std::str::from_utf8(&token).context("token file must be UTF-8")?;
        Self::connect(endpoint, token.trim())
    }

    fn request(&self, method: &str, suffix: &str) -> ureq::Request {
        http::authorize(
            self.agent.request(
                method,
                &format!("{}{suffix}", self.base.as_str().trim_end_matches('/')),
            ),
            &self.token,
        )
    }

    fn response(
        result: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<ureq::Response> {
        match result {
            Ok(response) if (200..300).contains(&response.status()) => Ok(response),
            Ok(_) => bail!("repository redirect refused"),
            // Never include the response body: it is server-controlled text.
            Err(ureq::Error::Status(code, _)) => match status_message(code) {
                Some(message) => bail!("{message}"),
                None => bail!("repository request failed (HTTP {code})"),
            },
            Err(_) => bail!("repository connection failed; verify network and endpoint"),
        }
    }

    fn json(response: ureq::Response) -> Result<Value> {
        serde_json::from_slice(&bounded(response.into_reader(), MAX_JSON_BYTES)?)
            .context("invalid repository JSON")
    }

    pub fn describe(&self) -> Result<Value> {
        let value = Self::json(Self::response(self.request("GET", "").call())?)?;
        ensure!(
            value["schema"] == SCHEMA && value["private"] == true,
            "unsupported private repository descriptor"
        );
        Ok(value)
    }

    pub fn list(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<Value> {
        validate_prefix(prefix)?;
        if let Some(key) = after {
            ObjectKey::parse(key)?;
        }
        ensure!(
            (1..=LIST_LIMIT_MAX).contains(&limit),
            "list limit must be 1..{LIST_LIMIT_MAX}"
        );
        let request = self
            .request("GET", "/objects")
            .query("prefix", prefix)
            .query("limit", &limit.to_string());
        let request = if let Some(key) = after {
            request.query("after", key)
        } else {
            request
        };
        Self::json(Self::response(request.call())?)
    }

    pub fn read(&self, key: &str) -> Result<Vec<u8>> {
        ObjectKey::parse(key)?;
        let response = Self::response(self.request("GET", &format!("/objects/{key}")).call())?;
        let expected = response
            .header(CONTENT_SHA256_HEADER)
            .context("repository omitted content digest")?
            .to_owned();
        let bytes = bounded(response.into_reader(), MAX_OBJECT_BYTES)?;
        ensure!(
            wire::sha256_hex(&bytes) == expected,
            "repository content digest mismatch"
        );
        Ok(bytes)
    }

    pub fn append(&self, key: &str, bytes: &[u8]) -> Result<Value> {
        ObjectKey::parse(key)?;
        ensure!(
            bytes.len() <= MAX_OBJECT_BYTES,
            "object exceeds 256 KiB; split larger objects before appending"
        );
        let response = Self::response(
            self.request("PUT", &format!("/objects/{key}"))
                .set("Content-Type", "application/octet-stream")
                .send_bytes(bytes),
        )?;
        let value = Self::json(response)?;
        ensure!(
            value["key"] == key
                && value["sha256"] == wire::sha256_hex(bytes)
                && value["size_bytes"].as_u64() == Some(bytes.len() as u64),
            "repository append acknowledgement mismatch"
        );
        Ok(value)
    }
}

/// What each error status of the contract (`errors` in
/// `contracts/rbq-repository.v1.json`) means for the user. Other statuses get a
/// generic message with the code.
pub fn status_message(code: u16) -> Option<&'static str> {
    Some(match code {
        401 => "repository credential expired or revoked; rotate it in Dash",
        403 => {
            "repository storage is not enabled for this credential; enable it in Dash and rotate"
        }
        404 => "repository object not found",
        409 => "immutable key conflict or repository quota exceeded",
        413 => "repository object exceeds size limit",
        429 => "repository rate limit reached; retry later",
        _ => return None,
    })
}

pub fn read_input(path: &Path) -> Result<Vec<u8>> {
    bounded(
        std::fs::File::open(path).context("open object input")?,
        MAX_OBJECT_BYTES,
    )
}

/// Never replace local work when downloading an object, and never leave a
/// partial file: bytes go to an owner-only temporary file in the same
/// directory, which is synced and then linked into place only if `path` does
/// not exist. A failed write leaves nothing behind, so a retry can succeed.
pub fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    ensure!(
        std::fs::symlink_metadata(path).is_err(),
        "output exists; existing files are never overwritten"
    );
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    // tempfile creates the file with mode 0600 on Unix.
    let mut temp = tempfile::Builder::new()
        .prefix(".rbq-download-")
        .tempfile_in(dir)
        .context("create temporary output file")?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .context("create new output file (existing files are never overwritten)")?;
    Ok(())
}
