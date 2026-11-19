//! Dash-hosted private repositories: HTTPS, no tokens in URLs, no redirects,
//! bounded responses, hash-verified reads and immutable append. No terminal I/O.
//!
//! Constants and validators of the wire contract are in [`crate::rbq_contract`].
pub use crate::private_http::status_message;
use crate::private_http::{PrivateHttp, bounded, read_token};
pub use crate::rbq_contract::*;
use crate::wire;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;

const MAX_JSON_BYTES: usize = 262144;

pub struct Repository {
    http: PrivateHttp,
}

impl Repository {
    pub fn connect(endpoint: &str, token: &str) -> Result<Self> {
        Ok(Self {
            http: PrivateHttp::connect(endpoint, ENDPOINT_PATH_PREFIX, token)?,
        })
    }

    pub fn from_token_file(endpoint: &str, path: &Path) -> Result<Self> {
        Self::connect(endpoint, &read_token(path)?)
    }

    fn request(&self, method: &str, suffix: &str) -> ureq::Request {
        self.http.request(method, suffix)
    }

    fn response(
        result: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<ureq::Response> {
        PrivateHttp::response(result)
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
                && value["created"].is_boolean()
                && value["sha256"] == wire::sha256_hex(bytes)
                && value["size_bytes"].as_u64() == Some(bytes.len() as u64),
            "repository append acknowledgement mismatch"
        );
        Ok(value)
    }
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
