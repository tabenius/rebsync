//! Dash-hosted private repositories: HTTPS, no tokens in URLs, no redirects,
//! bounded responses, hash-verified reads and immutable append. No terminal I/O.
use crate::storage::{ObjectKey, validate_prefix};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path, time::Duration};

pub const MAX_OBJECT_BYTES: usize = 262144;
const MAX_JSON_BYTES: usize = 262144;

pub struct Repository {
    base: url::Url,
    token: String,
    agent: ureq::Agent,
}

fn bounded(mut reader: impl Read, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max,
        "repository response or input exceeds its size limit"
    );
    Ok(bytes)
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
        let id = path.strip_prefix("/api/rbq/").unwrap_or("");
        ensure!(
            id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "use the /api/rbq/ID endpoint returned by rbq_get_repository"
        );
        ensure!(
            token.starts_with("rbm_")
                && token.len() == 68
                && token[4..].bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid Dash bearer token"
        );
        base.set_path(&path);
        Ok(Self {
            base,
            token: token.into(),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(60))
                .build(),
        })
    }

    pub fn from_token_file(endpoint: &str, path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).context("open private repository token file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                file.metadata()?.permissions().mode() & 0o077 == 0,
                "token file must be owner-only (chmod 600)"
            );
        }
        let token = bounded(file, 256)?;
        let token = std::str::from_utf8(&token).context("token file must be UTF-8")?;
        Self::connect(endpoint, token.trim())
    }

    fn request(&self, method: &str, suffix: &str) -> ureq::Request {
        self.agent
            .request(
                method,
                &format!("{}{suffix}", self.base.as_str().trim_end_matches('/')),
            )
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("User-Agent", concat!("rbq/", env!("CARGO_PKG_VERSION")))
    }

    fn response(
        result: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<ureq::Response> {
        match result {
            Ok(response) if (200..300).contains(&response.status()) => Ok(response),
            Ok(_) => bail!("repository redirect refused"),
            Err(ureq::Error::Status(401, _)) => {
                bail!("repository credential expired or revoked; rotate it in Dash")
            }
            Err(ureq::Error::Status(404, _)) => bail!("repository object not found"),
            Err(ureq::Error::Status(409, _)) => {
                bail!("immutable key conflict or repository quota exceeded")
            }
            Err(ureq::Error::Status(413, _)) => bail!("repository object exceeds size limit"),
            Err(ureq::Error::Status(code, _)) => bail!("repository request failed (HTTP {code})"),
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
            value["schema"] == "ragbaz.rbq-repository.v1" && value["private"] == true,
            "unsupported private repository descriptor"
        );
        Ok(value)
    }

    pub fn list(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<Value> {
        validate_prefix(prefix)?;
        if let Some(key) = after {
            ObjectKey::parse(key)?;
        }
        ensure!((1..=100).contains(&limit), "list limit must be 1..100");
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
            .header("x-content-sha256")
            .context("repository omitted content digest")?
            .to_owned();
        let bytes = bounded(response.into_reader(), MAX_OBJECT_BYTES)?;
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == expected,
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
                && value["sha256"] == format!("{:x}", Sha256::digest(bytes))
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

/// Never replace local work when downloading an object.
pub fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("create new output file (existing files are never overwritten)")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
