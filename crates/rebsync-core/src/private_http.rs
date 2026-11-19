//! Shared transport policy for account-private Dash endpoints. Never follows
//! redirects or includes server bodies, URLs or credentials in diagnostics.
use anyhow::{Context, Result, bail, ensure};
use std::{io::Read, path::Path, time::Duration};

pub(crate) fn bounded(mut reader: impl Read, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max,
        "private request data exceeds its size limit"
    );
    Ok(bytes)
}

pub(crate) fn read_token(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path).context("inspect private token file")?;
    ensure!(
        metadata.file_type().is_file(),
        "token must be a regular file, not a symlink or device"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open private token file")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "token must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.mode() & 0o077 == 0,
            "token file must be owner-only (chmod 600)"
        );
        // SAFETY: geteuid takes no arguments and has no memory preconditions.
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "token file must belong to the current user"
        );
    }
    let bytes = bounded(file, 256)?;
    let token = std::str::from_utf8(&bytes).context("token file must be UTF-8")?;
    Ok(token.trim().to_owned())
}

pub(crate) struct PrivateHttp {
    base: url::Url,
    token: String,
    agent: ureq::Agent,
}

impl PrivateHttp {
    pub(crate) fn connect(endpoint: &str, prefix: &str, token: &str) -> Result<Self> {
        let mut base = url::Url::parse(endpoint)
            .map_err(|_| anyhow::anyhow!("invalid private endpoint URL"))?;
        let local = match base.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        ensure!(
            base.scheme() == "https" || (base.scheme() == "http" && local),
            "private endpoint requires HTTPS (HTTP allowed only on loopback for local testing)"
        );
        ensure!(
            base.host().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "private endpoint must not contain credentials, query or fragment"
        );
        let path = base.path().trim_end_matches('/').to_owned();
        let id = path.strip_prefix(prefix).unwrap_or("");
        ensure!(
            id.len() == 36
                && id.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                }),
            "private endpoint requires a credential UUID at its documented path"
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

    pub(crate) fn request(&self, method: &str, suffix: &str) -> ureq::Request {
        self.agent
            .request(
                method,
                &format!("{}{suffix}", self.base.as_str().trim_end_matches('/')),
            )
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("User-Agent", concat!("rbq/", env!("CARGO_PKG_VERSION")))
    }

    pub(crate) fn response(
        result: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<ureq::Response> {
        match result {
            Ok(response) if (200..300).contains(&response.status()) => Ok(response),
            Ok(_) => bail!("private endpoint redirect refused"),
            Err(ureq::Error::Status(401, _)) => {
                bail!("credential expired or revoked; rotate it in Dash")
            }
            Err(ureq::Error::Status(403, _)) => {
                bail!("access forbidden; check credential opt-ins and current membership")
            }
            Err(ureq::Error::Status(404, _)) => bail!("private resource or endpoint not found"),
            Err(ureq::Error::Status(409, _)) => {
                bail!("immutable key conflict, changed revision or quota exceeded")
            }
            Err(ureq::Error::Status(413, _)) => bail!("private request exceeds size limit"),
            Err(ureq::Error::Status(code, _)) => bail!("private request failed (HTTP {code})"),
            Err(_) => bail!("private connection failed; verify network and endpoint"),
        }
    }
}
