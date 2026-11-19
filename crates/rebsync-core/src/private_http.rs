//! Shared transport policy for account-private Dash endpoints. Never follows
//! redirects or includes server bodies, URLs or credentials in diagnostics.
//! Token and endpoint formats come from the shared rbq contract
//! ([`crate::rbq_contract`]); bounded reads and the HTTP client from [`crate::wire`].
use crate::rbq_contract::{valid_endpoint_id, valid_token};
use crate::wire::{self, http};
use anyhow::{Context, Result, bail, ensure};
use std::{io::Read, path::Path, time::Duration};

pub(crate) fn bounded(reader: impl Read, max: usize) -> Result<Vec<u8>> {
    wire::read_bounded(reader, max as u64)?.context("private request data exceeds its size limit")
}

/// What each error status listed in the rbq contract (`errors` in
/// `contracts/rbq-repository.v1.json`) means for the user. Other statuses get a
/// generic message with the code.
pub fn status_message(code: u16) -> Option<&'static str> {
    Some(match code {
        401 => "credential expired or revoked; rotate it in Dash",
        403 => "access forbidden; check credential opt-ins and current membership",
        404 => "private resource or endpoint not found",
        409 => "immutable key conflict, changed revision or quota exceeded",
        413 => "private request exceeds size limit",
        429 => "rate limit reached; retry later",
        _ => return None,
    })
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
            wire::is_owner_only(&metadata),
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
            valid_endpoint_id(id),
            "private endpoint requires a credential UUID at its documented path"
        );
        ensure!(valid_token(token), "invalid Dash bearer token");
        base.set_path(&path);
        Ok(Self {
            base,
            token: token.into(),
            agent: http::agent(Duration::from_secs(10), Duration::from_secs(60)),
        })
    }

    pub(crate) fn request(&self, method: &str, suffix: &str) -> ureq::Request {
        http::authorize(
            self.agent.request(
                method,
                &format!("{}{suffix}", self.base.as_str().trim_end_matches('/')),
            ),
            &self.token,
        )
    }

    pub(crate) fn response(
        result: std::result::Result<ureq::Response, ureq::Error>,
    ) -> Result<ureq::Response> {
        match result {
            Ok(response) if (200..300).contains(&response.status()) => Ok(response),
            Ok(_) => bail!("private endpoint redirect refused"),
            // Never include the response body: it is server-controlled text.
            Err(ureq::Error::Status(code, _)) => match status_message(code) {
                Some(message) => bail!("{message}"),
                None => bail!("private request failed (HTTP {code})"),
            },
            Err(_) => bail!("private connection failed; verify network and endpoint"),
        }
    }
}
