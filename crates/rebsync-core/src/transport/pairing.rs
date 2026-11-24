//! Pairing: devices that know each other's keys, recorded in signed
//! statements on both sides.
//!
//! Every device has one long-term [`Identity`] (the same key it serves QUIC
//! with). Pairing two devices means each one signs a statement about the
//! other's key:
//!
//! * the **server** signs "this client key may read (and write)", optionally
//!   until a date; with that record a client connects with its key alone, no
//!   token;
//! * the **client** signs "this server key is `NAME`, reachable at these
//!   addresses"; with that record `paired:NAME` resolves to an address and a
//!   pin.
//!
//! The exchange can happen ahead of time and entirely non-interactively:
//! each device prints its [`Card`] (`rbq peer id`), the cards travel by any
//! channel (a file, a QR code, provisioning tooling), and each side records
//! the other (`rbq peer pair add`). A card is self-signed, which proves its
//! holder has the key; it does not prove *who* the holder is, so a card must
//! come over a channel you trust, exactly like an SSH host key.
//!
//! Records are stored one file per peer under the device's trust directory.
//! A record only counts if this device's own key signed it, it names a well-
//! formed key, and it has not expired. A record copied in from elsewhere, or
//! edited, is ignored.

use super::{Scopes, quic::Identity};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const CARD_SCHEMA: &str = "rbq.card.v1";
pub const PAIRING_SCHEMA: &str = "rbq.pairing.v1";
const MAX_RECORD: u64 = 64 * 1024;
const MAX_NAME: usize = 64;
const MAX_ADDRESSES: usize = 16;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .context("invalid base64")
}

/// A device as others see it: its key (as a certificate) and, optionally, a
/// name and where to reach it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub peer: String,
    /// Base64 DER certificate carrying the public key.
    pub certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Connection targets, e.g. `quic://100.101.102.103:8788`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

impl Device {
    fn of(identity: &Identity, name: Option<String>, addresses: Vec<String>) -> Self {
        Self {
            peer: identity.peer_id().to_owned(),
            certificate: b64(identity.certificate_der()),
            name,
            addresses,
        }
    }

    /// The key must hash to the claimed id, names and addresses must be sane.
    fn check(&self) -> Result<Vec<u8>> {
        let certificate = unb64(&self.certificate)?;
        let peer = super::quic::peer_id_of_certificate(&certificate)?;
        ensure!(
            peer == self.peer,
            "device claims peer {} but its key is {peer}",
            self.peer
        );
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        ensure!(self.addresses.len() <= MAX_ADDRESSES, "too many addresses");
        for address in &self.addresses {
            let target = super::Target::parse(address)
                .with_context(|| format!("invalid address {address:?}"))?;
            ensure!(
                matches!(target, super::Target::Quic { .. }),
                "paired addresses must be quic://HOST:PORT"
            );
        }
        Ok(certificate)
    }
}

/// Names are labels for people and `paired:NAME`, not identities.
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= MAX_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "a name is 1..{MAX_NAME} letters, digits, '-', '_' or '.'"
    );
    Ok(())
}

/// What the issuer says about the subject.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A card: the issuer describing itself.
    Card,
    /// The subject may use the issuer's store with `scopes`.
    Client,
    /// The subject is a server the issuer will connect to.
    Server,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Statement {
    pub schema: String,
    pub role: Role,
    pub issuer: Device,
    pub subject: Device,
    /// For a client record: what it may do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Scopes>,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// A statement and the issuer's signature over its canonical JSON.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signed {
    pub statement: Statement,
    pub scheme: String,
    pub signature: String,
}

/// A device's self-signed card, the thing two devices exchange to pair.
pub type Card = Signed;

impl Signed {
    fn sign(identity: &Identity, statement: Statement) -> Result<Self> {
        let (scheme, signature) = identity.sign(&serde_json::to_vec(&statement)?)?;
        Ok(Self {
            statement,
            scheme,
            signature: b64(&signature),
        })
    }

    /// Verify the signature, both keys and the dates. Does not decide whether
    /// the issuer is trusted; callers check who issued it.
    pub fn verify(&self) -> Result<&Statement> {
        let statement = &self.statement;
        let expected = match statement.role {
            Role::Card => CARD_SCHEMA,
            Role::Client | Role::Server => PAIRING_SCHEMA,
        };
        ensure!(statement.schema == expected, "unexpected schema");
        let issuer_certificate = statement.issuer.check()?;
        statement.subject.check()?;
        if statement.role == Role::Card {
            ensure!(
                statement.issuer == statement.subject,
                "a card describes its own issuer"
            );
        } else {
            ensure!(
                statement.issuer.peer != statement.subject.peer,
                "a device does not pair with itself"
            );
        }
        ensure!(
            (statement.role == Role::Client) == statement.scopes.is_some(),
            "only client records carry scopes"
        );
        super::quic::verify_signature(
            &issuer_certificate,
            &self.scheme,
            &serde_json::to_vec(statement)?,
            &unb64(&self.signature)?,
        )?;
        ensure!(
            statement.issued_at <= now() + 300,
            "record is issued in the future"
        );
        if let Some(expires) = statement.expires_at {
            ensure!(expires > now(), "record expired");
        }
        Ok(statement)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() as u64 <= MAX_RECORD, "record is too large");
        serde_json::from_slice(bytes).context("not a pairing record or card")
    }
}

/// This device's card: its key, an optional name and addresses, signed by
/// itself.
pub fn card(identity: &Identity, name: Option<String>, addresses: Vec<String>) -> Result<Card> {
    let device = Device::of(identity, name, addresses);
    device.check()?;
    Signed::sign(
        identity,
        Statement {
            schema: CARD_SCHEMA.into(),
            role: Role::Card,
            issuer: device.clone(),
            subject: device,
            scopes: None,
            issued_at: now(),
            expires_at: None,
        },
    )
}

/// Records signed by this device about other devices.
pub struct TrustStore {
    dir: PathBuf,
    identity: Arc<Identity>,
}

/// One valid record, as listed.
#[derive(Clone, Debug, Serialize)]
pub struct Paired {
    pub peer: String,
    pub role: Role,
    pub name: Option<String>,
    pub addresses: Vec<String>,
    pub scopes: Option<Scopes>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

impl TrustStore {
    /// The store in `dir` (created owner-only), for records `identity` signs.
    pub fn open(dir: &Path, identity: Arc<Identity>) -> Result<Self> {
        fs::create_dir_all(dir)
            .with_context(|| format!("create trust directory {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            identity,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    fn path(&self, peer: &str, role: Role) -> PathBuf {
        let role = match role {
            Role::Client => "client",
            Role::Server => "server",
            Role::Card => "card",
        };
        self.dir.join(format!("{peer}.{role}.json"))
    }

    /// Sign and store a record about the device a verified card describes.
    /// Replaces an earlier record for the same peer and role.
    pub fn add(
        &self,
        card: &Card,
        role: Role,
        scopes: Option<Scopes>,
        expires_at: Option<u64>,
        name: Option<String>,
        addresses: Option<Vec<String>>,
    ) -> Result<Signed> {
        let described = card.verify().context("the card does not verify")?;
        ensure!(described.role == Role::Card, "expected a card");
        ensure!(role != Role::Card, "a pairing is for a client or a server");
        ensure!(
            described.subject.peer != self.identity.peer_id(),
            "that is this device's own card"
        );
        let mut subject = described.subject.clone();
        if name.is_some() {
            subject.name = name;
        }
        if let Some(addresses) = addresses {
            subject.addresses = addresses;
        }
        let scopes = match role {
            Role::Client => Some(scopes.unwrap_or(Scopes::ALL)),
            _ => None,
        };
        if role == Role::Client {
            ensure!(
                scopes.is_some_and(|s| s.read || s.write),
                "a client pairing needs read or write"
            );
        }
        let record = Signed::sign(
            &self.identity,
            Statement {
                schema: PAIRING_SCHEMA.into(),
                role,
                issuer: Device::of(&self.identity, None, Vec::new()),
                subject,
                scopes,
                issued_at: now(),
                expires_at,
            },
        )?;
        record.verify()?;
        // Owner-only from the first byte, then renamed over any earlier
        // record, so a reader never sees a torn file.
        let path = self.path(&record.statement.subject.peer, role);
        let temporary = self.dir.join(format!(
            ".{}.{}.tmp",
            record.statement.subject.peer,
            std::process::id()
        ));
        let _ = fs::remove_file(&temporary);
        crate::process::write_private(&temporary, &serde_json::to_vec_pretty(&record)?)?;
        fs::rename(&temporary, &path)?;
        Ok(record)
    }

    /// Remove every record about `peer`. Returns how many were removed.
    pub fn remove(&self, peer: &str) -> Result<usize> {
        super::quic::validate_peer_id(peer)?;
        let mut removed = 0;
        for role in [Role::Client, Role::Server] {
            let path = self.path(&peer.to_ascii_lowercase(), role);
            if path.exists() {
                fs::remove_file(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Valid records: signed by this device, well formed, not expired.
    /// Anything else in the directory is ignored.
    pub fn records(&self) -> Vec<Signed> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|e| e == "json"))
            .filter_map(|entry| {
                let file = fs::File::open(entry.path()).ok()?;
                let bytes = crate::wire::read_bounded(file, MAX_RECORD).ok()??;
                let record = Signed::parse(&bytes).ok()?;
                let statement = record.verify().ok()?;
                (statement.issuer.peer == self.identity.peer_id() && statement.role != Role::Card)
                    .then_some(record)
            })
            .collect()
    }

    pub fn list(&self) -> Vec<Paired> {
        let mut list: Vec<Paired> = self
            .records()
            .into_iter()
            .map(|record| {
                let statement = record.statement;
                Paired {
                    peer: statement.subject.peer,
                    role: statement.role,
                    name: statement.subject.name,
                    addresses: statement.subject.addresses,
                    scopes: statement.scopes,
                    issued_at: statement.issued_at,
                    expires_at: statement.expires_at,
                }
            })
            .collect();
        list.sort_by(|a, b| (&a.name, &a.peer).cmp(&(&b.name, &b.peer)));
        list
    }

    /// A paired server by name or peer id: its pin and addresses.
    pub fn server(&self, name_or_peer: &str) -> Result<Paired> {
        let wanted = name_or_peer.to_ascii_lowercase();
        let matches: Vec<Paired> = self
            .list()
            .into_iter()
            .filter(|paired| {
                paired.role == Role::Server
                    && (paired.peer == wanted
                        || paired
                            .name
                            .as_deref()
                            .is_some_and(|name| name.eq_ignore_ascii_case(name_or_peer)))
            })
            .collect();
        match matches.len() {
            0 => bail!("no paired server named {name_or_peer:?}; see rbq peer pair list"),
            1 => Ok(matches.into_iter().next().expect("one match")),
            _ => bail!("{name_or_peer:?} names several paired servers; use its peer id"),
        }
    }
}

/// A pending one-time pairing invitation, stored under the hash of its
/// secret (the secret itself is never written to disk).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Invite {
    expires_at: u64,
    scopes: Scopes,
    /// This server's name, put on the card it returns.
    #[serde(default)]
    server_name: Option<String>,
}

/// Longest an invitation may live.
pub const MAX_INVITE_SECONDS: u64 = 24 * 3600;

impl TrustStore {
    fn invites(&self) -> PathBuf {
        self.dir.join(".invites")
    }

    /// Create a one-time pairing secret valid for `ttl_seconds`. The first
    /// client that presents it, over QUIC with its key, is paired with
    /// `scopes`; the secret then stops working. Expired invitations are
    /// removed.
    pub fn invite(
        &self,
        scopes: Scopes,
        ttl_seconds: u64,
        server_name: Option<String>,
    ) -> Result<String> {
        ensure!(
            (1..=MAX_INVITE_SECONDS).contains(&ttl_seconds),
            "an invitation lives 1 s to 24 h"
        );
        ensure!(
            scopes.read || scopes.write,
            "an invitation grants read or write"
        );
        if let Some(name) = &server_name {
            validate_name(name)?;
        }
        let dir = self.invites();
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        // Forget invitations nobody redeemed in time.
        for entry in fs::read_dir(&dir)?.filter_map(Result::ok) {
            let expired = fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Invite>(&bytes).ok())
                .is_none_or(|invite| invite.expires_at <= now());
            if expired {
                let _ = fs::remove_file(entry.path());
            }
        }
        let mut bytes = [0_u8; 32];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("no system randomness"))?;
        let secret: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        crate::process::write_private(
            &dir.join(format!(
                "{}.json",
                crate::wire::sha256_hex(secret.as_bytes())
            )),
            &serde_json::to_vec(&Invite {
                expires_at: now() + ttl_seconds,
                scopes,
                server_name,
            })?,
        )?;
        Ok(secret)
    }

    /// Take the invitation for `secret` out of the store. Exactly one caller
    /// can take a given invitation: the rename is atomic.
    fn take_invite(&self, secret: &str) -> Result<Invite> {
        ensure!(
            secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid or expired pairing secret"
        );
        let path = self.invites().join(format!(
            "{}.json",
            crate::wire::sha256_hex(secret.to_ascii_lowercase().as_bytes())
        ));
        let mut nonce = [0_u8; 8];
        let _ = rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut nonce);
        let claimed = path.with_extension(format!(
            "taken-{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        fs::rename(&path, &claimed)
            .map_err(|_| anyhow::anyhow!("invalid or expired pairing secret"))?;
        let bytes = fs::read(&claimed);
        let _ = fs::remove_file(&claimed);
        let invite: Invite = serde_json::from_slice(&bytes?).context("damaged invitation")?;
        ensure!(
            invite.expires_at > now(),
            "invalid or expired pairing secret"
        );
        Ok(invite)
    }
}

impl super::PairingAuthority for TrustStore {
    fn redeem(
        &self,
        secret: &str,
        client_key: &str,
        card: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let card: Card = serde_json::from_value(card.clone()).context("not a card")?;
        let described = card.verify().context("the card does not verify")?;
        // The card must describe the key the TLS handshake just proved, so a
        // client cannot pair someone else's key.
        ensure!(
            described.role == Role::Card && described.subject.peer == client_key,
            "the card is not for the key this connection presented"
        );
        // Only now spend the secret: a malformed request does not burn it.
        let invite = self.take_invite(secret)?;
        self.add(&card, Role::Client, Some(invite.scopes), None, None, None)?;
        Ok(serde_json::to_value(super::pairing::card(
            &self.identity,
            invite.server_name,
            Vec::new(),
        )?)?)
    }
}

/// This machine's host name as a valid pairing name, so the server lists a
/// joining device by something recognisable. `None` if there is none usable.
pub fn device_name() -> Option<String> {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|name| {
            name.trim()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
                .take(MAX_NAME)
                .collect::<String>()
        })
        .filter(|name| validate_name(name).is_ok())
}

/// The one-time secret in a connection string (`&pair=...`), if any.
pub fn pairing_secret(connection: &str) -> Option<String> {
    connection
        .split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix("pair="))
        .map(str::to_owned)
}

/// Pair with the server `target` names by redeeming `secret`, and record it
/// (as `name`, reachable at `address`) in `store`. Both sides end up with
/// signed records about each other.
pub fn join(
    target: &super::Target,
    secret: &str,
    store: &TrustStore,
    name: Option<String>,
) -> Result<Paired> {
    let super::Target::Quic { host, port, peer } = target else {
        bail!("pairing is only offered over quic://");
    };
    let pin = peer
        .as_deref()
        .context("a pairing connection must pin the server (&peer=...)")?;
    let own = card(&store.identity, device_name(), Vec::new())?;
    let mut link =
        super::quic::QuicLink::connect_as(host, *port, pin, String::new(), Some(&store.identity))?;
    let server: Card = serde_json::from_value(link.pair(secret, serde_json::to_value(&own)?)?)
        .context("the server returned no card")?;
    let described = server
        .verify()
        .context("the server's card does not verify")?;
    ensure!(
        described.role == Role::Card && described.subject.peer == pin,
        "the server's card is not for the key it presented"
    );
    let address = super::Target::Quic {
        host: host.clone(),
        port: *port,
        peer: None,
    }
    .describe();
    store.add(&server, Role::Server, None, None, name, Some(vec![address]))?;
    store.server(pin)
}

impl super::PeerTrust for TrustStore {
    fn scopes(&self, peer_id: &str) -> Option<Scopes> {
        let path = self.path(peer_id, Role::Client);
        let file = fs::File::open(path).ok()?;
        let bytes = crate::wire::read_bounded(file, MAX_RECORD).ok()??;
        let record = Signed::parse(&bytes).ok()?;
        let statement = record.verify().ok()?;
        (statement.issuer.peer == self.identity.peer_id()
            && statement.role == Role::Client
            && statement.subject.peer == peer_id)
            .then_some(statement.scopes)
            .flatten()
    }
}

/// Where a device keeps its signed pairings unless told otherwise.
pub fn default_trust_dir(config: &crate::Config) -> Result<PathBuf> {
    Ok(crate::sync::state_dir(config)?.join("paired"))
}

#[cfg(test)]
mod tests {
    use super::super::PeerTrust;
    use super::*;

    fn device() -> (tempfile::TempDir, TrustStore) {
        let root = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::generate().unwrap());
        let store = TrustStore::open(&root.path().join("paired"), identity).unwrap();
        (root, store)
    }

    #[test]
    fn cards_prove_their_key_and_tampering_is_detected() {
        let identity = Identity::generate().unwrap();
        let card = card(
            &identity,
            Some("laptop".into()),
            vec!["quic://100.101.102.103:8788".into()],
        )
        .unwrap();
        assert_eq!(card.verify().unwrap().subject.peer, identity.peer_id());
        // Change any signed field and the signature no longer verifies.
        let mut renamed = card.clone();
        renamed.statement.subject.name = Some("phone".into());
        renamed.statement.issuer.name = Some("phone".into());
        assert!(renamed.verify().is_err());
        // Claim another key's id and the key check fails first.
        let mut lying = card.clone();
        lying.statement.subject.peer = "ab".repeat(32);
        lying.statement.issuer.peer = "ab".repeat(32);
        assert!(lying.verify().is_err());
        assert!(super::card(&identity, Some("bad name!".into()), vec![]).is_err());
        assert!(super::card(&identity, None, vec!["tcp://h:1".into()]).is_err());
    }

    #[test]
    fn pairing_is_signed_on_both_sides_and_scoped() {
        let (_s, server) = device();
        let (_c, client) = device();
        let client_card = card(client.identity(), Some("laptop".into()), vec![]).unwrap();
        let server_card = card(
            server.identity(),
            Some("phone".into()),
            vec!["quic://100.88.0.7:8788".into()],
        )
        .unwrap();
        // The server lets the laptop read only; the laptop records the phone.
        server
            .add(
                &client_card,
                Role::Client,
                Some(Scopes {
                    read: true,
                    write: false,
                }),
                None,
                None,
                None,
            )
            .unwrap();
        client
            .add(&server_card, Role::Server, None, None, None, None)
            .unwrap();
        assert_eq!(
            server.scopes(client.identity().peer_id()),
            Some(Scopes {
                read: true,
                write: false
            })
        );
        assert_eq!(server.scopes(server.identity().peer_id()), None);
        let phone = client.server("PHONE").unwrap();
        assert_eq!(phone.peer, server.identity().peer_id());
        assert_eq!(phone.addresses, vec!["quic://100.88.0.7:8788".to_string()]);
        // Removing the pairing revokes it.
        assert_eq!(server.remove(client.identity().peer_id()).unwrap(), 1);
        assert_eq!(server.scopes(client.identity().peer_id()), None);
    }

    #[test]
    fn records_not_signed_by_this_device_or_expired_are_ignored() {
        let (_s, server) = device();
        let (_o, other) = device();
        let (_c, client) = device();
        let client_card = card(client.identity(), None, vec![]).unwrap();
        // Another device's record copied into this store is not trusted.
        let foreign = other
            .add(&client_card, Role::Client, None, None, None, None)
            .unwrap();
        fs::write(
            server.path(client.identity().peer_id(), Role::Client),
            serde_json::to_vec(&foreign).unwrap(),
        )
        .unwrap();
        assert_eq!(server.scopes(client.identity().peer_id()), None);
        assert!(server.list().is_empty());
        // An expired record no longer counts.
        let expired = server
            .add(
                &client_card,
                Role::Client,
                None,
                Some(now() + 1),
                None,
                None,
            )
            .unwrap();
        assert!(expired.verify().is_ok());
        std::thread::sleep(std::time::Duration::from_millis(2100));
        assert_eq!(server.scopes(client.identity().peer_id()), None);
        // A device cannot pair with itself, nor take a record as a card.
        let own = card(server.identity(), None, vec![]).unwrap();
        assert!(
            server
                .add(&own, Role::Client, None, None, None, None)
                .is_err()
        );
        assert!(
            server
                .add(&foreign, Role::Client, None, None, None, None)
                .is_err()
        );
    }
}
