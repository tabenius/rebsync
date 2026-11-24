//! Encrypted sharing: `rbq-peer/1` over QUIC, next to the `rbq-peer/0` HTTP
//! endpoint.
//!
//! The HTTP endpoint is plaintext: anyone on the same network sees the token
//! and every object. This serves the same object store with rbq's QUIC
//! transport instead: TLS 1.3 to this phone's long-term key, which a client
//! pins from the connection string (`peer=`) or QR code. The token still
//! authorises, but never crosses the network in clear.
//!
//! The phone's data root can move between volumes at runtime, so the
//! transport reads storage through [`FollowStorage`], which always uses the
//! current root and answers "unavailable" (503) while a move holds it, like
//! the HTTP endpoint does.

use crate::peer::{Clients, SharedStorage};
use rebsync_core::{
    ObjectKey, ObjectStorage, PutOutcome, StorageError,
    storage::{ObjectMeta, StorageCapabilities},
    transport::{self, pairing::TrustStore, quic::Identity},
};
use std::{
    ops::Range,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};

/// The object store as it is now, wherever the data root lives.
pub struct FollowStorage(pub SharedStorage);

impl FollowStorage {
    fn current(&self) -> Result<Arc<dyn ObjectStorage>, StorageError> {
        // Never block a network request behind a volume move: refuse, and
        // let the peer retry, as the HTTP endpoint does.
        self.0
            .try_read()
            .map(|storage| storage.clone())
            .map_err(|_| StorageError::Unavailable("data is being moved; retry later".into()))
    }
}

impl ObjectStorage for FollowStorage {
    fn capabilities(&self) -> StorageCapabilities {
        // Report the weakest guarantees while the store is unreadable.
        self.current()
            .map(|storage| storage.capabilities())
            .unwrap_or(StorageCapabilities {
                atomic_create_if_absent: false,
                owner_only_permissions: false,
                durable_publication: false,
                range_reads: false,
                raw_prefix_listing: false,
                max_key_bytes: 1024,
            })
    }

    fn put(&self, key: &ObjectKey, data: &[u8]) -> Result<ObjectMeta, StorageError> {
        self.current()?.put(key, data)
    }

    fn put_if_absent(&self, key: &ObjectKey, data: &[u8]) -> Result<PutOutcome, StorageError> {
        self.current()?.put_if_absent(key, data)
    }

    fn get(&self, key: &ObjectKey) -> Result<Vec<u8>, StorageError> {
        self.current()?.get(key)
    }

    fn get_range(&self, key: &ObjectKey, range: Range<u64>) -> Result<Vec<u8>, StorageError> {
        self.current()?.get_range(key, range)
    }

    fn head(&self, key: &ObjectKey) -> Result<ObjectMeta, StorageError> {
        self.current()?.head(key)
    }

    fn list_prefix(&self, prefix: &str, limit: usize) -> Result<Vec<ObjectMeta>, StorageError> {
        self.current()?.list_prefix(prefix, limit)
    }

    fn delete(&self, key: &ObjectKey) -> Result<(), StorageError> {
        self.current()?.delete(key)
    }
}

/// A running QUIC share.
pub struct QuicShare {
    server: transport::Server,
    pub port: u16,
    pub peer_id: String,
    /// The phone's signed pairings: devices that connect with their key and
    /// no token, and one-time invitations for new ones.
    pub trust: Arc<TrustStore>,
}

impl QuicShare {
    /// Serve on UDP `port` (falling back to any free port), as the identity
    /// kept in `identity_dir` (created on first use, owner-only).
    /// `trust_dir` holds the phone's signed pairings (created owner-only).
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        port: u16,
        token: String,
        storage: SharedStorage,
        writes_paused: Arc<AtomicBool>,
        identity_dir: &Path,
        trust_dir: &Path,
        clients: Arc<Clients>,
    ) -> Result<Self, String> {
        transport::validate_token(&token).map_err(|e| e.to_string())?;
        let identity =
            Arc::new(Identity::load_or_create(identity_dir).map_err(|e| format!("{e:#}"))?);
        let trust =
            Arc::new(TrustStore::open(trust_dir, identity.clone()).map_err(|e| format!("{e:#}"))?);
        // QUIC clients appear in the same Connected clients list as HTTP ones.
        let service = transport::Service::new(
            Arc::new(FollowStorage(storage)),
            token,
            writes_paused,
        )
        .with_observer(clients)
        // Paired devices connect with their key alone; invitations pair new
        // ones on first contact.
        .with_trust(trust.clone())
        .with_pairing(trust.clone());
        let server = transport::Server::bind_quic("0.0.0.0", port, service.clone(), &identity)
            .or_else(|_| transport::Server::bind_quic("0.0.0.0", 0, service, &identity))
            .map_err(|e| format!("{e:#}"))?;
        let port = match &server.target {
            transport::Target::Quic { port, .. } => *port,
            _ => unreachable!("bind_quic returns a QUIC target"),
        };
        Ok(Self {
            server,
            port,
            peer_id: identity.peer_id().to_owned(),
            trust,
        })
    }

    pub fn stop(self) {
        self.server.stop();
    }
}

/// The connection string a client pastes or scans.
pub fn pairing(host: &str, port: u16, peer_id: &str, token: &str) -> String {
    format!("rbq+quic://{host}:{port}?peer={peer_id}&token={token}")
}

/// A one-time pairing string: no token, a secret that pairs the scanning
/// device's key on first use and then stops working.
pub fn invitation(host: &str, port: u16, peer_id: &str, secret: &str) -> String {
    format!("rbq+quic://{host}:{port}?peer={peer_id}&pair={secret}")
}
