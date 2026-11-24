//! Compiles Rebeqah's platform-independent modules unchanged, without Tauri,
//! so their tests (including a live HTTP test of the peer endpoint) run on any
//! host and in CI without GTK or an Android toolchain.
#[path = "../../src-tauri/src/dash_link.rs"]
pub mod dash_link;
#[path = "../../src-tauri/src/datastore.rs"]
pub mod datastore;
#[path = "../../src-tauri/src/peer.rs"]
pub mod peer;
#[path = "../../src-tauri/src/quic_share.rs"]
pub mod quic_share;
#[path = "../../src-tauri/src/volumes.rs"]
pub mod volumes;
