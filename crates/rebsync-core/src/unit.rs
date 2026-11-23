//! Optional bridge/unit control-plane primitives from `ragbaz-unit-core`.
//!
//! This module wires the extracted unit protocol into rebsync without changing
//! rebsync's artifact/storage model. Use it for control messages (peer sync,
//! fleet commands, event acks), not as a replacement for content-addressed
//! layer manifests or ObjectStorage.

pub use ragbaz_unit_core::{
    BlobRef, BridgeRegisterReq, BridgeRegisterResp, BridgeToFc, CapProbe, Change as InboxChange,
    DeliveryStatus, Event, EventState, FcToBridge, Inbox, InboxError, MachineId, OsMachineId,
    PluginDependency, PluginManifest, PowProof, Promise, ResponseMeta, SyncPage, SyncRequest,
    UnitCaps, VersionSelector,
};

/// Recommended service name for LAN discovery of a bridge/unit daemon.
pub const RAGBAZD_SERVICE_TYPE: &str = "_ragbazd._tcp";
