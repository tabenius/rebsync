//! A [`Sealer`] keyed by the desktop's Secret Service (GNOME Keyring,
//! KWallet, KeePassXC): the RBQ-SERVICE-PLAN.md §1 "Linux desktop" backend.
//!
//! The Secret Service holds one random 32-byte wrapping key per credential
//! directory (item "rbq credential store", attributes `service=rbq-credentials`
//! and `user=wrapping-key:<SHA-256 of the directory path>`). Secrets are
//! encrypted with XChaCha20-Poly1305 under that key, with a random 24-byte
//! nonce, and authenticated with the entry's associated data. The key never
//! touches the credential directory.
//!
//! A locked or absent Secret Service is [`StoreError::Locked`] /
//! [`StoreError::Unavailable`]: the caller decides, there is no silent
//! plaintext fallback.

use super::StoreError;
use super::files::Sealer;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const SEALER_ID: &str = "secret-service.xchacha20poly1305.v1";
const SERVICE: &str = "rbq-credentials";
const NONCE: usize = 24;

/// The wrapping key for one credential directory, from the Secret Service.
pub struct SecretServiceSealer {
    cipher: XChaCha20Poly1305,
}

fn keyring_error(error: keyring::Error) -> StoreError {
    match error {
        keyring::Error::NoStorageAccess(_) => StoreError::Locked,
        keyring::Error::NoEntry => StoreError::NotFound,
        _ => StoreError::Unavailable,
    }
}

impl SecretServiceSealer {
    /// The sealer for the credential store in `dir`, creating its wrapping
    /// key on first use.
    pub fn for_store(dir: &Path) -> Result<Self, StoreError> {
        let canonical = std::fs::canonicalize(dir).map_err(|_| StoreError::Unavailable)?;
        let user = format!(
            "wrapping-key:{:x}",
            Sha256::digest(canonical.to_string_lossy().as_bytes())
        );
        let entry = keyring::Entry::new(SERVICE, &user).map_err(keyring_error)?;
        let key = match entry.get_secret() {
            Ok(key) => key,
            Err(keyring::Error::NoEntry) => {
                let mut key = vec![0_u8; 32];
                getrandom::getrandom(&mut key).map_err(|_| StoreError::Unavailable)?;
                entry.set_secret(&key).map_err(keyring_error)?;
                // Re-read: if another process created one first, use theirs.
                entry.get_secret().map_err(keyring_error)?
            }
            Err(error) => return Err(keyring_error(error)),
        };
        if key.len() != 32 {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            cipher: XChaCha20Poly1305::new_from_slice(&key).map_err(|_| StoreError::Invalid)?,
        })
    }
}

impl Sealer for SecretServiceSealer {
    fn id(&self) -> &str {
        SEALER_ID
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0_u8; NONCE];
        getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Unavailable)?;
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| StoreError::Invalid)?;
        Ok([&nonce[..], &ciphertext].concat())
    }

    fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, StoreError> {
        if sealed.len() < NONCE {
            return Err(StoreError::Invalid);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE);
        self.cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| StoreError::Invalid)
    }
}
