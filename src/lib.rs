#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![doc = include_str!("../README.md")]

/// Cryptographic primitives module.
pub mod crypto;

/// Core decryption engine and payload decoding logic.
mod engine;

/// Entropy abstraction used by the key stretcher.
mod entropy;

pub use engine::{EngineError, OuroborosEngine, PayloadIter, PayloadOp, CIPHERTEXT, ENTRY_SIZE};
#[cfg(feature = "hardened")]
pub use engine::{HardenedKdfParams, HARDENED_NONCE_SIZE, HARDENED_SALT_SIZE, HARDENED_TAG_SIZE};
pub use entropy::EntropySource;
