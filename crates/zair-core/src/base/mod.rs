//! Foundational primitive types and byte/serde helpers.

use std::fmt;

use serde::{Deserialize, Serialize};

mod digest;
mod nullifier;
mod utils;
mod value_commitment;

pub use digest::{hash_bytes, hash_message, signature_digest};
pub use nullifier::{NULLIFIER_SIZE, Nullifier, SanitiseNullifiers};
pub use utils::{ReverseBytes, ReversedHex};
pub use value_commitment::{VALUE_COMMIT_SHA256_PREFIX, cv_sha256, cv_sha256_preimage};

/// Zcash shielded pool identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pool {
    /// Sapling pool.
    Sapling,
    /// Orchard pool.
    Orchard,
}

impl Pool {
    /// Encoded pool byte used in signature digest preimages.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Sapling => 0,
            Self::Orchard => 1,
        }
    }
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sapling => f.write_str("Sapling"),
            Self::Orchard => f.write_str("Orchard"),
        }
    }
}
