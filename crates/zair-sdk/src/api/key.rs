//! In-memory key derivation utilities.

use thiserror::Error;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

/// Errors that can occur during key derivation.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Returned when the seed slice is not exactly 64 bytes.
    #[error("Seed must be exactly 64 bytes, got {0}")]
    InvalidSeedLength(usize),
    /// Returned when the account index cannot be converted into a valid ZIP-32 `AccountId`.
    #[error("Invalid account ID: {0}")]
    InvalidAccountId(String),
    /// Returned when `UnifiedSpendingKey::from_seed` fails.
    #[error("Failed to derive spending key: {0}")]
    KeyDerivation(String),
}

/// Derive a UFVK from an in-memory seed.
///
/// # Arguments
///
/// * `network` - Zcash network
/// * `account_id` - ZIP-32 account index
/// * `seed` - 64-byte BIP-39 seed
///
/// # Returns
///
/// Encoded UFVK string.
///
/// # Errors
///
/// Returns an error if key derivation fails.
pub fn derive_ufvk_from_seed(
    network: Network,
    account_id: u32,
    seed: &[u8],
) -> Result<String, KeyError> {
    let seed: &[u8; 64] = seed
        .try_into()
        .map_err(|_| KeyError::InvalidSeedLength(seed.len()))?;

    let account_id =
        AccountId::try_from(account_id).map_err(|e| KeyError::InvalidAccountId(e.to_string()))?;

    let usk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
        .map_err(|e| KeyError::KeyDerivation(e.to_string()))?;

    Ok(usk.to_unified_full_viewing_key().encode(&network))
}
