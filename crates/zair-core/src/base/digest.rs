//! Message utilities.

use blake2b_simd::Params;
use thiserror::Error;

use super::Pool;

/// Domain marker prepended to submission-signature digest preimages.
pub const SIGNATURE_PREIMAGE_TAG: &[u8; 8] = b"ZAIR_SIG";
/// Protocol version byte included in signature digest preimages.
pub const SIGNATURE_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum DigestError {
    /// The target ID length exceeds 255 bytes.
    #[error("target ID length exceeds 255 bytes")]
    TargetIdTooLong,
    /// The proof length exceeds [`u32::MAX`].
    #[error("proof length exceeds u32::MAX")]
    ProofTooLong,
}

/// Hash arbitrary bytes to 32 bytes with `BLAKE2b`.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Params::new().hash_length(32).hash(data);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Hash message bytes for submission signing.
#[must_use]
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    hash_bytes(message)
}

/// Build the 32-byte message signed by spend authorization keys.
///
/// Preimage layout:
/// `ZAIR_SIG_V1 || version:u8 || pool:u8 || target_id_len:u8 || target_id || proof_hash ||
/// message_hash`
///
/// # Errors
/// Returns an error if the target ID length exceeds 255 bytes.
pub fn signature_digest(
    pool: Pool,
    target_id: &[u8],
    proof_hash: &[u8; 32],
    message_hash: &[u8; 32],
) -> Result<[u8; 32], DigestError> {
    let target_len = u8::try_from(target_id.len()).map_err(|_| DigestError::TargetIdTooLong)?;

    let mut preimage = Vec::new();
    preimage.extend_from_slice(SIGNATURE_PREIMAGE_TAG);
    preimage.push(SIGNATURE_VERSION);
    preimage.push(pool.as_byte());
    preimage.push(target_len);
    preimage.extend_from_slice(target_id);
    preimage.extend_from_slice(proof_hash);
    preimage.extend_from_slice(message_hash);

    Ok(hash_bytes(&preimage))
}
