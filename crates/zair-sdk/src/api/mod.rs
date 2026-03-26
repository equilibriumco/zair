//! In-memory API for zair-sdk.
//!
//! This module provides file-free variants of the claim pipeline:
//! scan -> prove -> sign.
//! All functions accept in-memory types and return results directly,
//! with no filesystem I/O.

pub mod claims;
pub mod key;
#[cfg(feature = "prove")]
pub mod prove;
pub mod scan;
pub mod sign;

// Re-export key types for convenience
pub use sign::ResolvedMessageHashes;
use thiserror::Error;
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::submission::ClaimSubmission;

use super::common::to_zcash_network;
use crate::api::claims::ClaimsError;
use crate::api::key::KeyError;
#[cfg(feature = "prove")]
use crate::api::prove::ProveError;
use crate::api::scan::ScanError;
use crate::api::sign::SignError;

/// Errors that can occur in the API pipeline.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Returned when the key-derivation sub-step fails.
    #[error("Key derivation failed: {0}")]
    Key(#[from] KeyError),
    /// Returned when the chain-scanning sub-step fails.
    #[error("Chain scanning failed: {0}")]
    Scan(#[from] ScanError),
    /// Returned when the proof-generation sub-step fails.
    #[cfg(feature = "prove")]
    #[error("Proof generation failed: {0}")]
    Prove(#[from] ProveError),
    /// Returned when the claim-processing sub-step fails.
    #[error("Claim processing failed: {0}")]
    Claims(#[from] ClaimsError),
    /// Returned when the signing sub-step fails.
    #[error("Signing failed: {0}")]
    Sign(#[from] SignError),
    /// No message hashes provided for signing.
    ///
    /// Provide `ResolvedMessageHashes` with at least a shared hash or per-proof hashes.
    #[error(
        "No message hashes provided for signing. Supply ResolvedMessageHashes with a shared hash and/or per-proof entries"
    )]
    MissingMessageHashes,
}

/// Run the full in-memory claim pipeline: scan -> prove -> sign.
///
/// # Arguments
///
/// * `lightwalletd_url` - gRPC endpoint (None for network default)
/// * `sapling_snapshot_nullifiers` - Sapling nullifiers as raw bytes
/// * `orchard_snapshot_nullifiers` - Orchard nullifiers as raw bytes
/// * `seed` - 64-byte BIP-39 seed
/// * `account_id` - ZIP-32 account index
/// * `sapling_proving_key` - Groth16 proving key bytes (None if no Sapling claims)
/// * `orchard_params_bytes` - Halo2 params bytes (None if no Orchard claims)
/// * `birthday_height` - earliest block for note scanning
/// * `config` - airdrop configuration
/// * `message_hashes` - pre-computed message hashes to sign; per‑proof hashes (keyed by airdrop
///   nullifier) take precedence over the shared fallback
///
/// # Errors
///
/// Returns an error if any step in the pipeline fails.
#[cfg(feature = "prove")]
#[allow(clippy::too_many_arguments, reason = "API entrypoint")]
pub async fn run(
    lightwalletd_url: Option<String>,
    sapling_snapshot_nullifiers: &[u8],
    orchard_snapshot_nullifiers: &[u8],
    seed: &[u8],
    account_id: u32,
    sapling_proving_key: Option<&[u8]>,
    orchard_params_bytes: Option<&[u8]>,
    birthday_height: u64,
    config: &AirdropConfiguration,
    message_hashes: Option<ResolvedMessageHashes>,
) -> Result<ClaimSubmission, ApiError> {
    let ufvk = key::derive_ufvk_from_seed(to_zcash_network(config.network), account_id, seed)
        .map_err(ApiError::Key)?;

    let claims = scan::airdrop_claim_from_config(
        lightwalletd_url,
        sapling_snapshot_nullifiers,
        orchard_snapshot_nullifiers,
        &ufvk,
        birthday_height,
        config,
    )
    .await
    .map_err(ApiError::Scan)?;

    let (proofs, secrets) = prove::generate_claim_proofs_from_bytes(
        claims,
        seed,
        account_id,
        sapling_proving_key,
        orchard_params_bytes,
        config,
    )
    .await
    .map_err(ApiError::Prove)?;

    let message_hashes = message_hashes.ok_or(ApiError::MissingMessageHashes)?;
    sign::sign_claim_submission_from_bytes(
        proofs,
        secrets,
        seed,
        account_id,
        config,
        &message_hashes,
    )
    .await
    .map_err(ApiError::Sign)
}
