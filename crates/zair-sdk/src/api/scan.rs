//! In-memory chain scanning and claim input generation.

use std::str::FromStr as _;

use http::Uri;
use thiserror::Error;
use tracing::{info, instrument, warn};
use zair_core::base::SanitiseNullifiers;
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs::AirdropClaimInputs;
use zair_scan::ViewingKeys;
use zair_scan::light_walletd::LightWalletd;
use zair_scan::light_walletd::error::LightWalletdError;
use zair_scan::scanner::{AccountNotesVisitor, ScannerError};
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::api::claims::{
    GapTreeMode, OrchardPool, PoolClaimResult, PoolProcessor, SaplingPool,
    build_pool_merkle_tree_from_memory, generate_claims,
};
use crate::common::{resolve_lightwalletd_url, to_zcash_network};

/// Errors that can occur during chain scanning.
#[derive(Debug, Error)]
pub enum ScanError {
    /// Returned when the airdrop configuration requires a pool's snapshot nullifiers but none
    /// were provided.
    #[error("{0} snapshot nullifiers are required by the airdrop configuration")]
    MissingSnapshotNullifiers(String),
    /// Returned when a pool section is absent from the airdrop configuration while processing
    /// notes for that pool.
    #[error("{0} pool is unexpectedly missing in the airdrop configuration")]
    MissingPoolConfig(String),
    /// Returned when the non-membership tree root computed from snapshot nullifiers does not
    /// match the root stored in the airdrop configuration.
    #[error("{0} merkle root mismatch with airdrop configuration")]
    MerkleRootMismatch(String),
    /// Returned when the UFVK string cannot be decoded for the configured network.
    #[error("Failed to decode Unified Full Viewing Key: {0}")]
    InvalidUfvk(String),
    /// Returned when the binary snapshot nullifier bytes cannot be parsed into valid nullifiers.
    #[error("Failed to parse {0} snapshot nullifiers: {1}")]
    InvalidNullifiers(String, String),
    /// Returned when claim input assembly fails — tree building, witness generation, or
    /// metadata conversion.
    #[error("Failed to generate {0} claims: {1}")]
    ClaimGeneration(String, String),
    /// Returned when a lightwalletd gRPC call or connection fails.
    #[error("Lightwalletd error: {0}")]
    Lightwalletd(#[from] LightWalletdError),
    /// Returned when the block scanner encounters an error parsing tree state or commitment
    /// trees.
    #[error("Scanner error: {0}")]
    Scanner(#[from] ScannerError),
}

#[instrument(level = "debug", skip_all, fields(pool = %P::POOL))]
pub(crate) async fn process_pool_claims_from_memory<P: PoolProcessor>(
    pool_enabled_in_config: bool,
    visitor: &AccountNotesVisitor,
    viewing_keys: &ViewingKeys,
    airdrop_config: &AirdropConfiguration,
    snapshot_nullifiers: Option<SanitiseNullifiers>,
    gap_tree_mode: GapTreeMode,
) -> Result<PoolClaimResult<P::PrivateInputs>, ScanError> {
    if !pool_enabled_in_config {
        return Ok(PoolClaimResult::empty());
    }

    let Some(snapshot_nullifiers) = snapshot_nullifiers else {
        return Err(ScanError::MissingSnapshotNullifiers(P::POOL.to_string()));
    };

    let notes = match P::collect_notes(visitor, viewing_keys, airdrop_config) {
        Ok(Some(notes)) => notes,
        Ok(None) => {
            warn!("UFVK has no {} viewing key; skipping", P::POOL);
            return Ok(PoolClaimResult::empty());
        }
        Err(e) => {
            return Err(ScanError::ClaimGeneration(
                P::POOL.to_string(),
                e.to_string(),
            ));
        }
    };

    let user_nullifiers = SanitiseNullifiers::new(notes.keys().copied().collect());
    let pool_data = build_pool_merkle_tree_from_memory(
        snapshot_nullifiers,
        user_nullifiers,
        P::POOL,
        gap_tree_mode,
    )
    .await
    .map_err(|e| ScanError::ClaimGeneration(P::POOL.to_string(), e.to_string()))?;

    let anchor = pool_data.tree.root_bytes();
    let Some(expected_root) = P::expected_root(airdrop_config) else {
        return Err(ScanError::MissingPoolConfig(P::POOL.to_string()));
    };
    if expected_root != anchor {
        return Err(ScanError::MerkleRootMismatch(P::POOL.to_string()));
    }

    info!(
        pool = %P::POOL,
        "Extracting witness paths for user nullifiers"
    );
    let claims = generate_claims(
        &pool_data.tree,
        &pool_data.user_nullifiers,
        &notes,
        viewing_keys,
    )
    .map_err(|e| ScanError::ClaimGeneration(P::POOL.to_string(), e.to_string()))?;

    Ok(PoolClaimResult { claims })
}

/// Scan the chain for eligible notes and produce claim inputs.
///
/// # Arguments
///
/// * `lightwalletd_url` - gRPC endpoint (None for network default)
/// * `sapling_snapshot_nullifiers` - Sapling nullifiers as raw bytes (from binary snapshot file)
/// * `orchard_snapshot_nullifiers` - Orchard nullifiers as raw bytes (from binary snapshot file)
/// * `ufvk_encoded` - encoded Unified Full Viewing Key string
/// * `birthday_height` - earliest block for note scanning
/// * `config` - airdrop configuration
///
/// # Returns
///
/// `AirdropClaimInputs` ready for the proving step.
///
/// # Errors
///
/// Returns an error if scanning, tree building, or claim assembly fails.
#[allow(clippy::too_many_arguments, reason = "API entrypoint")]
pub async fn airdrop_claim_from_config(
    lightwalletd_url: Option<String>,
    sapling_snapshot_nullifiers: &[u8],
    orchard_snapshot_nullifiers: &[u8],
    ufvk_encoded: &str,
    birthday_height: u64,
    config: &AirdropConfiguration,
) -> Result<AirdropClaimInputs, ScanError> {
    let network = to_zcash_network(config.network);
    let lightwalletd_url = resolve_lightwalletd_url(network, lightwalletd_url.as_deref());

    let ufvk =
        UnifiedFullViewingKey::decode(&network, ufvk_encoded).map_err(ScanError::InvalidUfvk)?;

    let viewing_keys = ViewingKeys::new(&ufvk);

    let lightwalletd_url = Uri::from_str(&lightwalletd_url)
        .map_err(|e| ScanError::InvalidUfvk(format!("Invalid URI: {e}")))?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    let tree_state = lightwalletd
        .get_tree_state(birthday_height.saturating_sub(1))
        .await?;
    let visitor = AccountNotesVisitor::from_tree_state(&tree_state)?;

    let scan_range = birthday_height..=config.snapshot_height;
    let initial_metadata = zair_scan::scanner::BlockScanner::parse_tree_state(&tree_state)?;

    let (visitor, _final_metadata) = lightwalletd
        .scan_blocks_spawned(ufvk, network, visitor, &scan_range, Some(initial_metadata))
        .await?;

    info!(
        total = visitor
            .sapling_notes()
            .len()
            .checked_add(visitor.orchard_notes().len()),
        "Scan complete"
    );

    let sapling_nullifiers = if config.sapling.is_some() && !sapling_snapshot_nullifiers.is_empty()
    {
        Some(
            zair_scan::read_nullifiers(sapling_snapshot_nullifiers)
                .await
                .map_err(|e| ScanError::InvalidNullifiers("Sapling".to_string(), e.to_string()))?,
        )
    } else {
        None
    };

    let orchard_nullifiers = if config.orchard.is_some() && !orchard_snapshot_nullifiers.is_empty()
    {
        Some(
            zair_scan::read_nullifiers(orchard_snapshot_nullifiers)
                .await
                .map_err(|e| ScanError::InvalidNullifiers("Orchard".to_string(), e.to_string()))?,
        )
    } else {
        None
    };

    let sapling_result = process_pool_claims_from_memory::<SaplingPool>(
        config.sapling.is_some(),
        &visitor,
        &viewing_keys,
        config,
        sapling_nullifiers.map(SanitiseNullifiers::new),
        GapTreeMode::Sparse,
    )
    .await?;

    let orchard_result = process_pool_claims_from_memory::<OrchardPool>(
        config.orchard.is_some(),
        &visitor,
        &viewing_keys,
        config,
        orchard_nullifiers.map(SanitiseNullifiers::new),
        GapTreeMode::Sparse,
    )
    .await?;

    Ok(AirdropClaimInputs {
        sapling_claim_input: sapling_result.claims,
        orchard_claim_input: orchard_result.claims,
    })
}
