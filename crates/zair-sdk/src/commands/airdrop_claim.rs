//! Airdrop claim generation entry point.
//!
//! This module provides the main `airdrop_claim` function that orchestrates
//! the claim generation process for both Sapling and Orchard pools.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{Context as _, ensure};
use http::Uri;
use tokio::fs::File;
use tokio::io::BufReader;
use tracing::{debug, info, instrument, warn};
use zair_core::base::{Nullifier, Pool, SanitiseNullifiers};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs::{AirdropClaimInputs, ClaimInput, PublicInputs};
use zair_nonmembership::TreePosition;
use zair_scan::ViewingKeys;
use zair_scan::light_walletd::LightWalletd;
use zair_scan::scanner::{AccountNotesVisitor, BlockScanner};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

use super::note_metadata::NoteMetadata;
use super::pool_processor::{OrchardPool, PoolClaimResult, PoolProcessor, SaplingPool};
use super::sensitive_output::write_sensitive_output;
use crate::api::claims::{
    LoadedPoolData, PoolMerkleTree, build_gap_tree_and_serialize, build_pool_merkle_tree_from_file,
    build_pool_merkle_tree_from_memory,
};
use crate::common::{resolve_lightwalletd_url, to_zcash_network};
/// 1 MiB buffer for file I/O.
const FILE_BUF_SIZE: usize = 1024 * 1024;
/// Default Sapling snapshot path used by claim flows.
const DEFAULT_SAPLING_SNAPSHOT_FILE: &str = "snapshot-sapling.bin";
/// Default Orchard snapshot path used by claim flows.
const DEFAULT_ORCHARD_SNAPSHOT_FILE: &str = "snapshot-orchard.bin";
/// Default Sapling gap-tree path used by claim flows.
const DEFAULT_SAPLING_GAP_TREE_FILE: &str = "gaptree-sapling.bin";
/// Default Orchard gap-tree path used by claim flows.
const DEFAULT_ORCHARD_GAP_TREE_FILE: &str = "gaptree-orchard.bin";

/// Gap-tree handling mode for claim prepare/run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapTreeMode {
    /// Require precomputed `gaptree-*.bin` files and fail if missing/invalid.
    None,
    /// Rebuild gap trees from snapshots and persist to `gaptree-*.bin`.
    Rebuild,
    /// Build sparse in-memory trees directly from snapshots; do not read/write gap-tree files.
    Sparse,
}

fn resolve_snapshot_path_if_enabled(
    enabled: bool,
    provided_path: Option<PathBuf>,
    default_path: &str,
    pool: Pool,
) -> Option<PathBuf> {
    if !enabled {
        return None;
    }

    provided_path.or_else(|| {
        let path = PathBuf::from(default_path);
        info!(
            file = ?path,
            %pool,
            "No snapshot path provided; using default"
        );
        Some(path)
    })
}

fn resolve_gap_tree_path_if_enabled(
    enabled: bool,
    provided_path: Option<PathBuf>,
    default_path: &str,
    pool: Pool,
    gap_tree_mode: GapTreeMode,
) -> Option<PathBuf> {
    if !enabled || gap_tree_mode == GapTreeMode::Sparse {
        return None;
    }

    provided_path.or_else(|| {
        let path = PathBuf::from(default_path);
        info!(
            file = ?path,
            %pool,
            "No gap-tree path provided; using default"
        );
        Some(path)
    })
}

/// Generate airdrop claim
///
/// Generate airdrop claim proof for the given unified full viewing key (UFVK)
/// and output them to the specified file. The function scans the blockchain
/// for notes associated with the UFVK, constructs non-membership Merkle trees
/// for the provided snapshot nullifiers, and generates non-membership proofs
/// for the user's notes.
///
/// # Errors
/// Returns error if any step in the process fails,
/// including scanning for notes, loading nullifiers, building Merkle trees,
/// or generating proofs.
#[instrument(level = "debug", skip_all)]
#[allow(
    clippy::too_many_arguments,
    reason = "CLI command entrypoint carries explicit file/path knobs"
)]
pub async fn airdrop_claim(
    lightwalletd_url: Option<String>,
    sapling_snapshot_nullifiers: Option<PathBuf>,
    orchard_snapshot_nullifiers: Option<PathBuf>,
    sapling_gap_tree_file: Option<PathBuf>,
    orchard_gap_tree_file: Option<PathBuf>,
    gap_tree_mode: GapTreeMode,
    unified_full_viewing_key: String,
    birthday_height: u64,
    airdrop_claims_output_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(airdrop_configuration_file).await?)?;
    let sapling_snapshot_nullifiers = resolve_snapshot_path_if_enabled(
        airdrop_config.sapling.is_some(),
        sapling_snapshot_nullifiers,
        DEFAULT_SAPLING_SNAPSHOT_FILE,
        Pool::Sapling,
    );
    let orchard_snapshot_nullifiers = resolve_snapshot_path_if_enabled(
        airdrop_config.orchard.is_some(),
        orchard_snapshot_nullifiers,
        DEFAULT_ORCHARD_SNAPSHOT_FILE,
        Pool::Orchard,
    );
    let sapling_gap_tree_file = resolve_gap_tree_path_if_enabled(
        airdrop_config.sapling.is_some(),
        sapling_gap_tree_file,
        DEFAULT_SAPLING_GAP_TREE_FILE,
        Pool::Sapling,
        gap_tree_mode,
    );
    let orchard_gap_tree_file = resolve_gap_tree_path_if_enabled(
        airdrop_config.orchard.is_some(),
        orchard_gap_tree_file,
        DEFAULT_ORCHARD_GAP_TREE_FILE,
        Pool::Orchard,
        gap_tree_mode,
    );
    validate_pool_inputs(
        &airdrop_config,
        sapling_snapshot_nullifiers.as_ref(),
        orchard_snapshot_nullifiers.as_ref(),
        sapling_gap_tree_file.as_ref(),
        orchard_gap_tree_file.as_ref(),
        gap_tree_mode,
    )?;

    let network = to_zcash_network(airdrop_config.network);
    let lightwalletd_url = resolve_lightwalletd_url(network, lightwalletd_url.as_deref());
    let ufvk = UnifiedFullViewingKey::decode(&network, &unified_full_viewing_key)
        .map_err(|e| eyre::eyre!("Failed to decode Unified Full Viewing Key: {e:?}"))?;
    debug!(birthday_height, "Using user-provided birthday height");

    let account_notes = find_user_notes(
        &lightwalletd_url,
        network,
        airdrop_config.snapshot_height,
        ufvk.clone(),
        birthday_height,
    )
    .await?;

    let viewing_keys = ViewingKeys::new(&ufvk);

    // Process pools in parallel
    let (sapling_result, orchard_result) = tokio::try_join!(
        process_pool_claims::<SaplingPool>(
            airdrop_config.sapling.is_some(),
            &account_notes,
            &viewing_keys,
            &airdrop_config,
            sapling_snapshot_nullifiers,
            sapling_gap_tree_file,
            gap_tree_mode,
        ),
        process_pool_claims::<OrchardPool>(
            airdrop_config.orchard.is_some(),
            &account_notes,
            &viewing_keys,
            &airdrop_config,
            orchard_snapshot_nullifiers,
            orchard_gap_tree_file,
            gap_tree_mode,
        ),
    )?;

    let total_claims = sapling_result
        .claims
        .len()
        .checked_add(orchard_result.claims.len());

    let user_proofs = AirdropClaimInputs {
        sapling_claim_input: sapling_result.claims,
        orchard_claim_input: orchard_result.claims,
    };

    let json = serde_json::to_string_pretty(&user_proofs)?;
    write_sensitive_output(&airdrop_claims_output_file, &json).await?;

    info!(
        file = ?airdrop_claims_output_file,
        count = total_claims,
        "airdrop claims written"
    );

    Ok(())
}

fn validate_pool_inputs(
    airdrop_config: &AirdropConfiguration,
    sapling_snapshot_nullifiers: Option<&PathBuf>,
    orchard_snapshot_nullifiers: Option<&PathBuf>,
    sapling_gap_tree_file: Option<&PathBuf>,
    orchard_gap_tree_file: Option<&PathBuf>,
    gap_tree_mode: GapTreeMode,
) -> eyre::Result<()> {
    let config_has_sapling = airdrop_config.sapling.is_some();
    let config_has_orchard = airdrop_config.orchard.is_some();

    ensure!(
        config_has_sapling || config_has_orchard,
        "Airdrop configuration must enable at least one pool (sapling/orchard)"
    );

    ensure!(
        !(config_has_sapling && sapling_snapshot_nullifiers.is_none()),
        "Airdrop configuration enables Sapling, but --snapshot-sapling is missing"
    );
    ensure!(
        !(config_has_orchard && orchard_snapshot_nullifiers.is_none()),
        "Airdrop configuration enables Orchard, but --snapshot-orchard is missing"
    );
    if gap_tree_mode == GapTreeMode::None {
        ensure!(
            !(config_has_sapling && sapling_gap_tree_file.is_none()),
            "Airdrop configuration enables Sapling, but --gap-tree-sapling is missing (or default gaptree-sapling.bin is unavailable)"
        );
        ensure!(
            !(config_has_orchard && orchard_gap_tree_file.is_none()),
            "Airdrop configuration enables Orchard, but --gap-tree-orchard is missing (or default gaptree-orchard.bin is unavailable)"
        );
    }

    Ok(())
}

/// Scan the blockchain for user notes within the snapshot range.
#[instrument(level = "debug", skip_all)]
async fn find_user_notes(
    lightwalletd_url: &str,
    network: Network,
    snapshot_height: u64,
    ufvk: UnifiedFullViewingKey,
    birthday_height: u64,
) -> eyre::Result<AccountNotesVisitor> {
    ensure!(
        birthday_height <= snapshot_height,
        "Birthday height cannot be past snapshot height"
    );

    let lightwalletd_url =
        Uri::from_str(lightwalletd_url).context("lightwalletd URL is required")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    // NOTE: We are interested at tree state from the point that the account could have notes
    let start_block = birthday_height;
    let tree_state_height = start_block.saturating_sub(1);
    let tree_state = lightwalletd.get_tree_state(tree_state_height).await?;

    // Initialize visitor from tree state
    let visitor = AccountNotesVisitor::from_tree_state(&tree_state)?;

    let scan_range = RangeInclusive::new(birthday_height, snapshot_height);

    info!("Scanning for user notes");
    let initial_metadata = BlockScanner::parse_tree_state(&tree_state)?;

    // Use channel-based scanning to keep non-Send BlockScanner off async tasks
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

    Ok(visitor)
}

/// Build the non-membership merkle tree for a pool.
///
/// This is a file-I/O wrapper around the API functions from `api::claims`.
async fn build_pool_merkle_tree(
    snapshot_nullifiers_path: &Path,
    gap_tree_path: Option<&Path>,
    user_nullifiers: SanitiseNullifiers,
    pool: Pool,
    gap_tree_mode: GapTreeMode,
) -> eyre::Result<LoadedPoolData> {
    let chain_nullifiers = load_nullifiers_from_file(snapshot_nullifiers_path).await?;

    info!(
        count = chain_nullifiers.len(),
        %pool,
        "Loaded chain nullifiers"
    );

    match gap_tree_mode {
        GapTreeMode::Sparse => {
            info!(
                %pool,
                "Building sparse non-membership tree from snapshot nullifiers..."
            );
            // Take ownership for this call
            let chain_for_sparse = chain_nullifiers;
            build_pool_merkle_tree_from_memory(
                chain_for_sparse,
                user_nullifiers,
                pool,
                gap_tree_mode,
            )
            .await
            .map_err(|e| eyre::eyre!("Failed to build sparse tree: {e}"))
        }
        GapTreeMode::Rebuild => {
            let gap_tree_path = gap_tree_path.ok_or_else(|| {
                eyre::eyre!("Missing gap-tree path for pool {pool} in Rebuild mode")
            })?;

            info!(%pool, "Rebuilding gap-tree from snapshot nullifiers...");
            // Read snapshot bytes for rebuild
            let snapshot_bytes = tokio::fs::read(snapshot_nullifiers_path).await?;
            let serialized = build_gap_tree_and_serialize(&snapshot_bytes, pool)
                .await
                .map_err(|e| eyre::eyre!("Failed to build gap tree: {e}"))?;

            tokio::fs::write(gap_tree_path, &serialized)
                .await
                .with_context(|| {
                    format!("Failed to write gap-tree to {}", gap_tree_path.display())
                })?;

            // Load the rebuilt gap tree using the chain nullifiers we already loaded
            build_pool_merkle_tree_from_file(chain_nullifiers, user_nullifiers, &serialized, pool)
                .await
                .map_err(|e| eyre::eyre!("Failed to load rebuilt gap tree: {e}"))
        }
        GapTreeMode::None => {
            let gap_tree_path = gap_tree_path
                .ok_or_else(|| eyre::eyre!("Missing gap-tree path for pool {pool} in None mode"))?;

            info!(%pool, "Loading gap tree from precomputed file...");
            let bytes = tokio::fs::read(gap_tree_path).await.with_context(|| {
                format!(
                    "Failed to read gap-tree from {}. Retry with --gap-tree-mode rebuild",
                    gap_tree_path.display()
                )
            })?;

            // Take ownership
            let chain_for_load = chain_nullifiers;
            build_pool_merkle_tree_from_file(chain_for_load, user_nullifiers, &bytes, pool)
                .await
                .map_err(|e| eyre::eyre!("Failed to load gap tree: {e}"))
        }
    }
}

/// Generate airdrop claims for the user's notes.
///
/// This generic function works with any metadata type implementing `NoteMetadata`,
/// producing claim inputs with the appropriate pool-specific private inputs.
fn generate_claims<M: NoteMetadata>(
    tree: &PoolMerkleTree,
    user_nullifiers: &[TreePosition],
    note_metadata_map: &HashMap<Nullifier, M>,
    viewing_keys: &ViewingKeys,
) -> eyre::Result<Vec<ClaimInput<M::PoolPrivateInputs>>> {
    user_nullifiers
        .iter()
        .enumerate()
        .map(|(index, tree_position)| {
            let metadata = note_metadata_map
                .get(&tree_position.nullifier)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Missing note metadata for nullifier {} at claim index {}",
                        tree_position.nullifier,
                        index
                    )
                })?;

            let nf_merkle_proof = tree.witness_bytes(tree_position.leaf_position.into())?;

            debug!(
                index,
                "Generated proof for nullifier {:x?} at block height {}",
                tree_position.nullifier,
                metadata.block_height()
            );

            let private_inputs =
                metadata.to_private_inputs(tree_position, nf_merkle_proof, viewing_keys)?;
            Ok(ClaimInput {
                public_inputs: PublicInputs {
                    airdrop_nullifier: metadata.hiding_nullifier(),
                },
                private_inputs,
            })
        })
        .collect()
}

/// Generic pool claim processor.
///
/// Processes claims for any pool type implementing `PoolProcessor`.
#[instrument(level = "debug", skip_all, fields(pool = %P::POOL))]
async fn process_pool_claims<P: PoolProcessor>(
    pool_enabled_in_config: bool,
    visitor: &AccountNotesVisitor,
    viewing_keys: &ViewingKeys,
    airdrop_config: &AirdropConfiguration,
    snapshot_nullifiers: Option<PathBuf>,
    gap_tree_file: Option<PathBuf>,
    gap_tree_mode: GapTreeMode,
) -> eyre::Result<PoolClaimResult<P::PrivateInputs>> {
    if !pool_enabled_in_config {
        return Ok(PoolClaimResult::empty());
    }

    let Some(snapshot_nullifiers) = snapshot_nullifiers else {
        return Err(eyre::eyre!(
            "{} snapshot nullifiers path is required by the airdrop configuration",
            P::POOL
        ));
    };
    if gap_tree_mode != GapTreeMode::Sparse && gap_tree_file.is_none() {
        return Err(eyre::eyre!(
            "{} gap-tree path is required by the airdrop configuration",
            P::POOL
        ));
    }

    let Some(notes) = P::collect_notes(visitor, viewing_keys, airdrop_config)? else {
        warn!("UFVK has no {} viewing key; skipping", P::POOL);
        return Ok(PoolClaimResult::empty());
    };

    // Build merkle tree
    let user_nullifiers = SanitiseNullifiers::new(notes.keys().copied().collect());
    let pool_data = build_pool_merkle_tree(
        &snapshot_nullifiers,
        gap_tree_file.as_deref(),
        user_nullifiers,
        P::POOL,
        gap_tree_mode,
    )
    .await?;

    // Verify merkle root
    let anchor = pool_data.tree.root_bytes();
    let Some(expected_root) = P::expected_root(airdrop_config) else {
        return Err(eyre::eyre!(
            "{} pool is unexpectedly missing in the airdrop configuration",
            P::POOL
        ));
    };
    ensure!(
        expected_root == anchor,
        "{} merkle root mismatch with airdrop configuration",
        P::POOL
    );

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
    .with_context(|| format!("Failed to generate {} claims", P::POOL))?;

    Ok(PoolClaimResult { claims })
}

/// Load nullifiers from a file.
#[instrument(level = "debug", fields(path))]
pub async fn load_nullifiers_from_file(path: &Path) -> eyre::Result<SanitiseNullifiers> {
    debug!("Loading nullifiers from file");

    let file = File::open(path).await?;
    let reader = BufReader::with_capacity(FILE_BUF_SIZE, file);

    let nullifiers = zair_scan::read_nullifiers(reader)
        .await
        .context(format!("Failed to read {}", path.display()))?;
    let sanitised_nullifiers = SanitiseNullifiers::new(nullifiers);

    info!(file = %path.display(), "Read {} nullifiers from disk", sanitised_nullifiers.len());

    Ok(sanitised_nullifiers)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use group::ff::PrimeField as _;
    use pasta_curves::pallas;
    use tokio::io::{AsyncWriteExt as _, BufWriter};
    use zair_core::schema::config::{
        AirdropConfiguration, AirdropNetwork, OrchardSnapshot, SaplingSnapshot,
        ValueCommitmentScheme,
    };
    use zair_nonmembership::{OrchardGapTree, SaplingGapTree};
    use zair_scan::write_nullifiers;

    use super::*;

    const POOLS: [Pool; 2] = [Pool::Sapling, Pool::Orchard];

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("zair-{prefix}-{}-{unique}.bin", std::process::id()))
    }

    fn chain_nullifiers(pool: Pool) -> SanitiseNullifiers {
        if pool == Pool::Orchard {
            SanitiseNullifiers::new(vec![
                Nullifier::from(pallas::Base::from(1_u64).to_repr()),
                Nullifier::from(pallas::Base::from(5_u64).to_repr()),
            ])
        } else {
            SanitiseNullifiers::new(vec![
                Nullifier::from([1_u8; 32]),
                Nullifier::from([3_u8; 32]),
            ])
        }
    }

    async fn write_snapshot_file(path: &Path, nullifiers: &SanitiseNullifiers) {
        let file = File::create(path)
            .await
            .expect("snapshot file should be created");
        let mut writer = BufWriter::with_capacity(FILE_BUF_SIZE, file);
        write_nullifiers(nullifiers, &mut writer)
            .await
            .expect("snapshot nullifiers should be written");
        writer.flush().await.expect("snapshot writer should flush");
    }

    async fn cleanup(paths: &[&Path]) {
        for path in paths {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    fn test_config(with_sapling: bool, with_orchard: bool) -> AirdropConfiguration {
        AirdropConfiguration::new(
            AirdropNetwork::Testnet,
            3_839_800,
            with_sapling.then_some(SaplingSnapshot {
                note_commitment_root: [1_u8; 32],
                nullifier_gap_root: [2_u8; 32],
                target_id: "ZAIRTEST".to_string(),
                value_commitment_scheme: ValueCommitmentScheme::Native,
            }),
            with_orchard.then_some(OrchardSnapshot {
                note_commitment_root: [3_u8; 32],
                nullifier_gap_root: [4_u8; 32],
                target_id: "ZAIRTEST:O".to_string(),
                value_commitment_scheme: ValueCommitmentScheme::Native,
            }),
        )
    }

    #[tokio::test]
    async fn corrupted_gap_tree_fails_without_rebuild() {
        for pool in POOLS {
            let snapshot_path = unique_temp_path("snapshot");
            let gaptree_path = unique_temp_path("gaptree");
            let chain = chain_nullifiers(pool);
            write_snapshot_file(&snapshot_path, &chain).await;
            tokio::fs::write(&gaptree_path, [0_u8, 1_u8, 2_u8])
                .await
                .expect("corrupt cache bytes should be written");

            let result = build_pool_merkle_tree(
                &snapshot_path,
                Some(&gaptree_path),
                SanitiseNullifiers::new(vec![]),
                pool,
                GapTreeMode::None,
            )
            .await;

            cleanup(&[snapshot_path.as_path(), gaptree_path.as_path()]).await;

            let err = result
                .err()
                .expect("corrupt gap-tree should fail without rebuild");
            let err_str = err.to_string();
            assert!(
                err_str.contains("gap-tree file is too short") ||
                    err_str.contains("Failed to load gap tree"),
                "error: {err_str}"
            );
        }
    }

    #[tokio::test]
    async fn corrupted_gap_tree_is_rebuilt_and_rewritten_with_rebuild_flag() {
        for pool in POOLS {
            let snapshot_path = unique_temp_path("snapshot");
            let gaptree_path = unique_temp_path("gaptree");
            let chain = chain_nullifiers(pool);
            write_snapshot_file(&snapshot_path, &chain).await;
            tokio::fs::write(&gaptree_path, [0_u8, 1_u8, 2_u8])
                .await
                .expect("corrupt cache bytes should be written");

            let pool_data = build_pool_merkle_tree(
                &snapshot_path,
                Some(&gaptree_path),
                SanitiseNullifiers::new(vec![]),
                pool,
                GapTreeMode::Rebuild,
            )
            .await
            .expect("rebuild should recover from corrupt gap-tree");

            let persisted = tokio::fs::read(&gaptree_path)
                .await
                .expect("gap-tree should be rewritten");
            assert!(
                persisted.len() > 3,
                "rewritten gap-tree should not equal corrupt placeholder bytes"
            );

            let persisted_root = if pool == Pool::Orchard {
                OrchardGapTree::from_bytes(&persisted)
                    .expect("rewritten orchard cache should decode")
                    .root_bytes()
            } else {
                SaplingGapTree::from_bytes(&persisted)
                    .expect("rewritten sapling cache should decode")
                    .root_bytes()
            };
            assert_eq!(
                persisted_root,
                pool_data.tree.root_bytes(),
                "rewritten cache root should match in-memory tree root"
            );

            cleanup(&[snapshot_path.as_path(), gaptree_path.as_path()]).await;
        }
    }

    #[tokio::test]
    async fn sparse_mode_builds_without_gap_tree_file() {
        for pool in POOLS {
            let snapshot_path = unique_temp_path("snapshot");
            let chain = chain_nullifiers(pool);
            write_snapshot_file(&snapshot_path, &chain).await;

            let pool_data = build_pool_merkle_tree(
                &snapshot_path,
                None,
                SanitiseNullifiers::new(vec![]),
                pool,
                GapTreeMode::Sparse,
            )
            .await
            .expect("sparse mode should build without gap-tree file");

            assert_eq!(
                pool_data.user_nullifiers.len(),
                0,
                "empty user nullifier set should produce no mapped positions"
            );

            cleanup(&[snapshot_path.as_path()]).await;
        }
    }

    #[test]
    fn sparse_mode_discards_gap_tree_paths() {
        let resolved = resolve_gap_tree_path_if_enabled(
            true,
            Some(PathBuf::from("gaptree-sapling.bin")),
            DEFAULT_SAPLING_GAP_TREE_FILE,
            Pool::Sapling,
            GapTreeMode::Sparse,
        );
        assert!(
            resolved.is_none(),
            "sparse mode should discard provided gap-tree path"
        );
    }

    #[test]
    fn none_mode_requires_gap_tree_paths() {
        let config = test_config(false, true);
        let err = validate_pool_inputs(
            &config,
            None,
            Some(&PathBuf::from("snapshot-orchard.bin")),
            None,
            None,
            GapTreeMode::None,
        )
        .expect_err("none mode must require gap-tree path for enabled pools");
        assert!(err.to_string().contains("--gap-tree-orchard is missing"));
    }
}
