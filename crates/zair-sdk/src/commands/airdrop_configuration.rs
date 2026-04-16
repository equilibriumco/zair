use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{Context as _, ContextCompat as _, ensure};
use http::Uri;
use tokio::fs::File;
use tokio::io::BufWriter;
use tracing::{info, instrument, warn};
use zair_core::base::{Pool, SanitiseNullifiers};
use zair_core::schema::config::{
    AirdropConfiguration, OrchardSnapshot, SaplingSnapshot, ValueCommitmentScheme,
};
use zair_nonmembership::{OrchardGapTree, SaplingGapTree};
use zair_scan::light_walletd::LightWalletd;
use zair_scan::scanner::ChainNullifiersVisitor;
use zair_scan::write_nullifiers;
use zcash_protocol::consensus::BlockHeight;

use crate::common::{CommonConfig, PoolSelection, resolve_lightwalletd_url, to_airdrop_network};
use crate::network_params::{
    orchard_activation_height, sapling_activation_height, scan_start_height,
};

/// 1 MiB buffer for file I/O.
const FILE_BUF_SIZE: usize = 1024 * 1024;

/// Build the airdrop configuration by fetching nullifiers from lightwalletd,
/// computing the non-membership roots, and exporting snapshot metadata.
///
/// # Errors
/// Returns an error if fetching nullifiers, validating inputs, or writing files fails.
#[instrument(level = "debug", skip_all, fields(snapshot_height = config.snapshot_height, ?pool))]
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "CLI-facing command entrypoint mirrors explicit command arguments"
)]
pub async fn build_airdrop_configuration(
    config: CommonConfig,
    pool: PoolSelection,
    configuration_output_file: PathBuf,
    sapling_snapshot_nullifiers: PathBuf,
    orchard_snapshot_nullifiers: PathBuf,
    sapling_gap_tree_file: PathBuf,
    orchard_gap_tree_file: PathBuf,
    no_gap_tree: bool,
    sapling_target_id: String,
    sapling_value_commitment_scheme: ValueCommitmentScheme,
    orchard_target_id: String,
    orchard_value_commitment_scheme: ValueCommitmentScheme,
) -> eyre::Result<()> {
    validate_target_ids(pool, &sapling_target_id, &orchard_target_id)?;

    let scan_range = resolve_snapshot_scan_range(config.network, pool, config.snapshot_height)?;
    let lightwalletd_url =
        resolve_lightwalletd_url(config.network, config.lightwalletd_url.as_deref());

    info!(?scan_range, "Fetching nullifiers for snapshot range");
    let lightwalletd_url = Uri::from_str(&lightwalletd_url).context("Invalid lightwalletd URL")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    let mut visitor = ChainNullifiersVisitor::default();
    let mut last_fetch_pct = 0_usize;
    info!(progress = "0%", "Fetching nullifiers");
    lightwalletd
        .scan_nullifiers_with_progress(
            &mut visitor,
            &scan_range,
            |height, scanned, total| {
                if total == 0 {
                    return;
                }
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "Fetch progress percentage uses saturating operations and is guarded against total=0"
                )]
                let pct = scanned.saturating_mul(100).saturating_div(total);
                if pct >= last_fetch_pct.saturating_add(10) {
                    last_fetch_pct = pct;
                    info!(
                        progress = %format!("{pct}%"),
                        current_height = height,
                        scanned_blocks = scanned,
                        total_blocks = total,
                        "Fetching nullifiers"
                    );
                }
            },
        )
        .await?;
    let (sapling_nullifiers, orchard_nullifiers) = visitor.sanitise_nullifiers();

    let sapling_handle = tokio::spawn(process_pool(
        pool.includes_sapling(),
        Pool::Sapling,
        sapling_nullifiers,
        sapling_snapshot_nullifiers,
        if no_gap_tree {
            None
        } else {
            Some(sapling_gap_tree_file)
        },
    ));
    let orchard_handle = tokio::spawn(process_pool(
        pool.includes_orchard(),
        Pool::Orchard,
        orchard_nullifiers,
        orchard_snapshot_nullifiers,
        if no_gap_tree {
            None
        } else {
            Some(orchard_gap_tree_file)
        },
    ));

    let (sapling_nf_root, orchard_nf_root) = tokio::try_join!(sapling_handle, orchard_handle)?;

    // Note commitment roots needed for proving note existence.
    let snapshot_height_u32: u32 = config
        .snapshot_height
        .try_into()
        .context("Snapshot height too large")?;

    let note_commitment_roots = lightwalletd
        .commitment_tree_anchors(BlockHeight::from_u32(snapshot_height_u32))
        .await
        .context("Failed to fetch commitment tree roots from lightwalletd")?;

    let sapling = if pool.includes_sapling() {
        let sapling_nf_root = sapling_nf_root?
            .context("Sapling pool enabled but nullifier gap root was not produced")?;
        Some(SaplingSnapshot {
            note_commitment_root: note_commitment_roots.sapling,
            nullifier_gap_root: sapling_nf_root,
            target_id: sapling_target_id,
            value_commitment_scheme: sapling_value_commitment_scheme,
        })
    } else {
        None
    };

    let orchard = if pool.includes_orchard() {
        let orchard_nf_root = orchard_nf_root?
            .context("Orchard pool enabled but nullifier gap root was not produced")?;
        Some(OrchardSnapshot {
            note_commitment_root: note_commitment_roots.orchard,
            nullifier_gap_root: orchard_nf_root,
            target_id: orchard_target_id,
            value_commitment_scheme: orchard_value_commitment_scheme,
        })
    } else {
        None
    };

    let config_out = AirdropConfiguration::new(
        to_airdrop_network(config.network),
        config.snapshot_height,
        sapling,
        orchard,
    );

    let json = serde_json::to_string_pretty(&config_out)?;
    tokio::fs::write(&configuration_output_file, json).await?;

    info!(file = ?configuration_output_file, "Exported configuration");
    Ok(())
}

fn validate_target_ids(
    pool: PoolSelection,
    sapling_target_id: &str,
    orchard_target_id: &str,
) -> eyre::Result<()> {
    if pool.includes_sapling() {
        ensure!(
            sapling_target_id.len() == 8,
            "Sapling target_id must be exactly 8 bytes"
        );
    }
    if pool.includes_orchard() {
        ensure!(
            orchard_target_id.len() <= 32,
            "Orchard target_id must be at most 32 bytes"
        );
    }
    Ok(())
}

/// Resolve the scan range for collecting nullifiers for a snapshot.
///
/// For `Both`, scanning starts at min(Sapling start, Orchard start), so one chain
/// pass covers both pools.
fn resolve_snapshot_scan_range(
    network: zcash_protocol::consensus::Network,
    pool: PoolSelection,
    snapshot_height: u64,
) -> eyre::Result<RangeInclusive<u64>> {
    if pool.includes_sapling() {
        let sapling_start = sapling_activation_height(network);
        ensure!(
            snapshot_height >= sapling_start,
            "Snapshot height {} is below Sapling activation height {}",
            snapshot_height,
            sapling_start
        );
    }

    if pool.includes_orchard() {
        let orchard_start = orchard_activation_height(network);
        ensure!(
            snapshot_height >= orchard_start,
            "Snapshot height {} is below Orchard activation height {}",
            snapshot_height,
            orchard_start
        );
    }

    let scan_start = scan_start_height(network, pool);
    Ok(scan_start..=snapshot_height)
}

#[instrument(level = "debug", skip_all, fields(pool = ?pool, store = %store.display()))]
async fn process_pool(
    enabled: bool,
    pool: Pool,
    nullifiers: SanitiseNullifiers,
    store: PathBuf,
    gap_tree_store: Option<PathBuf>,
) -> eyre::Result<Option<[u8; 32]>> {
    if !enabled {
        return Ok(None);
    }

    if nullifiers.is_empty() {
        warn!("No nullifiers collected; using canonical empty-gap root");
    } else {
        info!(count = nullifiers.len(), "Collected nullifiers");
    }

    let file = File::create(&store).await?;
    let mut writer = BufWriter::with_capacity(FILE_BUF_SIZE, file);
    write_nullifiers(&nullifiers, &mut writer).await?;
    info!(file = ?store, pool = ?pool, "Saved nullifiers");

    // The tree is built, serialized, and written all on the blocking thread so
    // the multi-GB in-memory representation never crosses the async boundary.
    let merkle_root = tokio::task::spawn_blocking(move || -> eyre::Result<[u8; 32]> {
        match pool {
            Pool::Sapling => {
                let tree = SaplingGapTree::from_nullifiers_with_progress(
                    &nullifiers,
                    progress_logger(pool),
                )?;
                let root = tree.root_bytes();
                if let Some(path) = gap_tree_store {
                    persist_gap_tree(pool, &path, |w| tree.write_to(w))?;
                }
                Ok(root)
            }
            Pool::Orchard => {
                let tree = OrchardGapTree::from_nullifiers_with_progress(
                    &nullifiers,
                    progress_logger(pool),
                )?;
                let root = tree.root_bytes();
                if let Some(path) = gap_tree_store {
                    persist_gap_tree(pool, &path, |w| tree.write_to(w))?;
                }
                Ok(root)
            }
        }
    })
    .await??;

    Ok(Some(merkle_root))
}

fn persist_gap_tree(
    pool: Pool,
    path: &Path,
    write_to: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
) -> eyre::Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create gap-tree file {}", path.display()))?;
    let mut writer = std::io::BufWriter::with_capacity(FILE_BUF_SIZE, file);
    write_to(&mut writer)
        .with_context(|| format!("Failed to write gap-tree to {}", path.display()))?;
    writer
        .into_inner()
        .map_err(|e| eyre::eyre!("Failed to flush gap-tree {}: {e}", path.display()))?;
    info!(pool = ?pool, file = %path.display(), "Saved gap-tree");
    Ok(())
}

fn progress_logger(pool: Pool) -> impl FnMut(usize, usize) {
    move |current: usize, total: usize| {
        if total == 0 {
            return;
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "Tree build progress percentage uses saturating operations and is guarded against total=0"
        )]
        let pct = current.saturating_mul(100).saturating_div(total);
        info!(pool = ?pool, progress = %format!("{pct}%"), "Building non-membership tree");
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use zair_core::schema::config::{AirdropNetwork, OrchardSnapshot, SaplingSnapshot};

    use super::*;

    #[test]
    fn deserialize_json_format() {
        // Documents the expected JSON format for consumers.
        let json = r#"{
          "network": "testnet",
          "snapshot_height": 200,
          "sapling": {
            "note_commitment_root": "0101010101010101010101010101010101010101010101010101010101010101",
            "nullifier_gap_root": "0505050505050505050505050505050505050505050505050505050505050505",
            "target_id": "ZAIRTEST",
            "value_commitment_scheme": "native"
          },
          "orchard": {
            "note_commitment_root": "0202020202020202020202020202020202020202020202020202020202020202",
            "nullifier_gap_root": "0606060606060606060606060606060606060606060606060606060606060606",
            "target_id": "ZAIRTEST:O",
            "value_commitment_scheme": "sha256"
          }
        }"#;

        let json_config: AirdropConfiguration =
            serde_json::from_str(json).expect("Failed to deserialize JSON");

        let expected_config = AirdropConfiguration::new(
            AirdropNetwork::Testnet,
            200,
            Some(SaplingSnapshot {
                note_commitment_root: [1_u8; 32],
                nullifier_gap_root: [5_u8; 32],
                target_id: "ZAIRTEST".to_string(),
                value_commitment_scheme: ValueCommitmentScheme::Native,
            }),
            Some(OrchardSnapshot {
                note_commitment_root: [2_u8; 32],
                nullifier_gap_root: [6_u8; 32],
                target_id: "ZAIRTEST:O".to_string(),
                value_commitment_scheme: ValueCommitmentScheme::Sha256,
            }),
        );

        assert_eq!(json_config, expected_config);
    }

    #[test]
    fn orchard_allows_target_id_up_to_32_bytes() {
        let target = "a".repeat(32);
        validate_target_ids(PoolSelection::Orchard, "ZAIRTEST", &target)
            .expect("Orchard target_id should be allowed up to 32 bytes");
    }

    #[tokio::test]
    async fn process_pool_empty_nullifiers_uses_canonical_root() {
        let nullifiers = SanitiseNullifiers::new(vec![]);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zair-empty-nullifiers-{}-{unique}.bin",
            std::process::id()
        ));

        let root = process_pool(true, Pool::Sapling, nullifiers, path.clone(), None)
            .await
            .expect("processing should succeed")
            .expect("enabled pool should produce a root");

        let expected_nullifiers = SanitiseNullifiers::new(vec![]);
        let expected_root = SaplingGapTree::from_nullifiers(&expected_nullifiers)
            .expect("empty nullifiers should produce canonical tree")
            .root_bytes();
        assert_eq!(root, expected_root);

        let size = std::fs::metadata(&path)
            .expect("snapshot file must exist")
            .len();
        assert_eq!(size, 0, "empty snapshot file should contain zero bytes");

        std::fs::remove_file(path).expect("temporary snapshot file should be removable");
    }
}
