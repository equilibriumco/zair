//! Per-claim message assignment helpers for submission signing/verification.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eyre::{Context as _, ensure};
use serde::{Deserialize, Serialize};
use zair_core::base::{Nullifier, hash_message};

use crate::api::sign::ResolvedMessageHashes;

/// One per-claim message-file assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimMessageAssignment {
    /// Airdrop nullifier identifying the claim entry.
    pub airdrop_nullifier: Nullifier,
    /// File path containing message bytes for this claim.
    pub message_file: PathBuf,
}

/// JSON payload for per-claim message assignments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaimMessagesFile {
    /// Sapling claim message assignments.
    #[serde(default)]
    pub sapling: Vec<ClaimMessageAssignment>,
    /// Orchard claim message assignments.
    #[serde(default)]
    pub orchard: Vec<ClaimMessageAssignment>,
}

async fn load_assignment_hashes(
    assignments: Vec<ClaimMessageAssignment>,
    pool_name: &str,
) -> eyre::Result<BTreeMap<Nullifier, [u8; 32]>> {
    let mut by_nullifier = BTreeMap::new();
    for assignment in assignments {
        let message_bytes = tokio::fs::read(&assignment.message_file)
            .await
            .with_context(|| {
                format!(
                    "Failed to read {} message file for nullifier {} at {}",
                    pool_name,
                    assignment.airdrop_nullifier,
                    assignment.message_file.display()
                )
            })?;
        let hash = hash_message(&message_bytes);
        let previous = by_nullifier.insert(assignment.airdrop_nullifier, hash);
        ensure!(
            previous.is_none(),
            "Duplicate {} message assignment for airdrop nullifier {}",
            pool_name,
            assignment.airdrop_nullifier
        );
    }
    Ok(by_nullifier)
}

/// Load shared/per-claim message hashes.
///
/// If both are provided, per-claim mappings override the shared message for matching nullifiers.
pub async fn resolve_message_hashes(
    shared_message_file: Option<&PathBuf>,
    messages_file: Option<&PathBuf>,
) -> eyre::Result<ResolvedMessageHashes> {
    let shared = if let Some(path) = shared_message_file {
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("Failed to read shared message file at {}", path.display()))?;
        Some(hash_message(&bytes))
    } else {
        None
    };

    let Some(messages_file) = messages_file else {
        return Ok(ResolvedMessageHashes {
            shared,
            ..ResolvedMessageHashes::default()
        });
    };

    let payload: ClaimMessagesFile = serde_json::from_str(
        &tokio::fs::read_to_string(messages_file).await?,
    )
    .with_context(|| {
        format!(
            "Failed to parse claim messages JSON from {}",
            messages_file.display()
        )
    })?;

    let (sapling, orchard) = tokio::try_join!(
        load_assignment_hashes(payload.sapling, "Sapling"),
        load_assignment_hashes(payload.orchard, "Orchard"),
    )?;

    Ok(ResolvedMessageHashes {
        shared,
        sapling,
        orchard,
    })
}
