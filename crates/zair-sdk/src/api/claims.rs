//! Claim types and processing for SDK API.

use std::collections::HashMap;

use thiserror::Error;
use tracing::{debug, info};
use zair_core::base::{Nullifier, Pool, SanitiseNullifiers};
use zair_core::schema::proof_inputs::{ClaimInput, PublicInputs};
use zair_nonmembership::{
    MerklePathError, NonMembershipTree, OrchardNonMembershipTree, TreePosition,
};
use zair_scan::ViewingKeys;

pub use crate::commands::{
    ClaimProofsOutput, ClaimSecretsOutput, GapTreeMode, NoteMetadata, OrchardPool, PoolClaimResult,
    PoolProcessor, SaplingPool,
};

/// Errors that can occur during claim processing.
#[derive(Debug, Error)]
pub enum ClaimsError {
    /// Returned when a non-`Sparse` gap-tree mode is passed to the in-memory tree builder.
    #[error("In-memory build requires GapTreeMode::Sparse, got {0}")]
    InvalidGapTreeMode(String),
    /// Returned when the `spawn_blocking` merkle-tree construction task fails or the tree
    /// library returns an error.
    #[error("Failed to build {0} merkle tree: {1}")]
    MerkleTreeBuild(String, String),
    /// Returned when the scanned note-metadata map has no entry for a nullifier the user owns —
    /// indicates a scanning consistency issue.
    #[error("Missing note metadata for nullifier {0} at claim index {1}")]
    MissingNoteMetadata(Nullifier, usize),
    /// Returned when the sparse non-membership tree cannot produce a witness path for a given
    /// leaf position.
    #[error("Failed to generate merkle witness for {0}: {1}")]
    WitnessGeneration(String, String),
    /// Returned when note metadata cannot be converted into the pool-specific private inputs
    /// required for proof generation.
    #[error("Failed to convert note metadata to private inputs for {0}: {1}")]
    PrivateInputsConversion(String, String),
}

/// Loaded pool data including the non-membership merkle-tree and user's nullifier positions.
pub struct LoadedPoolData {
    /// The non-membership merkle tree for the pool.
    pub tree: PoolMerkleTree,
    /// The user's nullifiers with tree positions needed to generate proofs.
    pub user_nullifiers: Vec<TreePosition>,
}

/// Pool-specific non-membership tree variants.
pub enum PoolMerkleTree {
    /// Sapling pool non-membership tree using sparse representation.
    SaplingSparse(NonMembershipTree),
    /// Orchard pool non-membership tree using sparse representation.
    OrchardSparse(OrchardNonMembershipTree),
}

impl PoolMerkleTree {
    /// Returns the root hash of the merkle tree as 32 bytes.
    #[must_use]
    pub fn root_bytes(&self) -> [u8; 32] {
        match self {
            Self::SaplingSparse(tree) => tree.root().to_bytes(),
            Self::OrchardSparse(tree) => tree.root_bytes(),
        }
    }

    /// Returns the merkle path (witness) for a given leaf position.
    ///
    /// # Errors
    ///
    /// Returns an error if the witness cannot be generated for the given position.
    pub fn witness_bytes(&self, position: u64) -> Result<Vec<[u8; 32]>, MerklePathError> {
        match self {
            Self::SaplingSparse(tree) => tree
                .witness(position.into())
                .map(|path| path.into_iter().map(|node| node.to_bytes()).collect()),
            Self::OrchardSparse(tree) => tree.witness_bytes(position.into()),
        }
    }
}

/// Build the non-membership merkle tree for a pool from in-memory nullifiers.
///
/// Only supports `Sparse` gap tree mode (no file I/O).
///
/// # Errors
///
/// Returns an error if the gap tree mode is not `Sparse` or if tree construction fails.
pub async fn build_pool_merkle_tree_from_memory(
    chain_nullifiers: SanitiseNullifiers,
    user_nullifiers: SanitiseNullifiers,
    pool: Pool,
    gap_tree_mode: GapTreeMode,
) -> Result<LoadedPoolData, ClaimsError> {
    if gap_tree_mode != GapTreeMode::Sparse {
        return Err(ClaimsError::InvalidGapTreeMode(format!(
            "{gap_tree_mode:?}"
        )));
    }

    let use_orchard_tree = pool == Pool::Orchard;

    info!(
        count = chain_nullifiers.len(),
        %pool,
        "Loaded chain nullifiers"
    );
    info!(
        %pool,
        "Building sparse non-membership tree from snapshot nullifiers..."
    );

    let chain_for_build = chain_nullifiers;
    let user_for_build = user_nullifiers;
    let (tree, user_positions) = tokio::task::spawn_blocking(move || {
        if use_orchard_tree {
            OrchardNonMembershipTree::from_chain_and_user_nullifiers_with_progress(
                &chain_for_build,
                &user_for_build,
                |_current, _total| {},
            )
            .map(|(tree, positions)| (PoolMerkleTree::OrchardSparse(tree), positions))
        } else {
            NonMembershipTree::from_chain_and_user_nullifiers_with_progress(
                &chain_for_build,
                &user_for_build,
                |_current, _total| {},
            )
            .map(|(tree, positions)| (PoolMerkleTree::SaplingSparse(tree), positions))
        }
    })
    .await
    .map_err(|e| ClaimsError::MerkleTreeBuild(pool.to_string(), e.to_string()))?
    .map_err(|e| ClaimsError::MerkleTreeBuild(pool.to_string(), e.to_string()))?;

    info!(%pool, "Non-membership tree ready");
    Ok(LoadedPoolData {
        tree,
        user_nullifiers: user_positions,
    })
}

/// Generate airdrop claims for the user's notes.
///
/// This generic function works with any metadata type implementing `NoteMetadata`,
/// producing claim inputs with the appropriate pool-specific private inputs.
///
/// # Errors
///
/// Returns an error if note metadata is missing for any nullifier or if merkle witness generation
/// fails.
#[allow(clippy::implicit_hasher)]
pub fn generate_claims<M: NoteMetadata>(
    tree: &PoolMerkleTree,
    user_nullifiers: &[TreePosition],
    note_metadata_map: &HashMap<Nullifier, M>,
    viewing_keys: &ViewingKeys,
) -> Result<Vec<ClaimInput<M::PoolPrivateInputs>>, ClaimsError> {
    user_nullifiers
        .iter()
        .enumerate()
        .map(|(index, tree_position)| {
            let metadata = note_metadata_map.get(&tree_position.nullifier).ok_or(
                ClaimsError::MissingNoteMetadata(tree_position.nullifier, index),
            )?;

            let nf_merkle_proof = tree
                .witness_bytes(tree_position.leaf_position.into())
                .map_err(|e| {
                    ClaimsError::WitnessGeneration("unknown".to_string(), e.to_string())
                })?;

            debug!(
                index,
                "Generated proof for nullifier {:x?} at block height {}",
                tree_position.nullifier,
                metadata.block_height()
            );

            let private_inputs = metadata
                .to_private_inputs(tree_position, nf_merkle_proof, viewing_keys)
                .map_err(|e| {
                    ClaimsError::PrivateInputsConversion("unknown".to_string(), e.to_string())
                })?;
            Ok(ClaimInput {
                public_inputs: PublicInputs {
                    airdrop_nullifier: metadata.hiding_nullifier(),
                },
                private_inputs,
            })
        })
        .collect()
}
