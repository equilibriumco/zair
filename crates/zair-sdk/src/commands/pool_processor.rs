//! Pool processors for Sapling and Orchard claim generation.
//!
//! This module defines the `PoolProcessor` trait and its implementations
//! for Sapling and Orchard pools, enabling generic claim processing.

use std::collections::HashMap;

use zair_core::base::{Nullifier, Pool};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs::{ClaimInput, OrchardPrivateInputs, SaplingPrivateInputs};
use zair_scan::ViewingKeys;
use zair_scan::scanner::AccountNotesVisitor;
use zair_scan::user_nullifiers::NoteNullifier as _;

use super::note_metadata::{
    NoteMetadata, OrchardNoteMetadata, SaplingNoteMetadata, orchard_g_d_from_diversifier,
};

/// Result of processing claims for a single pool.
pub struct PoolClaimResult<P> {
    /// The claim inputs for this pool.
    pub claims: Vec<ClaimInput<P>>,
}

impl<P> PoolClaimResult<P> {
    /// Create an empty result for when a pool has no claims.
    #[must_use]
    pub const fn empty() -> Self {
        Self { claims: Vec::new() }
    }
}

/// Trait for processing claims for a specific pool.
///
/// This trait abstracts over pool-specific operations, enabling a single
/// generic function to handle both Sapling and Orchard claim processing.
pub trait PoolProcessor {
    /// The pool-specific private inputs type.
    type PrivateInputs;
    /// The pool-specific note metadata type.
    type Metadata: NoteMetadata<PoolPrivateInputs = Self::PrivateInputs>;

    /// The pool identifier.
    const POOL: Pool;

    /// Returns the expected merkle root from the airdrop configuration.
    fn expected_root(config: &AirdropConfiguration) -> Option<[u8; 32]>;

    /// Collects note metadata from the visitor.
    /// Returns `None` if the viewing key is not available.
    ///
    /// # Errors
    ///
    /// Returns an error if note collection fails.
    fn collect_notes(
        visitor: &AccountNotesVisitor,
        viewing_keys: &ViewingKeys,
        airdrop_config: &AirdropConfiguration,
    ) -> eyre::Result<Option<HashMap<Nullifier, Self::Metadata>>>;
}

/// Sapling pool processor.
pub struct SaplingPool;

impl PoolProcessor for SaplingPool {
    type PrivateInputs = SaplingPrivateInputs;
    type Metadata = SaplingNoteMetadata;

    const POOL: Pool = Pool::Sapling;

    fn expected_root(config: &AirdropConfiguration) -> Option<[u8; 32]> {
        config.sapling.as_ref().map(|pool| pool.nullifier_gap_root)
    }

    fn collect_notes(
        visitor: &AccountNotesVisitor,
        viewing_keys: &ViewingKeys,
        airdrop_config: &AirdropConfiguration,
    ) -> eyre::Result<Option<HashMap<Nullifier, Self::Metadata>>> {
        let Some(sapling_key) = viewing_keys.sapling() else {
            return Ok(None);
        };

        let Some(sapling_config) = airdrop_config.sapling.as_ref() else {
            return Ok(None);
        };

        let hiding_factor = zair_scan::user_nullifiers::SaplingHidingFactor {
            personalization: sapling_config.target_id.as_bytes(),
        };

        let mut notes = HashMap::new();
        for found_note in visitor.sapling_notes() {
            let nullifier = found_note.nullifier(sapling_key);
            let hiding_nullifier = found_note.hiding_nullifier(sapling_key, &hiding_factor)?;

            let cm_merkle_proof = visitor
                .sapling_witness(found_note.note.position)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Missing Sapling witness for position {}",
                        found_note.note.position
                    )
                })?;

            notes.insert(
                nullifier,
                SaplingNoteMetadata {
                    diversifier: found_note.note.diversifier(),
                    hiding_nullifier,
                    pk_d: found_note.note.pk_d(),
                    value: found_note.note.note.value().inner(),
                    rcm: found_note.note.rcm(),
                    note_position: found_note.note.position,
                    scope: found_note.note.scope,
                    block_height: found_note.metadata.height,
                    cm_merkle_proof,
                },
            );
        }
        Ok(Some(notes))
    }
}

/// Orchard pool processor.
pub struct OrchardPool;

impl PoolProcessor for OrchardPool {
    type PrivateInputs = OrchardPrivateInputs;
    type Metadata = OrchardNoteMetadata;

    const POOL: Pool = Pool::Orchard;

    fn expected_root(config: &AirdropConfiguration) -> Option<[u8; 32]> {
        config.orchard.as_ref().map(|pool| pool.nullifier_gap_root)
    }

    fn collect_notes(
        visitor: &AccountNotesVisitor,
        viewing_keys: &ViewingKeys,
        airdrop_config: &AirdropConfiguration,
    ) -> eyre::Result<Option<HashMap<Nullifier, Self::Metadata>>> {
        let Some(orchard_key) = viewing_keys.orchard() else {
            return Ok(None);
        };

        let Some(orchard_config) = airdrop_config.orchard.as_ref() else {
            return Ok(None);
        };

        let hiding_factor = zair_scan::user_nullifiers::OrchardHidingFactor {
            domain: &orchard_config.target_id,
            tag: b"K",
        };

        let mut notes = HashMap::new();
        for found_note in visitor.orchard_notes() {
            let nullifier = found_note.nullifier(orchard_key);
            let hiding_nullifier = found_note.hiding_nullifier(orchard_key, &hiding_factor)?;

            let cm_merkle_proof = visitor
                .orchard_witness(found_note.metadata.position)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Missing Orchard witness for position {}",
                        found_note.metadata.position
                    )
                })?;

            let address = found_note.note.recipient();
            let diversifier = address.diversifier();
            let raw_addr = address.to_raw_address_bytes();
            let pk_d: [u8; 32] = raw_addr[11..43]
                .try_into()
                .map_err(|_| eyre::eyre!("Invalid Orchard raw address bytes"))?;
            let g_d = orchard_g_d_from_diversifier(diversifier.as_array());

            notes.insert(
                nullifier,
                OrchardNoteMetadata {
                    hiding_nullifier,
                    rho: found_note.note.rho().to_bytes(),
                    rseed: *found_note.note.rseed().as_bytes(),
                    g_d,
                    pk_d,
                    value: found_note.note.value().inner(),
                    note_position: found_note.metadata.position,
                    scope: found_note.metadata.scope,
                    block_height: found_note.metadata.height,
                    cm_merkle_proof,
                },
            );
        }
        Ok(Some(notes))
    }
}
