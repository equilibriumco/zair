//! Gap-tree serialization and witness helpers for Sapling and Orchard pools.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Gap-tree layout uses fixed-depth index math; bounds are validated by construction"
)]
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "Public API is crate-internal plumbing for cache persistence; verbose API docs add noise"
)]

mod dense;
mod orchard;
mod sapling;

pub use orchard::OrchardGapTree;
pub use sapling::SaplingGapTree;
use zair_core::base::SanitiseNullifiers;

use crate::{MerklePathError, TreePosition};

/// Map Sapling user nullifiers to gap positions in the canonical chain nullifier set.
///
/// # Errors
/// Returns an error if any mapped leaf position cannot be represented.
pub fn map_sapling_user_positions(
    chain_nullifiers: &SanitiseNullifiers,
    user_nullifiers: &SanitiseNullifiers,
) -> Result<Vec<TreePosition>, MerklePathError> {
    crate::pool::sapling::map_sapling_user_positions(chain_nullifiers, user_nullifiers)
}

/// Map Orchard user nullifiers to gap positions in the canonical chain nullifier set.
///
/// # Errors
/// Returns an error if Orchard nullifiers are non-canonical or a position conversion fails.
pub fn map_orchard_user_positions(
    chain_nullifiers: &SanitiseNullifiers,
    user_nullifiers: &SanitiseNullifiers,
) -> Result<Vec<TreePosition>, MerklePathError> {
    crate::pool::orchard::map_orchard_user_positions(chain_nullifiers, user_nullifiers)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField as _;
    use pasta_curves::pallas;
    use zair_core::base::{Nullifier, SanitiseNullifiers};

    use super::*;
    use crate::MerklePathError;

    fn assert_roundtrip<T>(
        tree: &T,
        to_bytes: impl Fn(&T) -> Vec<u8>,
        from_bytes: impl Fn(&[u8]) -> Result<T, MerklePathError>,
        root_bytes: impl Fn(&T) -> [u8; 32],
        witness_bytes: impl Fn(&T, u64) -> Result<Vec<[u8; 32]>, MerklePathError>,
    ) {
        let encoded = to_bytes(tree);
        let decoded = from_bytes(&encoded).expect("tree should decode");

        assert_eq!(root_bytes(&decoded), root_bytes(tree));
        assert_eq!(
            witness_bytes(&decoded, 1).expect("witness should exist for middle gap"),
            witness_bytes(tree, 1).expect("witness should exist for middle gap")
        );
    }

    #[test]
    fn write_to_matches_to_bytes() {
        let sapling_nullifiers = SanitiseNullifiers::new(vec![
            Nullifier::from([1_u8; 32]),
            Nullifier::from([3_u8; 32]),
        ]);
        let sapling_tree = SaplingGapTree::from_nullifiers(&sapling_nullifiers)
            .expect("sapling tree should build");
        let mut streamed = Vec::new();
        sapling_tree
            .write_to(&mut streamed)
            .expect("sapling write_to should succeed");
        assert_eq!(streamed, sapling_tree.to_bytes());

        let orchard_nullifiers = SanitiseNullifiers::new(vec![
            Nullifier::from(pallas::Base::from(1_u64).to_repr()),
            Nullifier::from(pallas::Base::from(5_u64).to_repr()),
        ]);
        let orchard_tree =
            OrchardGapTree::from_nullifiers_with_progress(&orchard_nullifiers, |_, _| {})
                .expect("orchard tree should build");
        let mut streamed = Vec::new();
        orchard_tree
            .write_to(&mut streamed)
            .expect("orchard write_to should succeed");
        assert_eq!(streamed, orchard_tree.to_bytes());
    }

    #[test]
    fn progress_ticks_are_monotonic_and_capped() {
        // 2000 leaves crosses PAR_CHUNK_MIN_LEN so the parallel path fires.
        let chain = SanitiseNullifiers::new(
            (1_u64..=2_000)
                .map(|v| Nullifier::from(pallas::Base::from(v).to_repr()))
                .collect(),
        );
        let mut ticks: Vec<usize> = Vec::new();
        OrchardGapTree::from_nullifiers_with_progress(&chain, |current, total| {
            assert!(current <= total, "current {current} exceeds total {total}");
            ticks.push(current.saturating_mul(100).saturating_div(total));
        })
        .expect("orchard tree should build");
        assert!(ticks.is_sorted(), "ticks not monotonic: {ticks:?}");
        assert!(ticks.len() <= 11, "too many ticks: {ticks:?}");
    }

    #[test]
    fn gap_tree_roundtrip_preserves_root_and_witnesses() {
        let sapling_nullifiers = SanitiseNullifiers::new(vec![
            Nullifier::from([1_u8; 32]),
            Nullifier::from([3_u8; 32]),
        ]);
        let sapling_tree =
            SaplingGapTree::from_nullifiers_with_progress(&sapling_nullifiers, |_, _| {})
                .expect("sapling tree should build");
        assert_roundtrip(
            &sapling_tree,
            SaplingGapTree::to_bytes,
            SaplingGapTree::from_bytes,
            SaplingGapTree::root_bytes,
            SaplingGapTree::witness_bytes,
        );

        let orchard_nullifiers = SanitiseNullifiers::new(vec![
            Nullifier::from(pallas::Base::from(1_u64).to_repr()),
            Nullifier::from(pallas::Base::from(5_u64).to_repr()),
        ]);
        let orchard_tree =
            OrchardGapTree::from_nullifiers_with_progress(&orchard_nullifiers, |_, _| {})
                .expect("orchard tree should build");
        assert_roundtrip(
            &orchard_tree,
            OrchardGapTree::to_bytes,
            OrchardGapTree::from_bytes,
            OrchardGapTree::root_bytes,
            OrchardGapTree::witness_bytes,
        );
    }
}
