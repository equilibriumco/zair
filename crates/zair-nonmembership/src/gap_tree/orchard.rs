use incrementalmerkletree::Hashable as _;
use orchard::tree::MerkleHashOrchard;
use zair_core::base::SanitiseNullifiers;

use super::dense::DenseGapTree;
use crate::core::{MerklePathError, should_report_progress};
use crate::pool::orchard::{
    ORCHARD_LEAF_HASH_LEVEL, canonicalize_orchard_chain_nullifiers, orchard_gap_bounds,
    orchard_max_nullifier, orchard_node_from_bytes,
};

#[derive(Debug, Clone)]
pub struct OrchardGapTree(DenseGapTree);

impl OrchardGapTree {
    pub fn from_nullifiers_with_progress(
        nullifiers: &SanitiseNullifiers,
        mut on_progress: impl FnMut(usize, usize),
    ) -> Result<Self, MerklePathError> {
        let chain = canonicalize_orchard_chain_nullifiers("chain", nullifiers)?;
        let min_node = orchard_node_from_bytes(*zair_core::base::Nullifier::MIN.as_ref()).ok_or(
            MerklePathError::Unexpected("invalid Orchard min nullifier encoding"),
        )?;
        let max_node = orchard_node_from_bytes(*orchard_max_nullifier().as_ref()).ok_or(
            MerklePathError::Unexpected("invalid Orchard max nullifier encoding"),
        )?;

        let leaf_count = chain.len().saturating_add(1);
        let mut leaves = Vec::with_capacity(leaf_count);
        let mut last_pct = 0_usize;
        on_progress(0, leaf_count);
        for gap_idx in 0..leaf_count {
            let gap = orchard_gap_bounds(&chain, gap_idx, min_node, max_node)?;
            leaves.push(MerkleHashOrchard::combine(
                ORCHARD_LEAF_HASH_LEVEL.into(),
                &gap.left_node,
                &gap.right_node,
            ));
            if should_report_progress(gap_idx.saturating_add(1), leaf_count, &mut last_pct) {
                on_progress(gap_idx.saturating_add(1), leaf_count);
            }
        }
        DenseGapTree::from_leaves(
            leaves,
            MerkleHashOrchard::empty_root,
            MerkleHashOrchard::combine,
            |node| node.to_bytes(),
        )
        .map(Self)
    }

    #[must_use]
    pub const fn root_bytes(&self) -> [u8; 32] {
        self.0.root_bytes()
    }

    pub fn witness_bytes(&self, leaf_position: u64) -> Result<Vec<[u8; 32]>, MerklePathError> {
        self.0.witness_bytes(leaf_position, |level| {
            MerkleHashOrchard::empty_root(level).to_bytes()
        })
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn write_to<W: std::io::Write + ?Sized>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.write_to(writer)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerklePathError> {
        DenseGapTree::from_bytes(bytes).map(Self)
    }
}
