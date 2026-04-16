use incrementalmerkletree::Hashable as _;
use zair_core::base::SanitiseNullifiers;

use super::dense::{DenseGapTree, build_leaves_batched};
use crate::core::MerklePathError;
use crate::node::NonMembershipNode;
use crate::pool::sapling::sapling_gap_bounds;

#[derive(Debug, Clone)]
pub struct SaplingGapTree(DenseGapTree);

impl SaplingGapTree {
    pub fn from_nullifiers(nullifiers: &SanitiseNullifiers) -> Result<Self, MerklePathError> {
        Self::from_nullifiers_with_progress(nullifiers, |_, _| {})
    }

    pub fn from_nullifiers_with_progress(
        nullifiers: &SanitiseNullifiers,
        on_progress: impl FnMut(usize, usize),
    ) -> Result<Self, MerklePathError> {
        let leaf_count = nullifiers.len().saturating_add(1);
        let leaves = build_leaves_batched(leaf_count, on_progress, |gap_idx| {
            let (left, right) = sapling_gap_bounds(nullifiers, gap_idx)?;
            Ok::<_, MerklePathError>(NonMembershipNode::leaf_from_nullifiers(&left, &right))
        })?;
        DenseGapTree::from_leaves(
            leaves,
            NonMembershipNode::empty_root,
            NonMembershipNode::combine,
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
            NonMembershipNode::empty_root(level).to_bytes()
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
