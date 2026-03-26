//! Space-efficient Merkle tree for non-membership proofs using `BridgeTree`.
//!
//! This module provides a Merkle tree implementation that uses the `bridgetree`
//! crate for space-efficient storage. Only leaves marked for witnessing have
//! their authentication paths retained.

#![allow(clippy::indexing_slicing, reason = "Allow indexing for clarity")]

use std::collections::BTreeSet;

use bridgetree::BridgeTree;
use incrementalmerkletree::{Hashable, Position};
use zair_core::base::{Nullifier, SanitiseNullifiers};

use crate::core::{MerklePathError, TreePosition, should_report_progress};
use crate::node::{NON_MEMBERSHIP_TREE_DEPTH, NonMembershipNode};

#[derive(Debug, PartialEq, Eq)]
/// A gap between two nullifiers.
struct Gap {
    /// The left nullifier of the gap.
    pub left: Nullifier,
    /// The right nullifier of the gap.
    pub right: Nullifier,
}

/// A space-efficient Merkle tree for non-membership proofs.
///
/// This tree uses `BridgeTree` internally, which only stores the data
/// necessary to generate witnesses for marked leaves. This provides
/// O(log n) memory usage instead of O(n).
///
/// # Usage
///
/// 1. Build the tree with [`NonMembershipTree::from_chain_and_user_nullifiers`], which
///    automatically marks leaves where user nullifiers fall
/// 2. Get the root with [`NonMembershipTree::root`]
/// 3. Generate witnesses with [`NonMembershipTree::witness`] using positions from step 1
///
/// The [`NonMembershipTree::from_nullifiers`] method is also available be used. It builds the tree
/// without marking any positions - useful for calculating the root.
#[derive(Debug, Clone)]
pub struct NonMembershipTree {
    /// The underlying `BridgeTree`.
    /// C = () since we don't need checkpoint IDs.
    /// DEPTH = 32 for a tree that can hold up to 2^32 leaves.
    inner: BridgeTree<NonMembershipNode, (), { NON_MEMBERSHIP_TREE_DEPTH }>,
    /// The root hash (cached after construction).
    cached_root: NonMembershipNode,
    /// Number of leaves in the tree.
    leaf_count: usize,
}

impl NonMembershipTree {
    /// Build a new Merkle tree from the given leaves (no positions marked).
    ///
    /// # Arguments
    /// * `leaves` - Iterator of leaf nodes to add to the tree.
    ///
    /// # Returns
    /// A new `NonMembershipTree`.
    ///
    /// # Errors
    /// - `MerklePathError::Unexpected` if the merkle root cannot be computed after construction.
    #[allow(
        dead_code,
        reason = "Kept for focused tree-construction tests; production path uses marked-construction APIs"
    )]
    fn from_leaves<I>(leaves: I) -> Result<Self, MerklePathError>
    where
        I: IntoIterator<Item = NonMembershipNode>,
        I::IntoIter: ExactSizeIterator,
    {
        let leaves_iter = leaves.into_iter();
        let len = leaves_iter.len();

        if len >= 2_usize.pow(u32::from(NON_MEMBERSHIP_TREE_DEPTH)) {
            return Err(MerklePathError::LeavesOverflow(len));
        }
        if len == 0_usize {
            return Err(MerklePathError::Unexpected(
                "0 leaves provided for a non-membership tree. This is not a valid case.",
            ));
        }

        // max_checkpoints = 1 since we only need the final state
        let mut tree: BridgeTree<NonMembershipNode, (), { NON_MEMBERSHIP_TREE_DEPTH }> =
            BridgeTree::new(1);
        let mut leaf_count = 0_usize;
        for leaf in leaves_iter {
            if !tree.append(leaf) {
                return Err(MerklePathError::Unexpected(
                    "Failed to append leaf to the Merkle tree",
                ));
            }
            leaf_count = leaf_count.saturating_add(1);
        }

        // Checkpoint the final state (using () as the checkpoint ID)
        tree.checkpoint(());

        // Cache the root
        let cached_root = tree.root(0).ok_or(MerklePathError::Unexpected(
            "Merkle root should exist at this point",
        ))?;

        Ok(Self {
            inner: tree,
            cached_root,
            leaf_count,
        })
    }

    /// Build a non-membership Merkle tree from nullifiers (no positions marked).
    ///
    /// For N nullifiers, this creates N+1 leaves.
    ///
    /// **Note**: This method does not mark any positions for witnessing.
    /// Use [`Self::from_chain_and_user_nullifiers`] for the production path
    /// that automatically marks positions.
    ///
    /// # Arguments
    /// * `nullifiers` - Sanitised (sorted, deduplicated) nullifiers.
    ///
    /// # Errors
    /// - `MerklePathError::LeavesOverflow` if the number of leaves exceeds `u32::MAX`.
    /// - `MerklePathError::Unexpected` if the merkle root cannot be computed after construction.
    pub fn from_nullifiers(nullifiers: &SanitiseNullifiers) -> Result<Self, MerklePathError> {
        Self::from_nullifiers_with_progress(nullifiers, |_, _| {})
    }

    /// Build a non-membership tree from nullifiers (no positions marked), with progress callback.
    ///
    /// Calls `on_progress(current, total)` after each leaf is appended.
    ///
    /// # Errors
    /// - `MerklePathError::LeavesOverflow` if the number of leaves exceeds `u32::MAX`.
    /// - `MerklePathError::Unexpected` if the merkle root cannot be computed after construction.
    pub fn from_nullifiers_with_progress(
        nullifiers: &SanitiseNullifiers,
        on_progress: impl FnMut(usize, usize),
    ) -> Result<Self, MerklePathError> {
        let empty_user = SanitiseNullifiers::new(vec![]);
        let (tree, _mapping) = Self::from_chain_and_user_nullifiers_with_progress(
            nullifiers,
            &empty_user,
            on_progress,
        )?;
        Ok(tree)
    }

    /// Build a non-membership tree, automatically marking leaves containing user nullifiers.
    ///
    /// This is the main production constructor. It builds the tree from chain nullifiers
    /// and marks exactly those leaves (gaps) where user nullifiers fall.
    ///
    /// # Arguments
    /// * `chain_nullifiers` - Sanitised (sorted, deduplicated) spent nullifiers from the chain.
    /// * `user_nullifiers` - Sanitised (sorted, deduplicated) user nullifiers to prove
    ///   non-membership for.
    ///
    /// # Returns
    /// A tuple of:
    /// - The tree with appropriate leaves marked
    /// - A vector of [`TreePosition`] mapping each user nullifier to its gap bounds and leaf
    ///   position
    ///
    /// # Errors
    /// Returns `MerklePathError::PositionConversionError` if leaf position exceeds `Position`
    /// bounds.
    pub fn from_chain_and_user_nullifiers(
        chain_nullifiers: &SanitiseNullifiers,
        user_nullifiers: &SanitiseNullifiers,
    ) -> Result<(Self, Vec<TreePosition>), MerklePathError> {
        Self::from_chain_and_user_nullifiers_with_progress(
            chain_nullifiers,
            user_nullifiers,
            |_, _| {},
        )
    }

    /// Build a non-membership tree with progress reporting, automatically marking
    /// leaves containing user nullifiers.
    ///
    /// Calls `on_progress(current, total)` after each leaf is appended.
    ///
    /// # Errors
    /// Returns `MerklePathError::PositionConversionError` if leaf position exceeds `Position`
    /// bounds.
    pub fn from_chain_and_user_nullifiers_with_progress(
        chain_nullifiers: &SanitiseNullifiers,
        user_nullifiers: &SanitiseNullifiers,
        mut on_progress: impl FnMut(usize, usize),
    ) -> Result<(Self, Vec<TreePosition>), MerklePathError> {
        // Build tree, marking leaves as we go based on user nullifiers
        let mut tree: BridgeTree<NonMembershipNode, (), { NON_MEMBERSHIP_TREE_DEPTH }> =
            BridgeTree::new(1);
        let mut leaf_count = 0usize;
        let mut user_gap_mapping = Vec::new();

        // Track which user nullifiers we've processed (using index into sorted slice)
        let mut user_idx = 0usize;

        // Iterate through gaps
        let num_gaps = chain_nullifiers.len().saturating_add(1);
        let mut last_progress_pct = 0_usize;
        if num_gaps > 0 {
            on_progress(0, num_gaps);
        }
        for gap_idx in 0..num_gaps {
            let Gap { left, right } = gap_bounds(chain_nullifiers, gap_idx);
            let leaf = NonMembershipNode::leaf_from_nullifiers(&left, &right);
            tree.append(leaf);

            // Check if any user nullifiers fall in this gap: left < user_nf < right
            let mut should_mark = false;
            while user_idx < user_nullifiers.len() {
                let user_nf = &user_nullifiers[user_idx];

                if user_nf <= &left {
                    // User nullifier is at or before left boundary
                    // Either it equals a chain nullifier (invalid) or we've passed it
                    user_idx = user_idx.saturating_add(1);
                    continue;
                }

                if user_nf >= &right {
                    // User nullifier is at or beyond right boundary - check next gap
                    break;
                }

                // User nullifier is strictly within (left, right) - mark this gap
                should_mark = true;
                user_gap_mapping.push(TreePosition::new(user_nf.to_owned(), gap_idx, left, right)?);
                user_idx = user_idx.saturating_add(1);
            }

            if should_mark {
                tree.mark();
            }

            leaf_count = leaf_count.saturating_add(1);
            if should_report_progress(leaf_count, num_gaps, &mut last_progress_pct) {
                on_progress(leaf_count, num_gaps);
            }
        }

        // Checkpoint the final state
        tree.checkpoint(());

        let cached_root = tree.root(0).ok_or(MerklePathError::Unexpected(
            "Merkle root should exist at this point",
        ))?;

        Ok((
            Self {
                inner: tree,
                cached_root,
                leaf_count,
            },
            user_gap_mapping,
        ))
    }

    /// Returns the root of the tree.
    ///
    /// Returns `None` if the tree is empty.
    #[must_use]
    pub const fn root(&self) -> NonMembershipNode {
        self.cached_root
    }

    /// Returns the number of leaves in the tree.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the set of positions marked for witnessing.
    #[must_use]
    pub fn marked_positions(&self) -> BTreeSet<Position> {
        self.inner.marked_positions()
    }

    /// Generate a witness (authentication path) for a marked leaf.
    ///
    /// # Arguments
    /// * `position` - The position of the leaf (must have been marked during construction).
    ///
    /// # Returns
    /// A vector of sibling hashes from leaf to root.
    ///
    /// # Errors
    /// Returns an error if the position is not marked or witness generation fails.
    pub fn witness(&self, position: Position) -> Result<Vec<NonMembershipNode>, MerklePathError> {
        self.inner
            .witness(position, 0)
            .map_err(|e| MerklePathError::WitnessError(format!("{e:?}")))
    }

    /// Verify that a leaf at the given position produces the expected root.
    ///
    /// # Arguments
    /// * `leaf` - The leaf node to verify.
    /// * `position` - The position of the leaf in the tree.
    /// * `path` - The authentication path (siblings from leaf to root).
    /// * `expected_root` - The expected root hash.
    ///
    /// # Returns
    /// `true` if the path is valid and produces the expected root.
    ///
    /// # Errors
    /// Returns an error if `level` conversion fails. Conversion is `usize` to `u8`.
    pub fn verify_path(
        leaf: &NonMembershipNode,
        position: Position,
        path: &[NonMembershipNode],
        expected_root: &NonMembershipNode,
    ) -> Result<bool, MerklePathError> {
        let mut current = *leaf;
        let mut pos: u64 = position.into();

        for (level, sibling) in path.iter().enumerate() {
            let (left, right) = if pos % 2 == 0 {
                (&current, sibling)
            } else {
                (sibling, &current)
            };

            current = NonMembershipNode::combine(
                incrementalmerkletree::Level::from(u8::try_from(level)?),
                left,
                right,
            );
            pos /= 2;
        }

        Ok(current == *expected_root)
    }
}

/// Returns (`left_bound`, `right_bound`) for the gap at `gap_idx`.
///
/// For N nullifiers, there are N+1 gaps:
/// - Gap 0: `(MIN, nullifiers[0])`
/// - Gap i: `(nullifiers[i-1], nullifiers[i])`
/// - Gap N: `(nullifiers[N-1], MAX)`
#[must_use]
fn gap_bounds(nullifiers: &[Nullifier], gap_idx: usize) -> Gap {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "Its unlikely that `i` - 1 will overflow here, because when `i` is used, is a positive number."
    )]

    let len = nullifiers.len();

    // Empty slice: single gap (Nullifier::MIN, Nullifier::MAX)
    if len == 0 {
        return Gap {
            left: Nullifier::MIN,
            right: Nullifier::MAX,
        };
    }

    match gap_idx {
        0 => Gap {
            left: Nullifier::MIN,
            right: nullifiers[0],
        },
        i if i == len => Gap {
            left: nullifiers[i - 1],
            right: Nullifier::MAX,
        },
        i if i > len => {
            // Safety: Gap is used only internally in this file.
            // Before its called we ensure gap_idx is in the expected range.
            panic!("gap_idx {gap_idx} out of bounds for {len} nullifiers")
        }
        i => Gap {
            left: nullifiers[i - 1],
            right: nullifiers[i],
        },
    }
}

/// Iterator that produces leaf nodes from a slice of nullifiers.
///
/// Generates N+1 leaves for N nullifiers gaps:
/// - First gap: `(MIN, nullifiers[0])`
/// - Last gap: `(nullifiers[n-1], MAX)`
/// - Gaps in between First and Last: `(nullifiers[i], nullifiers[i+1])` for `i` in 0..`n`-i
#[allow(
    dead_code,
    reason = "Used by test-only leaf-construction path retained for unit tests"
)]
struct NullifierLeafIterator<'a> {
    nullifiers: &'a [Nullifier],
    index: usize,
    total: usize,
}

impl<'a> NullifierLeafIterator<'a> {
    #[allow(
        dead_code,
        reason = "Used by test-only leaf-construction path retained for unit tests"
    )]
    const fn new(nullifiers: &'a [Nullifier]) -> Self {
        Self {
            nullifiers,
            index: 0,
            total: nullifiers.len().saturating_add(1),
        }
    }
}

impl Iterator for NullifierLeafIterator<'_> {
    type Item = NonMembershipNode;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }

        // If no nullifier is provided produce only a single gap from MIN to MAX
        let Gap { left, right } = if self.nullifiers.is_empty() {
            Gap {
                left: Nullifier::MIN,
                right: Nullifier::MAX,
            }
        } else {
            gap_bounds(self.nullifiers, self.index)
        };

        let leaf = NonMembershipNode::leaf_from_nullifiers(&left, &right);

        self.index = self.index.saturating_add(1);
        Some(leaf)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for NullifierLeafIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! nf {
        ($v:expr) => {{
            let mut arr = [0_u8; 32];
            arr[31] = $v;
            arr.into()
        }};
    }

    macro_rules! nfs {
        ($($v:expr),* $(,)?) => {{
            let mut v = vec![$( nf!($v) ),*];
            v.sort();
            v
        }};
    }

    const fn make_leaf(value: u8) -> NonMembershipNode {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        NonMembershipNode::new(bytes)
    }

    mod from_leaves {
        use super::*;

        #[test]
        fn no_leaves() {
            let tree = NonMembershipTree::from_leaves(std::iter::empty());
            assert!(matches!(tree, Err(MerklePathError::Unexpected(_))));
        }

        #[test]
        fn multiple_cases() {
            for i in 1..10 {
                let leaves = (0..i).map(make_leaf).collect::<Vec<_>>();
                let tree = NonMembershipTree::from_leaves(leaves).expect("Tree creation failed");
                assert_eq!(tree.leaf_count(), usize::from(i));
            }
        }

        #[test]
        fn leaves_overflow() {
            let iterator = NullifierLeafIterator {
                nullifiers: &[],
                index: 0,
                total: usize::MAX,
            };
            let tree = NonMembershipTree::from_leaves(iterator);
            assert!(matches!(tree, Err(MerklePathError::LeavesOverflow(_))));
        }
    }

    mod from_nullifiers {
        use hex_literal::hex;

        use super::*;

        #[test]
        fn empty_nullifiers() {
            let nullifiers = SanitiseNullifiers::new(vec![]);
            let tree =
                NonMembershipTree::from_nullifiers(&nullifiers).expect("Tree creation failed");

            // 0 nullifiers -> 1 gap (MIN, MAX)
            assert_eq!(tree.leaf_count(), 1);
            assert_eq!(
                tree.root().to_bytes(),
                hex!("c1fe1db7b01153fa3e40fd0053f3f7f69385c2de7fff5c4d705407fb32acb052")
            );
        }

        #[test]
        fn multiple_cases() {
            for i in 1..10 {
                let nullifiers = SanitiseNullifiers::new((1..=i).map(|i| nf!(i)).collect());
                let tree =
                    NonMembershipTree::from_nullifiers(&nullifiers).expect("Tree creation failed");

                // N nullifiers -> N+1 leaves
                assert_eq!(tree.leaf_count(), usize::from(i).saturating_add(1));
            }
        }
    }

    mod from_chain_and_user_nullifiers {
        use super::*;

        #[test]
        fn user_in_middle_gap() {
            // Chain: [10, 20, 30] -> gaps: (MIN,10), (10,20), (20,30), (30,MAX)
            // User: [15] falls in gap index 1: (10, 20)
            let chain = SanitiseNullifiers::new(nfs![10, 20, 30]);
            let user = SanitiseNullifiers::new(nfs![15]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            assert_eq!(tree.leaf_count(), 4);
            assert_eq!(mapping.len(), 1);
            assert_eq!(
                mapping[0],
                TreePosition::new(nf!(15), 1, nf!(10), nf!(20)).expect("Position creation failed")
            ); // gap index 1

            // Verify we can get a witness for the marked position
            let witness = tree
                .witness(mapping[0].leaf_position)
                .expect("Witness generation failed");
            let root = tree.root();

            // Reconstruct the leaf and verify
            let leaf = NonMembershipNode::leaf_from_nullifiers(
                &mapping[0].left_bound,
                &mapping[0].right_bound,
            );
            assert_eq!(
                NonMembershipTree::verify_path(&leaf, mapping[0].leaf_position, &witness, &root),
                Ok(true)
            );
        }

        #[test]
        fn user_in_first_gap() {
            // Chain: [50, 100] -> gaps: (MIN,50), (50,100), (100,MAX)
            // User: [25] falls in gap index 0: (MIN, 50)
            let chain = SanitiseNullifiers::new(nfs![50, 100]);
            let user = SanitiseNullifiers::new(nfs![25]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            assert_eq!(tree.leaf_count(), 3);
            assert_eq!(mapping.len(), 1);
            assert_eq!(
                mapping[0],
                TreePosition::new(nf!(25), 0, Nullifier::MIN, nf!(50))
                    .expect("Position creation failed")
            ); // gap index 0

            // Verify witness works
            let witness = tree
                .witness(mapping[0].leaf_position)
                .expect("Witness generation failed");
            let root = tree.root();
            let leaf = NonMembershipNode::leaf_from_nullifiers(
                &mapping[0].left_bound,
                &mapping[0].right_bound,
            );
            assert_eq!(
                NonMembershipTree::verify_path(&leaf, mapping[0].leaf_position, &witness, &root),
                Ok(true)
            );
        }

        #[test]
        fn user_in_last_gap() {
            // Chain: [10, 20] -> gaps: (MIN,10), (10,20), (20,MAX)
            // User: [200] falls in gap index 2: (20, MAX)
            let chain = SanitiseNullifiers::new(nfs![10, 20]);
            let user = SanitiseNullifiers::new(nfs![200]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            assert_eq!(tree.leaf_count(), 3);
            assert_eq!(mapping.len(), 1);
            assert_eq!(
                mapping[0],
                TreePosition::new(nf!(200), 2, nf!(20), Nullifier::MAX)
                    .expect("Position creation failed")
            ); // gap index 2

            // Verify witness works
            let witness = tree
                .witness(mapping[0].leaf_position)
                .expect("Witness generation failed");
            let root = tree.root();
            let leaf = NonMembershipNode::leaf_from_nullifiers(
                &mapping[0].left_bound,
                &mapping[0].right_bound,
            );
            assert_eq!(
                NonMembershipTree::verify_path(&leaf, mapping[0].leaf_position, &witness, &root),
                Ok(true)
            );
        }

        #[test]
        fn multiple_users_same_gap() {
            // Chain: [10, 100] -> gaps: (MIN,10), (10,100), (100,MAX)
            // Users: [20, 50, 80] all fall in gap index 1: (10, 100)
            let chain = SanitiseNullifiers::new(nfs![10, 100]);
            let user = SanitiseNullifiers::new(nfs![20, 50, 80]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            assert_eq!(tree.leaf_count(), 3);
            assert_eq!(mapping.len(), 3);

            // All three nullifiers map to the same gap
            assert_eq!(
                mapping[0],
                TreePosition::new(nf!(20), 1, nf!(10), nf!(100)).expect("Position creation failed")
            );
            assert_eq!(
                mapping[1],
                TreePosition::new(nf!(50), 1, nf!(10), nf!(100)).expect("Position creation failed")
            );
            assert_eq!(
                mapping[2],
                TreePosition::new(nf!(80), 1, nf!(10), nf!(100)).expect("Position creation failed")
            );

            // Only one position is marked (gap 1)
            let marked = tree.marked_positions();
            assert_eq!(marked.len(), 1);
            assert!(marked.contains(&Position::from(1u64)));
        }

        #[test]
        fn multiple_users_different_gaps() {
            // Chain: [10, 20, 30] -> gaps: (MIN,10), (10,20), (20,30), (30,MAX)
            // Users: [5, 15, 25, 200] in gaps 0, 1, 2, 3 respectively
            let chain = SanitiseNullifiers::new(nfs![10, 20, 30]);
            let user = SanitiseNullifiers::new(nfs![5, 15, 25, 200]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            assert_eq!(tree.leaf_count(), 4);
            assert_eq!(mapping.len(), 4);
            assert_eq!(
                mapping[0],
                TreePosition::new(nf!(5), 0, Nullifier::MIN, nf!(10))
                    .expect("Position creation failed")
            );
            assert_eq!(
                mapping[1],
                TreePosition::new(nf!(15), 1, nf!(10), nf!(20)).expect("Position creation failed")
            );
            assert_eq!(
                mapping[2],
                TreePosition::new(nf!(25), 2, nf!(20), nf!(30)).expect("Position creation failed")
            );
            assert_eq!(
                mapping[3],
                TreePosition::new(nf!(200), 3, nf!(30), Nullifier::MAX)
                    .expect("Position creation failed")
            );

            // All positions are marked
            let marked = tree.marked_positions();
            assert_eq!(marked.len(), 4);
        }

        #[test]
        fn user_equals_chain_nullifier_skipped() {
            // Chain: [10, 20, 30]
            // User: [20] equals a chain nullifier - should be skipped (not in any gap)
            let chain = SanitiseNullifiers::new(nfs![10, 20, 30]);
            let user = SanitiseNullifiers::new(nfs![20]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            assert_eq!(tree.leaf_count(), 4);
            // User nullifier equals chain nullifier, so it's not in any gap
            assert!(mapping.is_empty());
            assert!(tree.marked_positions().is_empty());
        }

        #[test]
        fn empty_chain_nullifiers() {
            let chain = SanitiseNullifiers::new(vec![]);
            let user = SanitiseNullifiers::new(nfs![50_u8]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            // 0 chain nullifiers -> 1 gap (MIN, MAX) -> 1 leaf
            assert_eq!(tree.leaf_count(), 1);
            // User nullifier 50 falls in the (MIN, MAX) gap
            assert_eq!(mapping.len(), 1);
            assert_eq!(mapping[0].nullifier, nf!(50));
            assert_eq!(mapping[0].left_bound, Nullifier::MIN);
            assert_eq!(mapping[0].right_bound, Nullifier::MAX);
        }

        #[test]
        fn empty_user_nullifiers() {
            let chain = SanitiseNullifiers::new(nfs![10, 20]);
            let user = SanitiseNullifiers::new(vec![]);

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            // Tree is built but no positions marked
            assert_eq!(tree.leaf_count(), 3);
            assert!(mapping.is_empty());
            assert!(tree.marked_positions().is_empty());
        }
    }

    mod verify_path {
        use super::*;

        #[test]
        fn wrong_leaf_fails() {
            let chain = SanitiseNullifiers::new(nfs![10, 20]);
            let user = SanitiseNullifiers::new(nfs![15]);

            let (tree, _) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            let root = tree.root();
            let witness = tree
                .witness(Position::from(1u64))
                .expect("Witness generation failed");

            // Using wrong leaf should fail verification
            let wrong_leaf = NonMembershipNode::leaf_from_nullifiers(&nf!(99), &nf!(100));
            assert_eq!(
                NonMembershipTree::verify_path(&wrong_leaf, Position::from(1u64), &witness, &root),
                Ok(false)
            );
        }

        #[test]
        fn wrong_position_fails() {
            let chain = SanitiseNullifiers::new(nfs![10, 20, 30]);
            let user = SanitiseNullifiers::new(nfs![5, 15]); // gaps 0 and 1

            let (tree, mapping) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            let root = tree.root();
            let witness = tree
                .witness(mapping[0].leaf_position)
                .expect("Witness generation failed");

            // Correct leaf for position 0
            let leaf = NonMembershipNode::leaf_from_nullifiers(
                &mapping[0].left_bound,
                &mapping[0].right_bound,
            );

            // Using correct leaf but wrong position should fail
            assert_eq!(
                NonMembershipTree::verify_path(
                    &leaf,
                    Position::from(1u64), // Wrong position
                    &witness,
                    &root
                ),
                Ok(false)
            );
        }

        #[test]
        fn unmarked_position_fails() {
            let chain = SanitiseNullifiers::new(nfs![10, 20, 30]);
            let user = SanitiseNullifiers::new(nfs![15]); // Only gap 1 is marked

            let (tree, _) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
                .expect("Tree creation failed");

            // Position 1 passes (marked)
            assert!(tree.witness(Position::from(1u64)).is_ok());

            // Position 0 fails (not marked)
            assert!(tree.witness(Position::from(0u64)).is_err());
        }
    }
}
