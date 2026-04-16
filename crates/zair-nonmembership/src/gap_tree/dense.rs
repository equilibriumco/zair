use std::io;

use incrementalmerkletree::Level;

use crate::core::{MerklePathError, validate_leaf_count};
use crate::node::NON_MEMBERSHIP_TREE_DEPTH;

const SERIALIZED_LEAF_COUNT_BYTES: usize = 8;
const SERIALIZED_NODE_BYTES: usize = 32;
const TREE_LEVEL_COUNT: usize = 33;

fn level_layout(
    leaf_count: usize,
) -> ([usize; TREE_LEVEL_COUNT], [usize; TREE_LEVEL_COUNT], usize) {
    let mut widths = [0_usize; TREE_LEVEL_COUNT];
    let mut offsets = [0_usize; TREE_LEVEL_COUNT];

    let mut width = leaf_count;
    let mut offset = 0_usize;

    for level in 0..TREE_LEVEL_COUNT {
        widths[level] = width;
        offsets[level] = offset;
        offset = offset.saturating_add(width);
        width = width.div_ceil(2);
    }

    (widths, offsets, offset)
}

#[derive(Debug, Clone)]
pub(super) struct DenseGapTree {
    leaf_count: usize,
    leaf_count_u64: u64,
    level_widths: [usize; TREE_LEVEL_COUNT],
    level_offsets: [usize; TREE_LEVEL_COUNT],
    nodes: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl DenseGapTree {
    pub(super) fn from_leaves<T: Copy>(
        leaves: Vec<T>,
        empty_root: impl Fn(Level) -> T,
        combine: impl Fn(Level, &T, &T) -> T,
        to_bytes: impl Fn(T) -> [u8; 32],
    ) -> Result<Self, MerklePathError> {
        let leaf_count = leaves.len();
        validate_leaf_count(leaf_count)?;
        let leaf_count_u64 = u64::try_from(leaf_count)
            .map_err(|_| MerklePathError::Unexpected("leaf count does not fit into u64"))?;
        let (level_widths, level_offsets, total_nodes) = level_layout(leaf_count);

        let mut nodes = Vec::with_capacity(total_nodes);
        nodes.extend(leaves.iter().copied().map(&to_bytes));

        let mut current = leaves;
        for level in 0..NON_MEMBERSHIP_TREE_DEPTH {
            let mut next = Vec::with_capacity(level_widths[usize::from(level) + 1]);
            let empty = empty_root(Level::from(level));
            for pair_start in (0..current.len()).step_by(2) {
                let left = current[pair_start];
                let right = current.get(pair_start + 1).copied().unwrap_or(empty);
                next.push(combine(Level::from(level), &left, &right));
            }
            nodes.extend(next.iter().copied().map(&to_bytes));
            current = next;
        }

        Self::from_nodes(
            leaf_count,
            leaf_count_u64,
            &level_widths,
            &level_offsets,
            total_nodes,
            nodes,
        )
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, MerklePathError> {
        let (&header, payload) = bytes
            .split_first_chunk::<SERIALIZED_LEAF_COUNT_BYTES>()
            .ok_or(MerklePathError::Unexpected("gap-tree file is too short"))?;

        let leaf_count_u64 = u64::from_le_bytes(header);
        let leaf_count = usize::try_from(leaf_count_u64)
            .map_err(|_| MerklePathError::Unexpected("leaf count does not fit into usize"))?;

        validate_leaf_count(leaf_count)?;
        let (level_widths, level_offsets, total_nodes) = level_layout(leaf_count);

        if payload.len() != total_nodes * SERIALIZED_NODE_BYTES {
            return Err(MerklePathError::Unexpected("gap-tree file length mismatch"));
        }

        let mut nodes = Vec::with_capacity(total_nodes);
        for chunk in payload.chunks_exact(SERIALIZED_NODE_BYTES) {
            let mut node = [0_u8; SERIALIZED_NODE_BYTES];
            node.copy_from_slice(chunk);
            nodes.push(node);
        }

        Self::from_nodes(
            leaf_count,
            leaf_count_u64,
            &level_widths,
            &level_offsets,
            total_nodes,
            nodes,
        )
    }

    fn from_nodes(
        leaf_count: usize,
        leaf_count_u64: u64,
        level_widths: &[usize; TREE_LEVEL_COUNT],
        level_offsets: &[usize; TREE_LEVEL_COUNT],
        total_nodes: usize,
        nodes: Vec<[u8; 32]>,
    ) -> Result<Self, MerklePathError> {
        if nodes.len() != total_nodes {
            return Err(MerklePathError::Unexpected("gap-tree node count mismatch"));
        }
        let root = *nodes.last().ok_or(MerklePathError::Unexpected(
            "gap-tree must contain at least one node",
        ))?;
        Ok(Self {
            leaf_count,
            leaf_count_u64,
            level_widths: *level_widths,
            level_offsets: *level_offsets,
            nodes,
            root,
        })
    }

    #[must_use]
    pub(super) const fn root_bytes(&self) -> [u8; 32] {
        self.root
    }

    pub(super) fn witness_bytes(
        &self,
        leaf_position: u64,
        empty_root_bytes: impl Fn(Level) -> [u8; 32],
    ) -> Result<Vec<[u8; 32]>, MerklePathError> {
        let mut index =
            usize::try_from(leaf_position).map_err(MerklePathError::PositionConversionError)?;
        if index >= self.leaf_count {
            return Err(MerklePathError::NotMarked(leaf_position));
        }

        let mut witness = Vec::with_capacity(usize::from(NON_MEMBERSHIP_TREE_DEPTH));
        for level in 0..NON_MEMBERSHIP_TREE_DEPTH {
            let level_idx = usize::from(level);
            let width = self.level_widths[level_idx];
            let sibling = index ^ 1;
            let sibling_node = if sibling < width {
                self.node_at(level_idx, sibling)
            } else {
                empty_root_bytes(Level::from(level))
            };
            witness.push(sibling_node);
            index /= 2;
        }
        Ok(witness)
    }

    pub(super) fn write_to<W: io::Write + ?Sized>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.leaf_count_u64.to_le_bytes())?;
        for node in &self.nodes {
            writer.write_all(node)?;
        }
        Ok(())
    }

    #[must_use]
    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            SERIALIZED_LEAF_COUNT_BYTES + self.nodes.len() * SERIALIZED_NODE_BYTES,
        );
        self.write_to(&mut bytes)
            .expect("writing to Vec<u8> is infallible");
        bytes
    }

    fn node_at(&self, level: usize, index: usize) -> [u8; 32] {
        self.nodes[self.level_offsets[level] + index]
    }
}
