#![allow(missing_docs)]

use ff::PrimeField as _;
use pasta_curves::pallas;
use zair_core::base::{Nullifier, SanitiseNullifiers};
use zair_nonmembership::{
    NonMembershipNode, NonMembershipTree, OrchardGapTree, OrchardNonMembershipTree, SaplingGapTree,
    map_orchard_user_positions, map_sapling_user_positions,
};

fn sapling_nf(v: u8) -> Nullifier {
    let mut bytes = [0_u8; 32];
    bytes[0] = v;
    Nullifier::from(bytes)
}

fn sapling_nf_u32(v: u32) -> Nullifier {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&v.to_le_bytes());
    Nullifier::from(bytes)
}

fn orchard_nf(v: u64) -> Nullifier {
    Nullifier::from(pallas::Base::from(v).to_repr())
}

#[test]
fn sapling_dense_matches_sparse() {
    let chain = SanitiseNullifiers::new(vec![sapling_nf(5), sapling_nf(10), sapling_nf(20)]);
    let user = SanitiseNullifiers::new(vec![
        sapling_nf(1),
        sapling_nf(7),
        sapling_nf(15),
        sapling_nf(20),
        sapling_nf(21),
    ]);

    let dense_tree = SaplingGapTree::from_nullifiers_with_progress(&chain, |_, _| {})
        .expect("dense sapling tree should build");
    let dense_positions = map_sapling_user_positions(&chain, &user)
        .expect("dense sapling position mapping should build");

    let (sparse_tree, sparse_positions) =
        NonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
            .expect("sparse sapling tree should build");

    assert_eq!(dense_tree.root_bytes(), sparse_tree.root().to_bytes());
    assert_eq!(dense_positions, sparse_positions);

    for position in &dense_positions {
        let dense_witness = dense_tree
            .witness_bytes(position.leaf_position.into())
            .expect("dense sapling witness should build");
        let sparse_witness = sparse_tree
            .witness(position.leaf_position)
            .expect("sparse sapling witness should build");
        let sparse_witness_bytes: Vec<[u8; 32]> = sparse_witness
            .iter()
            .map(NonMembershipNode::to_bytes)
            .collect();
        assert_eq!(dense_witness, sparse_witness_bytes);
    }
}

#[test]
fn orchard_dense_matches_sparse() {
    let chain = SanitiseNullifiers::new(vec![orchard_nf(5), orchard_nf(10), orchard_nf(20)]);
    let user = SanitiseNullifiers::new(vec![
        orchard_nf(1),
        orchard_nf(7),
        orchard_nf(15),
        orchard_nf(20),
        orchard_nf(21),
    ]);

    let dense_tree = OrchardGapTree::from_nullifiers_with_progress(&chain, |_, _| {})
        .expect("dense orchard tree should build");
    let dense_positions = map_orchard_user_positions(&chain, &user)
        .expect("dense orchard position mapping should build");

    let (sparse_tree, sparse_positions) =
        OrchardNonMembershipTree::from_chain_and_user_nullifiers(&chain, &user)
            .expect("sparse orchard tree should build");

    assert_eq!(dense_tree.root_bytes(), sparse_tree.root_bytes());
    assert_eq!(dense_positions, sparse_positions);

    for position in &dense_positions {
        let dense_witness = dense_tree
            .witness_bytes(position.leaf_position.into())
            .expect("dense orchard witness should build");
        let sparse_witness = sparse_tree
            .witness_bytes(position.leaf_position)
            .expect("sparse orchard witness should build");
        assert_eq!(dense_witness, sparse_witness);
    }
}

/// Sized above `PAR_CHUNK_MIN_LEN` (1024) so parallel leaf + first inner
/// levels run; sparse builder acts as the correctness oracle.
const LARGE_FIXTURE_LEN: u32 = 4_000;

#[test]
fn sapling_dense_matches_sparse_large_fixture() {
    let chain = SanitiseNullifiers::new((1..=LARGE_FIXTURE_LEN).map(sapling_nf_u32).collect());
    let dense_tree = SaplingGapTree::from_nullifiers_with_progress(&chain, |_, _| {})
        .expect("dense sapling tree should build");
    let empty_user = SanitiseNullifiers::new(vec![]);
    let (sparse_tree, _) = NonMembershipTree::from_chain_and_user_nullifiers(&chain, &empty_user)
        .expect("sparse sapling tree should build");
    assert_eq!(dense_tree.root_bytes(), sparse_tree.root().to_bytes());
}

#[test]
fn orchard_dense_matches_sparse_large_fixture() {
    let chain = SanitiseNullifiers::new(
        (1_u64..=u64::from(LARGE_FIXTURE_LEN))
            .map(orchard_nf)
            .collect(),
    );
    let dense_tree = OrchardGapTree::from_nullifiers_with_progress(&chain, |_, _| {})
        .expect("dense orchard tree should build");
    let empty_user = SanitiseNullifiers::new(vec![]);
    let (sparse_tree, _) =
        OrchardNonMembershipTree::from_chain_and_user_nullifiers(&chain, &empty_user)
            .expect("sparse orchard tree should build");
    assert_eq!(dense_tree.root_bytes(), sparse_tree.root_bytes());
}
