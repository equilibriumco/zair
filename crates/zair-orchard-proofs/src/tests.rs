use group::{Group as _, GroupEncoding as _};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::{pallas, vesta};
use rand::RngCore as _;

use crate::instance::to_instance;
use crate::types::{ClaimProofOutput, ValueCommitmentScheme};

#[test]
fn cv_sha256_test_vector() {
    let mut rcv_sha256 = [0u8; 32];
    for (i, b) in rcv_sha256.iter_mut().enumerate() {
        *b = i as u8;
    }

    let got = zair_core::base::cv_sha256(1, rcv_sha256);
    let expected: [u8; 32] = [
        0x6b, 0x9b, 0x2a, 0x58, 0x66, 0x11, 0x31, 0x76, 0xdc, 0x8c, 0x7f, 0x50, 0x03, 0xd7, 0xeb,
        0xdf, 0xd3, 0xf9, 0xf3, 0x3c, 0x92, 0x16, 0x04, 0x57, 0xf8, 0x3f, 0xcd, 0x82, 0xb8, 0x48,
        0x6e, 0x71,
    ];
    assert_eq!(got, expected);

    // Orchard SHA256 public input encoding uses 8 big-endian u32 digest words.
    let note_commitment_root = [0u8; 32];
    let nullifier_gap_root = [0u8; 32];
    let airdrop_nf = [0u8; 32];
    let rk_bytes = pallas::Point::generator().to_bytes();

    let [inst] = match to_instance(
        note_commitment_root,
        None,
        Some(expected),
        None,
        airdrop_nf,
        rk_bytes,
        nullifier_gap_root,
        ValueCommitmentScheme::Sha256,
    ) {
        Ok(v) => v,
        Err(e) => panic!("sha instance: {e}"),
    };

    for i in 0..8usize {
        let j = i * 4;
        let word = u32::from_be_bytes([
            expected[j],
            expected[j + 1],
            expected[j + 2],
            expected[j + 3],
        ]) as u64;
        assert_eq!(inst[2 + i], vesta::Scalar::from(word));
    }
}

#[test]
fn to_instance_lengths_match_scheme() {
    let note_commitment_root = [0u8; 32];
    let nullifier_gap_root = [0u8; 32];
    let airdrop_nf = [0u8; 32];

    let rk_bytes = pallas::Point::generator().to_bytes();
    let cv_bytes = pallas::Point::generator().double().to_bytes();

    let mut rcv_sha256 = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rcv_sha256);
    let digest = zair_core::base::cv_sha256(1, rcv_sha256);

    let [cv] = match to_instance(
        note_commitment_root,
        Some(cv_bytes),
        None,
        None,
        airdrop_nf,
        rk_bytes,
        nullifier_gap_root,
        ValueCommitmentScheme::Native,
    ) {
        Ok(v) => v,
        Err(e) => panic!("cv instance: {e}"),
    };
    assert_eq!(cv.len(), 7);

    let [sha] = match to_instance(
        note_commitment_root,
        None,
        Some(digest),
        None,
        airdrop_nf,
        rk_bytes,
        nullifier_gap_root,
        ValueCommitmentScheme::Sha256,
    ) {
        Ok(v) => v,
        Err(e) => panic!("sha instance: {e}"),
    };
    assert_eq!(sha.len(), 13);
}

#[test]
fn cv_sha256_depends_on_value() {
    let rcv_sha256 = [7_u8; 32];
    let d1 = zair_core::base::cv_sha256(1, rcv_sha256);
    let d2 = zair_core::base::cv_sha256(2, rcv_sha256);
    assert_ne!(d1, d2);
}

fn dummy_output() -> ClaimProofOutput {
    ClaimProofOutput {
        zkproof: Vec::new(),
        rk: [0_u8; 32],
        cv: Some([0_u8; 32]),
        cv_sha256: None,
        value: None,
        airdrop_nullifier: [0_u8; 32],
    }
}

fn dummy_params() -> Params<vesta::Affine> {
    // The invalid target-id tests return before Halo2 verification, so this can be small.
    Params::new(1)
}

#[test]
fn verify_rejects_invalid_target_id_length() {
    let params = dummy_params();
    let err = crate::verifier::verify_claim_proof_output(
        &params,
        &dummy_output(),
        [0_u8; 32],
        [0_u8; 32],
        ValueCommitmentScheme::Native,
        &[0_u8; 33],
    )
    .unwrap_err();
    assert!(matches!(err, crate::ClaimProofError::InvalidTargetIdLength));
}

#[test]
fn verify_rejects_non_utf8_target_id() {
    let params = dummy_params();
    let err = crate::verifier::verify_claim_proof_output(
        &params,
        &dummy_output(),
        [0_u8; 32],
        [0_u8; 32],
        ValueCommitmentScheme::Native,
        &[0xff],
    )
    .unwrap_err();
    assert!(matches!(err, crate::ClaimProofError::InvalidTargetIdUtf8));
}
