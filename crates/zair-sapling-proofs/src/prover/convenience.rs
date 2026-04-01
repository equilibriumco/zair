//! Convenience API for claim proof generation.
//!
//! This module provides higher-level functions for generating claim proofs
//! from raw byte inputs. This is useful when reading from JSON files or
//! network protocols.
//!
//! Note: This API does not exist in sapling-crypto. In Sapling, proofs are
//! created through the Builder pattern or directly via the trait methods.

use ff::PrimeField;
use group::Curve;
use incrementalmerkletree::Position;
use rand::rngs::OsRng;
use sapling::value::{NoteValue, ValueCommitTrapdoor};
use sapling::{Diversifier, Note, PaymentAddress, ProofGenerationKey, Rseed};

use crate::error::ClaimProofError;
use crate::prover::proving::{
    ClaimParameters, MerklePath, create_proof, encode_proof, prepare_circuit,
};
use crate::types::{ClaimProofInputs, ClaimProofOutput, ValueCommitmentScheme};

/// Compute the Zcash nullifier from note inputs (for debugging/verification).
///
/// This computes the same nullifier that the circuit computes internally.
#[must_use]
pub fn compute_nullifier(
    proof_generation_key: &ProofGenerationKey,
    note: &Note,
    position: u64,
) -> [u8; 32] {
    let viewing_key = proof_generation_key.to_viewing_key();

    // Use sapling's built-in nullifier computation
    note.nf(&viewing_key.nk, position).0
}

/// Check if a 256-bit value is strictly less than another using lexicographic ordering.
///
/// This compares bytes from index 0 (most significant) to index 31 (least significant),
/// matching the ordering used by the non-membership tree.
#[must_use]
pub fn bytes_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        if a_byte < b_byte {
            return true;
        }
        if a_byte > b_byte {
            return false;
        }
    }
    // Equal
    false
}

/// Generate a claim proof from raw byte inputs.
///
/// This is a convenience function that combines circuit preparation, proof creation,
/// and output computation into a single call.
///
/// # Arguments
/// * `params` - The proving parameters
/// * `inputs` - The claim proof inputs (raw bytes)
/// * `proof_generation_key` - The Sapling proof generation key
///
/// # Errors
/// Returns an error if proof generation fails.
#[allow(
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "End-to-end witness preparation and proving"
)]
pub fn generate_claim_proof(
    params: &ClaimParameters,
    inputs: &ClaimProofInputs,
    proof_generation_key: &ProofGenerationKey,
) -> Result<ClaimProofOutput, ClaimProofError> {
    let mut rng = OsRng;

    // Parse inputs
    let value = NoteValue::from_raw(inputs.value);
    let rcm = jubjub::Fr::from_bytes(&inputs.rcm)
        .into_option()
        .ok_or(ClaimProofError::InvalidRcm)?;

    // Build the Merkle path (same as sapling's pczt/parse.rs)
    let path_elems = inputs
        .merkle_path
        .iter()
        .enumerate()
        .map(|(i, hash)| {
            sapling::Node::from_bytes(*hash)
                .into_option()
                .ok_or_else(|| {
                    ClaimProofError::InvalidMerklePath(format!("Invalid node at index {i}"))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_path = MerklePath::from_parts(path_elems, Position::from(inputs.position))
        .map_err(|()| ClaimProofError::InvalidMerklePath("Invalid path length".to_string()))?;

    // Reconstruct the payment address
    let mut address_bytes = [0u8; 43];
    address_bytes[..11].copy_from_slice(&inputs.diversifier);
    address_bytes[11..].copy_from_slice(&inputs.pk_d);
    let recipient =
        PaymentAddress::from_bytes(&address_bytes).ok_or(ClaimProofError::InvalidPaymentAddress)?;

    // Build the note
    let rseed = Rseed::BeforeZip212(rcm);
    let note = Note::from_parts(recipient, value, rseed);

    // Compute the Zcash nullifier for debugging
    let nf = compute_nullifier(proof_generation_key, &note, inputs.position);

    let left_lt_nf = bytes_less_than(&inputs.nm_left_nf, &nf);
    let nf_lt_right = bytes_less_than(&nf, &inputs.nm_right_nf);

    if !left_lt_nf || !nf_lt_right {
        // Format as hex for error message
        fn to_hex(bytes: &[u8; 32]) -> String {
            use std::fmt::Write;
            bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
        }
        return Err(ClaimProofError::ProofCreation(format!(
            "Nullifier not within bounds: left_nf={}, nf={}, right_nf={}, left<nf={left_lt_nf}, nf<right={nf_lt_right}",
            to_hex(&inputs.nm_left_nf),
            to_hex(&nf),
            to_hex(&inputs.nm_right_nf),
        )));
    }

    let note_commitment_root = bls12_381::Scalar::from_bytes(&inputs.note_commitment_root)
        .into_option()
        .ok_or_else(|| {
            ClaimProofError::ProofCreation(
                "Invalid note-commitment root: not a valid scalar".to_string(),
            )
        })?;

    let nullifier_gap_root = bls12_381::Scalar::from_bytes(&inputs.nullifier_gap_root)
        .into_option()
        .ok_or_else(|| {
            ClaimProofError::ProofCreation(
                "Invalid nullifier gap root: not a valid scalar".to_string(),
            )
        })?;

    let alpha = jubjub::Fr::from_bytes(&inputs.alpha)
        .into_option()
        .ok_or(ClaimProofError::InvalidAlpha)?;

    let rcv = ValueCommitTrapdoor::from_bytes(inputs.rcv)
        .into_option()
        .ok_or(ClaimProofError::InvalidRcv)?;

    let rcv_sha256 = match inputs.value_commitment_scheme {
        ValueCommitmentScheme::Native | ValueCommitmentScheme::Plain => {
            if inputs.rcv_sha256.is_some() {
                return Err(ClaimProofError::ProofCreation(
                    "Unexpected rcv_sha256 for native/plain scheme".to_string(),
                ));
            }
            None
        }
        ValueCommitmentScheme::Sha256 => inputs
            .rcv_sha256
            .ok_or_else(|| ClaimProofError::ProofCreation("Missing rcv_sha256".to_string()))
            .map(Some)?,
    };

    // Prepare the circuit
    let diversifier = Diversifier(inputs.diversifier);
    let circuit = prepare_circuit(
        proof_generation_key.clone(),
        diversifier,
        rseed,
        value,
        alpha,
        &rcv,
        note_commitment_root,
        &merkle_path,
        inputs.nm_left_nf,
        inputs.nm_right_nf,
        inputs.nm_merkle_path.clone(),
        nullifier_gap_root,
        inputs.value_commitment_scheme,
        rcv_sha256,
    )?;

    // Create and encode the proof
    let proof = create_proof(params, circuit, &mut rng);
    let zkproof = encode_proof(&proof);

    // Note: We intentionally do NOT compute or expose the Zcash nullifier
    // to preserve privacy. The circuit proves knowledge of it internally.

    // Compute value commitment(s) deterministically from value and trapdoor/randomness.
    let rk_bytes: [u8; 32] = proof_generation_key.to_viewing_key().rk(alpha).into();
    let cv_bytes: [u8; 32] = sapling::value::ValueCommitment::derive(value, rcv).to_bytes();
    let cv_sha256 = rcv_sha256.map(|r| zair_core::base::cv_sha256(inputs.value, r));

    let proof_output = ClaimProofOutput {
        zkproof,
        rk: rk_bytes,
        cv: match inputs.value_commitment_scheme {
            ValueCommitmentScheme::Native => Some(cv_bytes),
            ValueCommitmentScheme::Sha256 | ValueCommitmentScheme::Plain => None,
        },
        cv_sha256,
        value: match inputs.value_commitment_scheme {
            ValueCommitmentScheme::Plain => Some(inputs.value),
            ValueCommitmentScheme::Native | ValueCommitmentScheme::Sha256 => None,
        },
        airdrop_nullifier: inputs.airdrop_nullifier,
    };
    Ok(proof_output)
}

/// Compute the merkle root from a note commitment and merkle path.
///
/// # Errors
/// - Returns `ClaimProofError::InvalidCmu` if the note commitment bytes are not a valid scalar.
/// - Returns `ClaimProofError::IntegerConversion` if the scalar bit count cannot be converted to
///   usize.
#[allow(
    dead_code,
    reason = "Useful helper for debugging/testing root recomputation"
)]
pub fn compute_note_commitment_root_from_path(
    cmu_bytes: &[u8; 32],
    merkle_path: &MerklePath,
) -> Result<bls12_381::Scalar, ClaimProofError> {
    use group::ff::PrimeFieldBits;

    let scalar_num_bits = usize::try_from(bls12_381::Scalar::NUM_BITS)?;
    let mut cur = bls12_381::Scalar::from_bytes(cmu_bytes)
        .into_option()
        .ok_or(ClaimProofError::InvalidCmu)?;
    let pos: u64 = merkle_path.position().into();

    for (i, sibling) in merkle_path.path_elems().iter().enumerate() {
        let sibling_scalar: bls12_381::Scalar = (*sibling).into();
        let is_right = (pos >> i) & 1 == 1;

        let (lhs, rhs) = if is_right {
            (&sibling_scalar, &cur)
        } else {
            (&cur, &sibling_scalar)
        };

        let lhs_bits = lhs.to_le_bits();
        let rhs_bits = rhs.to_le_bits();

        cur = jubjub::ExtendedPoint::from(sapling::pedersen_hash::pedersen_hash(
            sapling::pedersen_hash::Personalization::MerkleTree(i),
            lhs_bits
                .iter()
                .by_vals()
                .take(scalar_num_bits)
                .chain(rhs_bits.iter().by_vals().take(scalar_num_bits)),
        ))
        .to_affine()
        .get_u();
    }

    Ok(cur)
}

/// Compute the non-membership tree root from gap bounds and merkle path.
///
/// The non-membership tree uses:
/// - Leaf: `pedersen_hash(level=62, left_nf || right_nf)`
/// - Internal nodes: `pedersen_hash(level=i, left || right)` for levels 0-31
///
/// # Errors
/// - Returns `ClaimProofError::InvalidNmMerklePath` if a sibling in the merkle path is not a valid
///   scalar.
/// - Returns `ClaimProofError::IntegerConversion` if the scalar bit count cannot be converted to
///   usize.
#[allow(
    dead_code,
    reason = "Useful helper for debugging/testing root recomputation"
)]
pub fn compute_nullifier_gap_root_from_path(
    left_nf: &[u8; 32],
    right_nf: &[u8; 32],
    nm_merkle_path: &[([u8; 32], bool)],
) -> Result<bls12_381::Scalar, ClaimProofError> {
    use group::ff::PrimeFieldBits;
    use zair_sapling_circuit::circuit::NM_LEAF_HASH_LEVEL;

    let scalar_num_bits = usize::try_from(bls12_381::Scalar::NUM_BITS)?;

    // Compute the leaf hash: pedersen_hash(level=62, left_nf || right_nf)
    let left_bits = left_nf
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1));
    let right_bits = right_nf
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1));

    let mut cur = jubjub::ExtendedPoint::from(sapling::pedersen_hash::pedersen_hash(
        sapling::pedersen_hash::Personalization::MerkleTree(NM_LEAF_HASH_LEVEL),
        left_bits.chain(right_bits),
    ))
    .to_affine()
    .get_u();

    // Ascend the tree
    for (i, (sibling, is_right)) in nm_merkle_path.iter().enumerate() {
        let sibling_scalar = bls12_381::Scalar::from_bytes(sibling)
            .into_option()
            .ok_or_else(|| {
                ClaimProofError::InvalidNmMerklePath(format!("Invalid scalar at index {i}"))
            })?;

        let (lhs, rhs) = if *is_right {
            (&sibling_scalar, &cur)
        } else {
            (&cur, &sibling_scalar)
        };

        let lhs_bits = lhs.to_le_bits();
        let rhs_bits = rhs.to_le_bits();

        cur = jubjub::ExtendedPoint::from(sapling::pedersen_hash::pedersen_hash(
            sapling::pedersen_hash::Personalization::MerkleTree(i),
            lhs_bits
                .iter()
                .by_vals()
                .take(scalar_num_bits)
                .chain(rhs_bits.iter().by_vals().take(scalar_num_bits)),
        ))
        .to_affine()
        .get_u();
    }

    Ok(cur)
}
