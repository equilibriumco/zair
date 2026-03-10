use std::io::Cursor;

use halo2_proofs::plonk::{SingleVerifier, verify_proof};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bRead;
use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use pasta_curves::vesta;
use zair_core::base::{Nullifier, hash_bytes};

use crate::error::ClaimProofError;
use crate::instance::to_instance;
use crate::keys::keys_for;
use crate::types::{ClaimProofOutput, ValueCommitmentScheme};

/// Domain tag for Orchard proof-hash preimages.
pub const ORCHARD_PROOF_TAG: &[u8; 21] = b"ZAIR_ORCHARD_PROOF_V1";

// NOTE: This is public-facing adaption of `[read_params](zair-sdk::commands::orchard_params)`.
/// Loads Orchard parameters from bytes.
///
/// # Errors
/// Returns an error if the bytes fail to decode.
pub fn read_params_from_bytes(bytes: &[u8]) -> Result<Params<vesta::Affine>, ClaimProofError> {
    let mut cursor = Cursor::new(bytes);
    Params::<vesta::Affine>::read(&mut cursor).map_err(|_| ClaimProofError::ReadParams)
}

/// Verify an Orchard claim proof with the given public inputs.
///
/// # Errors
/// Returns an error if the public inputs fail decoding or if Halo2 verification fails.
#[allow(
    clippy::too_many_arguments,
    reason = "Public verifier API takes explicit proof fields"
)]
pub fn verify_claim_proof(
    params: &Params<vesta::Affine>,
    zkproof: &[u8],
    cv: &Option<[u8; 32]>,
    cv_sha256: &Option<[u8; 32]>,
    airdrop_nullifier: &[u8; 32],
    rk: &[u8; 32],
    note_commitment_root: &[u8; 32],
    nullifier_gap_root: &[u8; 32],
    value_commitment_scheme: ValueCommitmentScheme,
    target_id: &[u8],
) -> Result<(), ClaimProofError> {
    if target_id.len() > 32 {
        return Err(ClaimProofError::InvalidTargetIdLength);
    }
    std::str::from_utf8(target_id).map_err(|_| ClaimProofError::InvalidTargetIdUtf8)?;
    let mut target_id_arr = [0_u8; 32];
    target_id_arr[..target_id.len()].copy_from_slice(target_id);
    let target_id_len = target_id.len() as u8;

    let [col0] = to_instance(
        *note_commitment_root,
        *cv,
        *cv_sha256,
        *airdrop_nullifier,
        *rk,
        *nullifier_gap_root,
        value_commitment_scheme,
    )?;
    let instance_cols: [&[vesta::Scalar]; 1] = [&col0[..]];
    let instances: [&[&[vesta::Scalar]]; 1] = [&instance_cols];

    let keys = keys_for(
        params,
        value_commitment_scheme,
        target_id_arr,
        target_id_len,
    )?;
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::init(zkproof);
    verify_proof(params, &keys.vk, strategy, &instances, &mut transcript)?;
    Ok(())
}

/// Verify an Orchard claim proof with the given public inputs.
///
/// This is a convenience function for verifying proof produced by
/// [`generate_claim_proof`](crate::prover::generate_claim_proof).
///
/// # Errors
/// Returns an error if the public inputs fail decoding or if Halo2 verification fails.
pub fn verify_claim_proof_output(
    params: &Params<vesta::Affine>,
    ClaimProofOutput {
        zkproof,
        rk,
        cv,
        cv_sha256,
        airdrop_nullifier,
    }: &ClaimProofOutput,
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: ValueCommitmentScheme,
    target_id: &[u8],
) -> Result<(), ClaimProofError> {
    verify_claim_proof(
        params,
        zkproof,
        cv,
        cv_sha256,
        airdrop_nullifier,
        rk,
        &note_commitment_root,
        &nullifier_gap_root,
        value_commitment_scheme,
        target_id,
    )
}

/// Verify an Orchard spend-auth signature against a submission digest.
pub fn verify_signature(
    rk_bytes: [u8; 32],
    spend_auth_sig: [u8; 64],
    digest: &[u8; 32],
) -> Result<(), ClaimProofError> {
    let rk = VerificationKey::<SpendAuth>::try_from(rk_bytes)
        .map_err(|_| ClaimProofError::InvalidRkEncoding)?;
    let signature = Signature::<SpendAuth>::from(spend_auth_sig);

    rk.verify(digest, &signature)
        .map_err(|_| ClaimProofError::InvalidSignature)
}

/// Hashes and returns the digest for Orchard proof fields.
pub fn hash_orchard_proof_fields(
    zkproof: &[u8],
    rk: &[u8; 32],
    cv: Option<[u8; 32]>,
    cv_sha256: Option<[u8; 32]>,
    airdrop_nullifier: Nullifier,
) -> Result<[u8; 32], ClaimProofError> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(ORCHARD_PROOF_TAG);
    let proof_len =
        u32::try_from(zkproof.len()).map_err(|_| ClaimProofError::ProofLengthExceedsU32)?;
    preimage.extend_from_slice(&proof_len.to_le_bytes());
    preimage.extend_from_slice(zkproof);
    preimage.extend_from_slice(rk);
    match cv {
        Some(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&bytes);
        }
        None => preimage.push(0),
    }
    match cv_sha256 {
        Some(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&bytes);
        }
        None => preimage.push(0),
    }
    let nf: [u8; 32] = airdrop_nullifier.into();
    preimage.extend_from_slice(&nf);
    Ok(hash_bytes(&preimage))
}
