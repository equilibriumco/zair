use halo2_proofs::plonk::{SingleVerifier, verify_proof};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bRead;
use pasta_curves::vesta;

use crate::error::ClaimProofError;
use crate::instance::to_instance;
use crate::keys::keys_for;
use crate::types::{ClaimProofOutput, ValueCommitmentScheme};

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
