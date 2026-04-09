use halo2_proofs::plonk;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bWrite;
use orchard::note::{RandomSeed, Rho};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey as RedPallasVerificationKey};
use orchard::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
use pasta_curves::{pallas, vesta};
use zair_orchard_circuit::circuit::airdrop::Circuit;

use crate::error::ClaimProofError;
use crate::instance::{
    base_from_repr, point_from_bytes, scalar_from_repr, target_id_slice, to_instance,
};
use crate::keys::keys_for;
use crate::types::{ClaimProofInputs, ClaimProofOutput, ValueCommitmentScheme};

/// Generate an Orchard claim proof.
///
/// # Errors
/// Returns an error if any input decoding fails (non-canonical field elements, invalid point
/// encodings), if Halo2 keygen/proving fails, or if the circuit constraints are not satisfied.
pub fn generate_claim_proof(
    params: &Params<vesta::Affine>,
    inputs: &ClaimProofInputs,
) -> Result<ClaimProofOutput, ClaimProofError> {
    let _target_id = target_id_slice(&inputs.target_id, inputs.target_id_len)?;

    let (rcv_sha256, cv_sha256) = match inputs.value_commitment_scheme {
        ValueCommitmentScheme::Native | ValueCommitmentScheme::Plain => {
            if inputs.rcv_sha256.is_some() {
                return Err(ClaimProofError::UnexpectedRcvSha256);
            }
            (None, None)
        }
        ValueCommitmentScheme::Sha256 => {
            let rcv_sha256 = inputs.rcv_sha256.ok_or(ClaimProofError::MissingRcvSha256)?;
            (
                Some(rcv_sha256),
                Some(zair_core::base::cv_sha256(inputs.value, rcv_sha256)),
            )
        }
    };

    // Parse note randomness (rho/rseed) and derive (psi, rcm).
    let rho = Option::<Rho>::from(Rho::from_bytes(&inputs.rho))
        .ok_or(ClaimProofError::NonCanonicalBase)?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(inputs.rseed, &rho))
        .ok_or(ClaimProofError::NonCanonicalScalar)?;
    let psi = rseed.psi(&rho);
    let rcm = rseed.rcm_scalar(&rho);

    // Decode point/key material.
    let g_d = point_from_bytes(inputs.g_d)?;
    let pk_d = point_from_bytes(inputs.pk_d)?;
    let ak_p = point_from_bytes(inputs.ak_p)?;
    let nk = base_from_repr(inputs.nk)?;
    let rivk = scalar_from_repr(inputs.rivk)?;
    let alpha = scalar_from_repr(inputs.alpha)?;
    let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(inputs.rcv))
        .ok_or(ClaimProofError::NonCanonicalScalar)?;

    // Decode Merkle paths.
    let note_path = inputs
        .cm_merkle_path
        .iter()
        .map(|b| base_from_repr(*b))
        .collect::<Result<Vec<_>, _>>()?;
    let gap_path = inputs
        .nf_merkle_path
        .iter()
        .map(|b| base_from_repr(*b))
        .collect::<Result<Vec<_>, _>>()?;

    let note_path: [pallas::Base; orchard::NOTE_COMMITMENT_TREE_DEPTH] = note_path
        .try_into()
        .map_err(|_| ClaimProofError::NonCanonicalBase)?;
    let gap_path: [pallas::Base; orchard::NOTE_COMMITMENT_TREE_DEPTH] = gap_path
        .try_into()
        .map_err(|_| ClaimProofError::NonCanonicalBase)?;

    // Decode gap bounds.
    let left = base_from_repr(inputs.left)?;
    let right = base_from_repr(inputs.right)?;

    // Build the circuit witness.
    let circuit = Circuit {
        target_id: inputs.target_id,
        target_id_len: inputs.target_id_len,
        note_path: halo2_proofs::circuit::Value::known(note_path),
        note_pos: halo2_proofs::circuit::Value::known(inputs.cm_note_position),
        g_d: halo2_proofs::circuit::Value::known(g_d),
        pk_d: halo2_proofs::circuit::Value::known(pk_d),
        value: halo2_proofs::circuit::Value::known(NoteValue::from_raw(inputs.value)),
        rho: halo2_proofs::circuit::Value::known(base_from_repr(inputs.rho)?),
        psi: halo2_proofs::circuit::Value::known(psi),
        rcm: halo2_proofs::circuit::Value::known(rcm),
        alpha: halo2_proofs::circuit::Value::known(alpha),
        ak_p: halo2_proofs::circuit::Value::known(ak_p),
        nk: halo2_proofs::circuit::Value::known(nk),
        rivk: halo2_proofs::circuit::Value::known(rivk),
        rcv: halo2_proofs::circuit::Value::known(rcv.clone()),
        value_commitment_scheme: inputs.value_commitment_scheme.into(),
        rcv_sha256: match rcv_sha256 {
            Some(bytes) => halo2_proofs::circuit::Value::known(bytes),
            None => halo2_proofs::circuit::Value::unknown(),
        },
        left: halo2_proofs::circuit::Value::known(left),
        right: halo2_proofs::circuit::Value::known(right),
        gap_path: halo2_proofs::circuit::Value::known(gap_path),
        gap_pos: halo2_proofs::circuit::Value::known(inputs.nf_leaf_position),
    };

    let rk = RedPallasVerificationKey::<SpendAuth>::try_from(inputs.ak_p)
        .map_err(|_| ClaimProofError::InvalidPoint)?
        .randomize(&alpha);
    let rk_bytes: [u8; 32] = (&rk).into();

    // Compute cv option based on scheme.
    let cv = match inputs.value_commitment_scheme {
        ValueCommitmentScheme::Native => {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "Orchard value commitment API requires NoteValue subtraction to produce ValueSum"
            )]
            let value_sum = NoteValue::from_raw(inputs.value) - NoteValue::from_raw(0);
            Some(ValueCommitment::derive(value_sum, rcv).to_bytes())
        }
        ValueCommitmentScheme::Sha256 | ValueCommitmentScheme::Plain => None,
    };

    let plain_value = match inputs.value_commitment_scheme {
        ValueCommitmentScheme::Plain => Some(inputs.value),
        ValueCommitmentScheme::Native | ValueCommitmentScheme::Sha256 => None,
    };

    // Instances for proof creation.
    let [col0] = to_instance(
        inputs.note_commitment_root,
        cv,
        cv_sha256,
        plain_value,
        inputs.airdrop_nullifier,
        rk_bytes,
        inputs.nullifier_gap_root,
        inputs.value_commitment_scheme,
    )?;
    let instance_cols: [&[vesta::Scalar]; 1] = [&col0[..]];
    let instances: [&[&[vesta::Scalar]]; 1] = [&instance_cols];

    // Prove.
    let keys = keys_for(
        params,
        inputs.value_commitment_scheme,
        inputs.target_id,
        inputs.target_id_len,
    )?;
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    plonk::create_proof(
        params,
        &keys.pk,
        &[circuit],
        &instances,
        &mut rand::rngs::OsRng,
        &mut transcript,
    )?;
    let proof = transcript.finalize();

    Ok(ClaimProofOutput {
        zkproof: proof,
        rk: rk_bytes,
        cv,
        cv_sha256,
        value: plain_value,
        airdrop_nullifier: inputs.airdrop_nullifier,
    })
}
