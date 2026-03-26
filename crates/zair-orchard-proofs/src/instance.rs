use ff::PrimeField as _;
use group::{Curve as _, Group as _, GroupEncoding as _};
use halo2_proofs::plonk;
use pasta_curves::arithmetic::{Coordinates, CurveAffine as _};
use pasta_curves::{pallas, vesta};

use crate::error::ClaimProofError;
use crate::types::ValueCommitmentScheme;

/// Number of public instance scalars for the Native value commitment scheme.
const NATIVE_INSTANCE_COUNT: usize = 7;
/// Number of public instance scalars for the SHA-256 value commitment scheme.
const SHA256_INSTANCE_COUNT: usize = 13;

pub fn base_from_repr(bytes: [u8; 32]) -> Result<pallas::Base, ClaimProofError> {
    Option::<pallas::Base>::from(pallas::Base::from_repr(bytes))
        .ok_or(ClaimProofError::NonCanonicalBase)
}

#[cfg(feature = "prove")]
pub fn scalar_from_repr(bytes: [u8; 32]) -> Result<pallas::Scalar, ClaimProofError> {
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(bytes))
        .ok_or(ClaimProofError::NonCanonicalScalar)
}

#[cfg(feature = "prove")]
pub fn target_id_slice(target_id: &[u8; 32], target_id_len: u8) -> Result<&[u8], ClaimProofError> {
    let target = target_id
        .get(..usize::from(target_id_len))
        .ok_or(ClaimProofError::InvalidTargetIdLength)?;
    std::str::from_utf8(target).map_err(|_| ClaimProofError::InvalidTargetIdUtf8)?;
    Ok(target)
}

#[cfg(feature = "prove")]
pub fn point_from_bytes(bytes: [u8; 32]) -> Result<pallas::Affine, ClaimProofError> {
    let p = Option::<pallas::Point>::from(pallas::Point::from_bytes(&bytes))
        .ok_or(ClaimProofError::InvalidPoint)?;
    if bool::from(p.is_identity()) {
        return Err(ClaimProofError::IdentityPoint);
    }
    Ok(p.to_affine())
}

fn coords_or_zero(p: pallas::Point) -> (pallas::Base, pallas::Base) {
    if bool::from(p.is_identity()) {
        (pallas::Base::zero(), pallas::Base::zero())
    } else {
        let coords: Option<Coordinates<pallas::Affine>> = Option::from(p.to_affine().coordinates());
        coords.map_or_else(
            || (pallas::Base::zero(), pallas::Base::zero()),
            |c| (*c.x(), *c.y()),
        )
    }
}

pub fn to_instance(
    note_commitment_root: [u8; 32],
    cv: Option<[u8; 32]>,
    cv_sha256: Option<[u8; 32]>,
    airdrop_nf: [u8; 32],
    rk_bytes: [u8; 32],
    nullifier_gap_root: [u8; 32],
    scheme: ValueCommitmentScheme,
) -> Result<[Vec<vesta::Scalar>; 1], ClaimProofError> {
    let mut instance: Vec<vesta::Scalar> = Vec::with_capacity(match scheme {
        ValueCommitmentScheme::Native => NATIVE_INSTANCE_COUNT,
        ValueCommitmentScheme::Sha256 => SHA256_INSTANCE_COUNT,
    });

    let rk_point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&rk_bytes))
        .ok_or(ClaimProofError::InvalidPoint)?;
    let (rk_x, rk_y) = coords_or_zero(rk_point);
    instance.push(rk_x);
    instance.push(rk_y);

    match scheme {
        ValueCommitmentScheme::Native => {
            let cv_bytes = cv.ok_or(ClaimProofError::InvalidPoint)?;
            let cv_point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&cv_bytes))
                .ok_or(ClaimProofError::InvalidPoint)?;
            let (cv_x, cv_y) = coords_or_zero(cv_point);
            instance.push(cv_x);
            instance.push(cv_y);
            instance.push(base_from_repr(note_commitment_root)?);
            instance.push(base_from_repr(nullifier_gap_root)?);
            instance.push(base_from_repr(airdrop_nf)?);
        }
        ValueCommitmentScheme::Sha256 => {
            let digest = cv_sha256.ok_or(plonk::Error::Synthesis)?;
            for chunk in digest.chunks_exact(4) {
                let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
                instance.push(vesta::Scalar::from(word));
            }
            instance.push(base_from_repr(note_commitment_root)?);
            instance.push(base_from_repr(nullifier_gap_root)?);
            instance.push(base_from_repr(airdrop_nf)?);
        }
    }

    Ok([instance])
}
