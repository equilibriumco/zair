//! Canonical hashing helpers for signed claim submissions.

use zair_core::schema::submission::{OrchardSignedClaim, SaplingSignedClaim};
use zair_orchard_proofs::hash_orchard_proof_fields;
use zair_sapling_proofs::hash_sapling_proof_fields;

use super::claim_proofs::{OrchardClaimProofResult, SaplingClaimProofResult};

/// Hash a single unsigned Sapling proof entry.
#[must_use]
pub fn hash_sapling_proof(proof: &SaplingClaimProofResult) -> [u8; 32] {
    hash_sapling_proof_fields(
        &proof.zkproof,
        &proof.rk,
        proof.cv,
        proof.cv_sha256,
        proof.airdrop_nullifier,
    )
}

/// Hash a single unsigned Orchard proof entry.
pub fn hash_orchard_proof(proof: &OrchardClaimProofResult) -> eyre::Result<[u8; 32]> {
    let digest = hash_orchard_proof_fields(
        &proof.zkproof,
        &proof.rk,
        proof.cv,
        proof.cv_sha256,
        proof.airdrop_nullifier,
    )?;
    Ok(digest)
}

/// Hash the proof fields of a signed Sapling claim entry.
#[must_use]
pub fn hash_sapling_signed_claim_proof(claim: &SaplingSignedClaim) -> [u8; 32] {
    hash_sapling_proof_fields(
        &claim.zkproof,
        &claim.rk,
        claim.cv,
        claim.cv_sha256,
        claim.airdrop_nullifier,
    )
}

/// Hash the proof fields of a signed Orchard claim entry.
pub fn hash_orchard_signed_claim_proof(claim: &OrchardSignedClaim) -> eyre::Result<[u8; 32]> {
    let digest = hash_orchard_proof_fields(
        &claim.zkproof,
        &claim.rk,
        claim.cv,
        claim.cv_sha256,
        claim.airdrop_nullifier,
    )?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use zair_core::base::Nullifier;

    use super::*;
    use crate::commands::claim_proofs::{OrchardClaimProofResult, SaplingClaimProofResult};

    #[test]
    fn sapling_proof_hash_is_deterministic_and_sensitive_to_field_changes() {
        let p0 = SaplingClaimProofResult {
            zkproof: [1_u8; 192],
            rk: [2_u8; 32],
            cv: Some([3_u8; 32]),
            cv_sha256: None,
            airdrop_nullifier: Nullifier::from([4_u8; 32]),
        };
        let p1 = SaplingClaimProofResult {
            zkproof: [9_u8; 192],
            rk: [8_u8; 32],
            cv: None,
            cv_sha256: Some([7_u8; 32]),
            airdrop_nullifier: Nullifier::from([6_u8; 32]),
        };
        let h0 = hash_sapling_proof(&p0);
        let h0_again = hash_sapling_proof(&p0);
        let h1 = hash_sapling_proof(&p1);
        assert_eq!(h0, h0_again);
        assert_ne!(h0, h1);
    }

    #[test]
    fn orchard_proof_hash_is_deterministic_and_sensitive_to_length() {
        let p0 = OrchardClaimProofResult {
            zkproof: vec![1_u8; 5],
            rk: [2_u8; 32],
            cv: Some([3_u8; 32]),
            cv_sha256: None,
            airdrop_nullifier: Nullifier::from([4_u8; 32]),
        };
        let p1 = OrchardClaimProofResult {
            zkproof: vec![1_u8; 6],
            rk: [2_u8; 32],
            cv: Some([3_u8; 32]),
            cv_sha256: None,
            airdrop_nullifier: Nullifier::from([4_u8; 32]),
        };
        let h0 = hash_orchard_proof(&p0).expect("hash should succeed");
        let h0_again = hash_orchard_proof(&p0).expect("hash should succeed");
        let h1 = hash_orchard_proof(&p1).expect("hash should succeed");
        assert_eq!(h0, h0_again);
        assert_ne!(h0, h1);
    }
}
