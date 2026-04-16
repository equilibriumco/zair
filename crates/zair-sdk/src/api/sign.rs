//! In-memory claim signing.

use std::collections::BTreeMap;

use thiserror::Error;
use tracing::info;
use zair_core::base::{Nullifier, Pool, signature_digest};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::submission::{ClaimSubmission, OrchardSignedClaim, SaplingSignedClaim};

use crate::api::claims::{ClaimProofsOutput, ClaimSecretsOutput};
use crate::commands::submission_auth::{orchard, sapling};
use crate::commands::{ensure_unique_airdrop_nullifiers, hash_orchard_proof, hash_sapling_proof};
use crate::common::to_zcash_network;

/// Errors that can occur during claim signing.
#[derive(Debug, Error)]
pub enum SignError {
    /// Returned when both Sapling and Orchard proof lists are empty.
    #[error("No proofs found to sign")]
    NoProofs,
    /// Returned when Sapling secrets are supplied but no Sapling proofs exist.
    #[error("Sapling secrets provided without Sapling proofs")]
    MismatchedSaplingSecrets,
    /// Returned when Orchard secrets are supplied but no Orchard proofs exist.
    #[error("Orchard secrets provided without Orchard proofs")]
    MismatchedOrchardSecrets,
    /// Returned when the Sapling proof count does not equal the Sapling secret count.
    #[error("Proof/secret count mismatch for Sapling entries: {0} proofs vs {1} secrets")]
    SaplingCountMismatch(usize, usize),
    /// Returned when the Orchard proof count does not equal the Orchard secret count.
    #[error("Proof/secret count mismatch for Orchard entries: {0} proofs vs {1} secrets")]
    OrchardCountMismatch(usize, usize),
    /// Returned when two Sapling secrets share the same airdrop nullifier.
    #[error("Duplicate Sapling secret entry for airdrop nullifier: {0:?}")]
    DuplicateSaplingSecret(Nullifier),
    /// Returned when two Orchard secrets share the same airdrop nullifier.
    #[error("Duplicate Orchard secret entry for airdrop nullifier: {0:?}")]
    DuplicateOrchardSecret(Nullifier),
    /// Returned when no matching secret is found for a proof's airdrop nullifier.
    #[error("Missing secret material for {0} proof entry with nullifier: {1:?}")]
    MissingSecret(String, Nullifier),
    /// Returned when Sapling proofs exist but the airdrop configuration has no Sapling pool
    /// section.
    #[error("Sapling proofs provided but airdrop configuration has no Sapling pool")]
    MissingSaplingPool,
    /// Returned when Orchard proofs exist but the airdrop configuration has no Orchard pool
    /// section.
    #[error("Orchard proofs provided but airdrop configuration has no Orchard pool")]
    MissingOrchardPool,
    /// Returned when the spend-auth signing key has not been derived for the pool.
    #[error("{0} signing key should be initialized")]
    MissingSigningKey(String),
    /// Returned when no message hash (shared or per-proof) is available for a claim's airdrop
    /// nullifier.
    #[error("No message provided for {0} claim with nullifier: {1:?}")]
    MissingMessageHash(String, Nullifier),
    /// Returned when the signature digest computation fails for a claim.
    #[error("Failed to compute signature digest for {0}: {1}")]
    DigestError(String, String),
    /// Returned when the spend-authority signature generation fails.
    #[error("Failed to sign {0} claim: {1}")]
    SigningError(String, String),
    /// Returned when the spend-auth key derivation from seed and account index fails.
    #[error("Failed to derive {0} signing key: {1}")]
    KeyDerivation(String, String),
}

/// Pre-computed message hashes for signing, with per‑pool per‑proof maps and a shared fallback.
///
/// Per‑proof hashes (keyed by airdrop nullifier) take precedence over the shared hash for
/// matching nullifiers.  At least one of `shared` or the relevant per‑proof entry must be
/// present for every proof that is signed.
#[derive(Debug, Clone, Default)]
pub struct ResolvedMessageHashes {
    /// Shared message hash applied to all proofs (unless overridden by a per‑proof entry).
    pub shared: Option<[u8; 32]>,
    /// Per‑proof Sapling message hashes keyed by airdrop nullifier.
    pub sapling: BTreeMap<Nullifier, [u8; 32]>,
    /// Per‑proof Orchard message hashes keyed by airdrop nullifier.
    pub orchard: BTreeMap<Nullifier, [u8; 32]>,
}

impl ResolvedMessageHashes {
    /// Returns `true` if no messages are provided at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared.is_none() && self.sapling.is_empty() && self.orchard.is_empty()
    }

    /// Resolve the Sapling message hash for a given nullifier.
    #[must_use]
    pub fn sapling_hash(&self, nullifier: Nullifier) -> Option<[u8; 32]> {
        self.sapling.get(&nullifier).copied().or(self.shared)
    }

    /// Resolve the Orchard message hash for a given nullifier.
    #[must_use]
    pub fn orchard_hash(&self, nullifier: Nullifier) -> Option<[u8; 32]> {
        self.orchard.get(&nullifier).copied().or(self.shared)
    }
}

/// Sign claim proofs into a submission package.
///
/// # Arguments
///
/// * `proofs` - generated claim proofs
/// * `secrets` - proof generation secrets (from the prove step)
/// * `seed` - 64-byte BIP-39 seed
/// * `account_id` - ZIP-32 account index
/// * `config` - airdrop configuration
/// * `message_hashes` - pre-computed message hashes to sign; per‑proof hashes (keyed by airdrop
///   nullifier) take precedence over the shared fallback
///
/// # Returns
///
/// Signed `ClaimSubmission` ready for the target chain.
///
/// # Errors
///
/// Returns an error if inputs are invalid, key derivation fails, or signing fails.
#[allow(
    clippy::too_many_arguments,
    clippy::similar_names,
    clippy::unused_async,
    clippy::too_many_lines,
    reason = "API entrypoint"
)]
pub async fn sign_claim_submission_from_bytes(
    proofs: ClaimProofsOutput,
    secrets: ClaimSecretsOutput,
    seed: &[u8],
    account_id: u32,
    config: &AirdropConfiguration,
    message_hashes: &ResolvedMessageHashes,
) -> Result<ClaimSubmission, SignError> {
    if proofs.sapling_proofs.is_empty() && proofs.orchard_proofs.is_empty() {
        return Err(SignError::NoProofs);
    }
    if proofs.sapling_proofs.is_empty() && !secrets.sapling.is_empty() {
        return Err(SignError::MismatchedSaplingSecrets);
    }
    if proofs.orchard_proofs.is_empty() && !secrets.orchard.is_empty() {
        return Err(SignError::MismatchedOrchardSecrets);
    }
    if proofs.sapling_proofs.len() != secrets.sapling.len() {
        return Err(SignError::SaplingCountMismatch(
            proofs.sapling_proofs.len(),
            secrets.sapling.len(),
        ));
    }
    if proofs.orchard_proofs.len() != secrets.orchard.len() {
        return Err(SignError::OrchardCountMismatch(
            proofs.orchard_proofs.len(),
            secrets.orchard.len(),
        ));
    }
    ensure_unique_airdrop_nullifiers(
        proofs
            .sapling_proofs
            .iter()
            .map(|proof| proof.airdrop_nullifier),
        "Sapling proof",
    )
    .map_err(|e| {
        SignError::DigestError("sapling nullifier uniqueness".to_string(), e.to_string())
    })?;
    ensure_unique_airdrop_nullifiers(
        proofs
            .orchard_proofs
            .iter()
            .map(|proof| proof.airdrop_nullifier),
        "Orchard proof",
    )
    .map_err(|e| {
        SignError::DigestError("orchard nullifier uniqueness".to_string(), e.to_string())
    })?;

    let seed_array: &[u8; 64] = seed.try_into().map_err(|_| {
        SignError::DigestError("seed".to_string(), "must be exactly 64 bytes".to_string())
    })?;

    let network = to_zcash_network(config.network);

    let sapling_target_id = if proofs.sapling_proofs.is_empty() {
        None
    } else {
        Some(
            config
                .sapling
                .as_ref()
                .ok_or(SignError::MissingSaplingPool)?
                .target_id
                .clone(),
        )
    };
    let orchard_target_id = if proofs.orchard_proofs.is_empty() {
        None
    } else {
        Some(
            config
                .orchard
                .as_ref()
                .ok_or(SignError::MissingOrchardPool)?
                .target_id
                .clone(),
        )
    };

    let sapling_keys = if proofs.sapling_proofs.is_empty() {
        None
    } else {
        Some(
            sapling::derive_spend_auth_keys(network, seed_array, account_id)
                .map_err(|e| SignError::KeyDerivation("sapling".to_string(), e.to_string()))?,
        )
    };
    let orchard_key = if proofs.orchard_proofs.is_empty() {
        None
    } else {
        Some(
            orchard::derive_spend_auth_key(network, seed_array, account_id)
                .map_err(|e| SignError::KeyDerivation("orchard".to_string(), e.to_string()))?,
        )
    };

    let mut sapling_secret_by_nf = BTreeMap::new();
    for secret in secrets.sapling {
        let nullifier = secret.airdrop_nullifier;
        let existing = sapling_secret_by_nf.insert(nullifier, secret);
        if existing.is_some() {
            return Err(SignError::DuplicateSaplingSecret(nullifier));
        }
    }

    let mut sapling = Vec::with_capacity(proofs.sapling_proofs.len());
    if !proofs.sapling_proofs.is_empty() {
        let target_id = sapling_target_id
            .as_deref()
            .ok_or_else(|| SignError::MissingSigningKey("Sapling".to_string()))?;
        let keys = sapling_keys
            .as_ref()
            .ok_or_else(|| SignError::MissingSigningKey("Sapling".to_string()))?;

        for proof in &proofs.sapling_proofs {
            let secret = sapling_secret_by_nf
                .get(&proof.airdrop_nullifier)
                .ok_or_else(|| {
                    SignError::MissingSecret("Sapling".to_string(), proof.airdrop_nullifier)
                })?;
            let msg_hash = message_hashes
                .sapling_hash(proof.airdrop_nullifier)
                .ok_or_else(|| {
                    SignError::MissingMessageHash("Sapling".to_string(), proof.airdrop_nullifier)
                })?;
            let proof_hash = hash_sapling_proof(proof);
            let digest =
                signature_digest(Pool::Sapling, target_id.as_bytes(), &proof_hash, &msg_hash)
                    .map_err(|e| SignError::DigestError("Sapling".to_string(), e.to_string()))?;

            let spend_auth_sig = sapling::sign_claim(proof, secret, keys, &digest)
                .map_err(|e| SignError::SigningError("Sapling".to_string(), e.to_string()))?;
            sapling.push(SaplingSignedClaim {
                zkproof: proof.zkproof,
                rk: proof.rk,
                cv: proof.cv,
                cv_sha256: proof.cv_sha256,
                value: proof.value,
                airdrop_nullifier: proof.airdrop_nullifier,
                proof_hash,
                message_hash: msg_hash,
                spend_auth_sig,
            });
        }
    }

    let mut orchard_secret_by_nf = BTreeMap::new();
    for secret in secrets.orchard {
        let nullifier = secret.airdrop_nullifier;
        let existing = orchard_secret_by_nf.insert(nullifier, secret);
        if existing.is_some() {
            return Err(SignError::DuplicateOrchardSecret(nullifier));
        }
    }

    let mut orchard = Vec::with_capacity(proofs.orchard_proofs.len());
    if !proofs.orchard_proofs.is_empty() {
        let target_id = orchard_target_id
            .as_deref()
            .ok_or_else(|| SignError::MissingSigningKey("Orchard".to_string()))?;
        let key = orchard_key
            .as_ref()
            .ok_or_else(|| SignError::MissingSigningKey("Orchard".to_string()))?;

        for proof in &proofs.orchard_proofs {
            let secret = orchard_secret_by_nf
                .get(&proof.airdrop_nullifier)
                .ok_or_else(|| {
                    SignError::MissingSecret("Orchard".to_string(), proof.airdrop_nullifier)
                })?;
            let msg_hash = message_hashes
                .orchard_hash(proof.airdrop_nullifier)
                .ok_or_else(|| {
                    SignError::MissingMessageHash("Orchard".to_string(), proof.airdrop_nullifier)
                })?;
            let proof_hash = hash_orchard_proof(proof)
                .map_err(|e| SignError::DigestError("Orchard".to_string(), e.to_string()))?;
            let digest =
                signature_digest(Pool::Orchard, target_id.as_bytes(), &proof_hash, &msg_hash)
                    .map_err(|e| SignError::DigestError("Orchard".to_string(), e.to_string()))?;

            let spend_auth_sig = orchard::sign_claim(proof, secret, key, &digest)
                .map_err(|e| SignError::SigningError("Orchard".to_string(), e.to_string()))?;
            orchard.push(OrchardSignedClaim {
                zkproof: proof.zkproof.clone(),
                rk: proof.rk,
                cv: proof.cv,
                cv_sha256: proof.cv_sha256,
                value: proof.value,
                airdrop_nullifier: proof.airdrop_nullifier,
                proof_hash,
                message_hash: msg_hash,
                spend_auth_sig,
            });
        }
    }

    let submission = ClaimSubmission { sapling, orchard };

    info!(
        sapling_count = submission.sapling.len(),
        orchard_count = submission.orchard.len(),
        "Claim submission signed"
    );

    Ok(submission)
}

#[cfg(test)]
mod tests {
    use zair_core::base::hash_message;

    use super::*;

    #[test]
    fn resolved_message_hashes_is_empty() {
        let input = ResolvedMessageHashes::default();
        assert!(input.is_empty());
    }

    #[test]
    fn resolved_message_hashes_shared_not_empty() {
        let hash = hash_message(b"hello");
        let input = ResolvedMessageHashes {
            shared: Some(hash),
            ..Default::default()
        };
        assert!(!input.is_empty());
        assert_eq!(input.shared, Some(hash));
    }

    #[test]
    fn resolved_message_hashes_sapling_per_proof() {
        let nullifier = Nullifier::default();
        let hash = hash_message(b"world");
        let mut sapling = BTreeMap::new();
        sapling.insert(nullifier, hash);
        let input = ResolvedMessageHashes {
            sapling,
            ..Default::default()
        };
        assert!(!input.is_empty());
        assert_eq!(input.sapling_hash(nullifier), Some(hash));
        assert_eq!(input.orchard_hash(nullifier), None);
    }

    #[test]
    fn resolved_message_hashes_orchard_per_proof() {
        let nullifier = Nullifier::default();
        let hash = hash_message(b"orchard");
        let mut orchard = BTreeMap::new();
        orchard.insert(nullifier, hash);
        let input = ResolvedMessageHashes {
            orchard,
            ..Default::default()
        };
        assert!(!input.is_empty());
        assert_eq!(input.orchard_hash(nullifier), Some(hash));
        assert_eq!(input.sapling_hash(nullifier), None);
    }

    #[test]
    fn resolved_message_hashes_per_proof_overrides_shared() {
        let nullifier = Nullifier::default();
        let shared = hash_message(b"shared");
        let per_proof = hash_message(b"per-proof");
        let mut sapling = BTreeMap::new();
        sapling.insert(nullifier, per_proof);
        let input = ResolvedMessageHashes {
            shared: Some(shared),
            sapling,
            ..Default::default()
        };
        assert_eq!(input.sapling_hash(nullifier), Some(per_proof));
    }

    #[test]
    fn resolved_message_hashes_shared_fallback() {
        let nullifier = Nullifier::default();
        let shared = hash_message(b"shared");
        let input = ResolvedMessageHashes {
            shared: Some(shared),
            ..Default::default()
        };
        assert_eq!(input.sapling_hash(nullifier), Some(shared));
        assert_eq!(input.orchard_hash(nullifier), Some(shared));
    }
}
