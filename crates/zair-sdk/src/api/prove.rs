//! In-memory proof generation.

use std::sync::Arc;

use thiserror::Error;
use tracing::info;
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::proof_inputs::AirdropClaimInputs;
use zair_orchard_proofs::ValueCommitmentScheme as OrchardValueCommitmentScheme;
use zair_sapling_proofs::prover::{
    ValueCommitmentScheme as SaplingValueCommitmentScheme, load_parameters_from_bytes,
};
use zcash_keys::keys::UnifiedSpendingKey;
use zip32::AccountId;

use crate::api::claims::{ClaimProofsOutput, ClaimSecretsOutput};
use crate::commands::{
    claim_matches_seed_keys, derive_sapling_proof_generation_keys,
    generate_sapling_proofs_parallel, generate_single_orchard_proof, read_params,
};
use crate::common::to_zcash_network;

/// Errors that can occur during proof generation.
#[derive(Debug, Error)]
pub enum ProveError {
    /// Returned when Sapling claims exist in the scan output but the airdrop configuration
    /// lacks a Sapling pool section.
    #[error("Sapling claims present but airdrop configuration has no sapling pool")]
    MissingSaplingPool,
    /// Returned when Orchard claims exist in the scan output but the airdrop configuration
    /// lacks an Orchard pool section.
    #[error("Orchard claims present but airdrop configuration has no orchard pool")]
    MissingOrchardPool,
    /// Returned when the seed slice is not exactly 64 bytes.
    #[error("Seed must be exactly 64 bytes, got {0}")]
    InvalidSeedLength(usize),
    /// Returned when the account index cannot be converted into a valid ZIP-32 `AccountId`.
    #[error("Invalid account ID: {0}")]
    InvalidAccountId(String),
    /// Returned when `UnifiedSpendingKey::from_seed` fails.
    #[error("Failed to derive spending key: {0}")]
    KeyDerivation(String),
    /// Returned when Sapling claims exist but no Groth16 proving key bytes were supplied.
    #[error("Sapling claims present but no proving key provided")]
    MissingSaplingProvingKey,
    /// Returned when Sapling proving/verifying key deserialization from bytes fails.
    #[error("Failed to load Sapling parameters: {0}")]
    LoadSaplingParams(String),
    /// Returned when Sapling proof generation keys cannot be derived from the seed and account
    /// index.
    #[error("Derivation of Sapling proof generation keys failed: {0}")]
    SaplingKeyDerivation(String),
    /// Returned when Sapling keys derived from the provided seed do not match the keys embedded
    /// in the claim inputs.
    #[error("Seed mismatch: seed-derived Sapling keys do not match claim inputs")]
    SaplingSeedMismatch,
    /// Returned when the number of generated Sapling proofs does not equal the number of input
    /// claims.
    #[error("Expected {0} Sapling proofs, generated {1}")]
    SaplingProofCountMismatch(usize, usize),
    /// Returned when the number of generated Sapling secrets does not equal the number of input
    /// claims.
    #[error("Expected {0} Sapling secrets, generated {1}")]
    SaplingSecretCountMismatch(usize, usize),
    /// Returned when Orchard claims exist but no Halo2 circuit parameters bytes were supplied.
    #[error("Orchard claims present but no params provided")]
    MissingOrchardParams,
    /// Returned when the Orchard target ID in the airdrop configuration exceeds 32 bytes.
    #[error("Orchard target_id must be at most 32 bytes, got {0}")]
    InvalidTargetIdLength(usize),
    /// Returned when the circuit parameter `k` in the supplied Halo2 params does not match the
    /// value commitment scheme's expected `k`.
    #[error("Orchard params `k` mismatch: expected {expected} (scheme={scheme:?}), got {actual}")]
    OrchardParamsKMismatch {
        /// Expected k value.
        expected: u32,
        /// Actual k value from params.
        actual: u32,
        /// The value commitment scheme used.
        scheme: OrchardValueCommitmentScheme,
    },
    /// Returned when Orchard Halo2 circuit parameters cannot be read or deserialized from raw
    /// bytes.
    #[error("Failed to read Orchard params: {0}")]
    ReadOrchardParams(String),
    /// Returned when the Halo2 proof generation for an Orchard claim fails.
    #[error("Failed to generate Orchard proof: {0}")]
    OrchardProofGeneration(String),
}

/// Generate claim proofs from in-memory inputs.
///
/// # Arguments
///
/// * `inputs` - claim inputs from the scan step
/// * `seed` - 64-byte BIP-39 seed
/// * `account_id` - ZIP-32 account index
/// * `sapling_proving_key` - Groth16 proving key bytes (None if no Sapling claims)
/// * `orchard_params_bytes` - Halo2 params bytes (None if no Orchard claims)
/// * `config` - airdrop configuration
///
/// # Returns
///
/// Tuple of `(proofs, secrets)`. Secrets are needed for signing.
///
/// # Errors
///
/// Returns an error if key derivation, proof generation, or verification fails.
#[allow(clippy::too_many_arguments, reason = "API entrypoint")]
#[allow(clippy::too_many_lines)]
pub async fn generate_claim_proofs_from_bytes(
    inputs: AirdropClaimInputs,
    seed: &[u8],
    account_id: u32,
    sapling_proving_key: Option<&[u8]>,
    orchard_params_bytes: Option<&[u8]>,
    config: &AirdropConfiguration,
) -> Result<(ClaimProofsOutput, ClaimSecretsOutput), ProveError> {
    let network = to_zcash_network(config.network);

    let sapling_config = if inputs.sapling_claim_input.is_empty() {
        None
    } else {
        Some(
            config
                .sapling
                .as_ref()
                .ok_or(ProveError::MissingSaplingPool)?
                .clone(),
        )
    };
    let sapling_scheme: SaplingValueCommitmentScheme = sapling_config
        .as_ref()
        .map_or(SaplingValueCommitmentScheme::Native, |s| {
            s.value_commitment_scheme.into()
        });

    let orchard_config = if inputs.orchard_claim_input.is_empty() {
        None
    } else {
        Some(
            config
                .orchard
                .as_ref()
                .ok_or(ProveError::MissingOrchardPool)?
                .clone(),
        )
    };
    let orchard_scheme: OrchardValueCommitmentScheme = orchard_config
        .as_ref()
        .map_or(OrchardValueCommitmentScheme::Native, |o| {
            o.value_commitment_scheme.into()
        });

    let seed_array: &[u8; 64] = seed
        .try_into()
        .map_err(|_| ProveError::InvalidSeedLength(seed.len()))?;

    let zip32_account =
        AccountId::try_from(account_id).map_err(|e| ProveError::InvalidAccountId(e.to_string()))?;
    let usk = UnifiedSpendingKey::from_seed(&network, seed_array, zip32_account)
        .map_err(|e| ProveError::KeyDerivation(e.to_string()))?;

    let (sapling_proofs, sapling_secrets) = if inputs.sapling_claim_input.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let pk_bytes = sapling_proving_key.ok_or(ProveError::MissingSaplingProvingKey)?;

        info!("Loading Sapling parameters from bytes...");
        let params = tokio::task::spawn_blocking({
            let pk_bytes = pk_bytes.to_vec();
            move || load_parameters_from_bytes(&pk_bytes, false)
        })
        .await
        .map_err(|e| ProveError::LoadSaplingParams(e.to_string()))?
        .map_err(|e| ProveError::LoadSaplingParams(e.to_string()))?;
        let pvk = params.prepared_verifying_key();
        info!("Sapling parameters ready");

        info!("Deriving Sapling proof generation keys...");
        let keys = derive_sapling_proof_generation_keys(network, seed_array, account_id)
            .map_err(|e| ProveError::SaplingKeyDerivation(e.to_string()))?;
        info!("Derived Sapling proof generation keys (external + internal)");

        if inputs
            .sapling_claim_input
            .iter()
            .any(|claim| !claim_matches_seed_keys(claim, &keys))
        {
            return Err(ProveError::SaplingSeedMismatch);
        }

        let expected_sapling_count = inputs.sapling_claim_input.len();
        let (sapling_proofs, sapling_secrets) = generate_sapling_proofs_parallel(
            inputs.sapling_claim_input.clone(),
            Arc::new(params),
            Arc::new(pvk),
            Arc::new(keys),
            sapling_config
                .as_ref()
                .map_or([0_u8; 32], |s| s.note_commitment_root),
            sapling_config
                .as_ref()
                .map_or([0_u8; 32], |s| s.nullifier_gap_root),
            sapling_scheme,
        )
        .await
        .map_err(|e| ProveError::LoadSaplingParams(e.to_string()))?;

        if sapling_proofs.len() != expected_sapling_count {
            return Err(ProveError::SaplingProofCountMismatch(
                expected_sapling_count,
                sapling_proofs.len(),
            ));
        }
        if sapling_secrets.len() != expected_sapling_count {
            return Err(ProveError::SaplingSecretCountMismatch(
                expected_sapling_count,
                sapling_secrets.len(),
            ));
        }
        (sapling_proofs, sapling_secrets)
    };

    let mut orchard_proofs = Vec::with_capacity(inputs.orchard_claim_input.len());
    let mut orchard_secrets = Vec::with_capacity(inputs.orchard_claim_input.len());
    if let Some(orchard) = orchard_config {
        let params_bytes = orchard_params_bytes.ok_or(ProveError::MissingOrchardParams)?;

        if orchard.target_id.len() > 32 {
            return Err(ProveError::InvalidTargetIdLength(orchard.target_id.len()));
        }

        let expected_k = zair_orchard_proofs::k_for_scheme(orchard_scheme);
        let params = tokio::task::spawn_blocking({
            let params_bytes = params_bytes.to_vec();
            move || read_params(params_bytes)
        })
        .await
        .map_err(|e| ProveError::ReadOrchardParams(e.to_string()))?
        .map_err(|e| ProveError::ReadOrchardParams(e.to_string()))?;

        if params.k() != expected_k {
            return Err(ProveError::OrchardParamsKMismatch {
                expected: expected_k,
                actual: params.k(),
                scheme: orchard_scheme,
            });
        }

        for claim_input in &inputs.orchard_claim_input {
            let (proof, secret) = generate_single_orchard_proof(
                &params,
                claim_input,
                &usk,
                orchard.note_commitment_root,
                orchard.nullifier_gap_root,
                &orchard.target_id,
                orchard_scheme,
            )
            .map_err(|e| ProveError::OrchardProofGeneration(e.to_string()))?;
            orchard_proofs.push(proof);
            orchard_secrets.push(secret);
        }
    }

    let proofs = ClaimProofsOutput {
        sapling_proofs,
        orchard_proofs,
    };
    let secrets = ClaimSecretsOutput {
        sapling: sapling_secrets,
        orchard: orchard_secrets,
    };

    Ok((proofs, secrets))
}
