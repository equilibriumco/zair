//! Generate claim proofs using the custom claim circuit.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bellman::groth16::PreparedVerifyingKey;
use bls12_381::Bls12;
use eyre::{Context as _, ContextCompat as _, ensure};
use group::GroupEncoding as _;
use group::ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use halo2_proofs::poly::commitment::Params;
use orchard::keys::{
    FullViewingKey as OrchardFullViewingKey, SpendAuthorizingKey, SpendValidatingKey,
};
use orchard::value::ValueCommitTrapdoor as OrchardValueCommitTrapdoor;
use pasta_curves::{pallas, vesta};
use secrecy::ExposeSecret;
use tracing::info;
use zair_core::base::Nullifier;
use zair_core::schema::config::{AirdropConfiguration, ValueCommitmentScheme};
use zair_core::schema::proof_inputs::{
    AirdropClaimInputs, ClaimInput, OrchardPrivateInputs, SaplingPrivateInputs, SerializableScope,
};
use zair_orchard_proofs::{
    ClaimProofInputs as OrchardClaimProofInputs,
    ValueCommitmentScheme as OrchardValueCommitmentScheme,
    generate_claim_proof as generate_orchard_claim_proof,
    verify_claim_proof_output as verify_orchard_claim_proof_output,
};
use zair_sapling_proofs::prover::{
    ClaimParameters, ClaimProofInputs, ValueCommitmentScheme as SaplingValueCommitmentScheme,
    generate_claim_proof, generate_parameters, load_parameters, save_parameters,
};
use zair_sapling_proofs::verifier::{ClaimProofOutput, verify_claim_proof_output};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zcash_spec::PrfExpand;
use zip32::AccountId;

use super::claim_proofs::{
    ClaimProofsOutput, ClaimSecretsOutput, OrchardClaimProofResult, OrchardClaimSecretResult,
    SaplingClaimProofResult, SaplingClaimSecretResult,
};
use super::orchard_params::{OrchardParamsMode, load_or_prepare_orchard_params};
use super::sensitive_output::write_sensitive_output;
use crate::common::to_zcash_network;
use crate::seed::read_seed_file;

/// Maximum number of concurrent outer Sapling proving tasks.
///
/// Sapling proving already uses multicore internals (rayon via bellman), so the
/// outer task fan-out is intentionally conservative to avoid oversubscription.
const MAX_SAPLING_PROVING_TASKS: usize = 2;

fn sapling_proving_task_limit() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_SAPLING_PROVING_TASKS)
}

fn setup_targets(
    proving_key_file: &Path,
    verifying_key_file: &Path,
    scheme: ValueCommitmentScheme,
) -> Vec<(SaplingValueCommitmentScheme, PathBuf, PathBuf)> {
    vec![(
        SaplingValueCommitmentScheme::from(scheme),
        proving_key_file.to_path_buf(),
        verifying_key_file.to_path_buf(),
    )]
}

/// Generate or load the claim circuit parameters with custom paths.
async fn load_params(proving_key_path: PathBuf) -> eyre::Result<ClaimParameters> {
    ensure!(
        tokio::fs::try_exists(&proving_key_path).await?,
        "Proving key not found at {}. Run `zair setup sapling --scheme native` or `zair setup sapling --scheme sha256` with matching output paths first.",
        proving_key_path.display(),
    );

    info!("Loading existing claim circuit parameters (this may take a moment)...");
    let params = tokio::task::spawn_blocking(move || load_parameters(&proving_key_path, false))
        .await?
        .context("Failed to load parameters")?;
    info!("Parameters loaded successfully");

    Ok(params)
}

/// Generate claim circuit parameters (proving and verifying keys).
///
/// # Arguments
///
/// * `proving_key_file` - Path to write the proving key
/// * `verifying_key_file` - Path to write the verifying key
///
/// # Errors
/// Returns an error if parameter generation or file I/O fails.
pub async fn generate_claim_params(
    proving_key_file: PathBuf,
    verifying_key_file: PathBuf,
    scheme: ValueCommitmentScheme,
) -> eyre::Result<()> {
    info!("Generating claim circuit parameters...");
    info!("This creates Groth16 proving and verifying keys for the Sapling claim circuit.");

    let targets = setup_targets(&proving_key_file, &verifying_key_file, scheme);
    for (scheme, proving_key_path, verifying_key_path) in targets {
        info!(
            scheme = ?scheme,
            proving_key = %proving_key_path.display(),
            verifying_key = %verifying_key_path.display(),
            "Generating parameter set"
        );

        let params = tokio::task::spawn_blocking(move || generate_parameters(scheme))
            .await?
            .map_err(|e| eyre::eyre!("Parameter generation failed for {:?}: {e}", scheme))?;

        tokio::task::spawn_blocking({
            let proving_key_path = proving_key_path.clone();
            let verifying_key_path = verifying_key_path.clone();
            move || save_parameters(&params, &proving_key_path, &verifying_key_path)
        })
        .await?
        .context("Failed to save parameters")?;

        let proving_size = tokio::fs::metadata(&proving_key_path).await?.len();
        let verifying_size = tokio::fs::metadata(&verifying_key_path).await?.len();

        info!(
            scheme = ?scheme,
            proving_key = %proving_key_path.display(),
            proving_size_kb = proving_size / 1024,
            verifying_key = %verifying_key_path.display(),
            verifying_size_kb = verifying_size / 1024,
            "Parameter set generated successfully"
        );
    }

    Ok(())
}

/// Sapling proof generation keys for both external and internal scopes.
pub struct SaplingProofGenerationKeys {
    external: sapling::ProofGenerationKey,
    internal: sapling::ProofGenerationKey,
}

/// Derive Sapling proof generation keys from a seed.
pub fn derive_sapling_proof_generation_keys(
    network: Network,
    seed: &[u8; 64],
    account_id: u32,
) -> eyre::Result<SaplingProofGenerationKeys> {
    let account_id =
        AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account-id"))?;

    let usk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    let extsk = usk.sapling();
    Ok(SaplingProofGenerationKeys {
        external: extsk.expsk.proof_generation_key(),
        internal: extsk.derive_internal().expsk.proof_generation_key(),
    })
}

/// Returns true when claim key material matches seed-derived key material for its scope.
#[allow(clippy::similar_names)]
pub fn claim_matches_seed_keys(
    claim_input: &ClaimInput<SaplingPrivateInputs>,
    keys: &SaplingProofGenerationKeys,
) -> bool {
    let proof_generation_key = match claim_input.private_inputs.scope {
        SerializableScope::External => &keys.external,
        SerializableScope::Internal => &keys.internal,
    };

    let seed_ak = proof_generation_key.ak.to_bytes();
    let seed_nk = proof_generation_key.to_viewing_key().nk.0.to_bytes();

    claim_input.private_inputs.ak == seed_ak && claim_input.private_inputs.nk == seed_nk
}

/// Generate and verify a single Sapling claim proof.
fn generate_single_sapling_proof(
    claim_input: &ClaimInput<SaplingPrivateInputs>,
    params: &ClaimParameters,
    pvk: &PreparedVerifyingKey<Bls12>,
    keys: &SaplingProofGenerationKeys,
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: SaplingValueCommitmentScheme,
) -> eyre::Result<(SaplingClaimProofResult, SaplingClaimSecretResult)> {
    info!(
        value = claim_input.private_inputs.value,
        "Generating claim proof..."
    );

    let mut rng = rand_core::OsRng;

    let proof_generation_key = match claim_input.private_inputs.scope {
        SerializableScope::External => keys.external.clone(),
        SerializableScope::Internal => keys.internal.clone(),
    };

    // Caller-generated witness randomness (Sapling-style).
    let alpha = jubjub::Fr::random(&mut rng);
    let alpha_bytes = alpha.to_repr();

    let rcv = sapling::value::ValueCommitTrapdoor::random(&mut rng);
    let rcv_bytes = rcv.inner().to_repr();

    let rcv_sha256 = match value_commitment_scheme {
        SaplingValueCommitmentScheme::Native => None,
        SaplingValueCommitmentScheme::Sha256 => {
            let mut rcv_sha256 = [0_u8; 32];
            rand_core::RngCore::fill_bytes(&mut rng, &mut rcv_sha256);
            Some(rcv_sha256)
        }
    };

    let airdrop_nullifier: [u8; 32] = claim_input.public_inputs.airdrop_nullifier.into();
    let claim_inputs = to_claim_proof_inputs(
        &claim_input.private_inputs,
        airdrop_nullifier,
        note_commitment_root,
        nullifier_gap_root,
        value_commitment_scheme,
        alpha_bytes,
        rcv_bytes,
        rcv_sha256,
    );

    let proof_output = generate_claim_proof(params, &claim_inputs, &proof_generation_key)
        .map_err(|e| eyre::eyre!("Failed to generate Sapling proof: {e}"))?;

    verify_claim_proof_output(
        &proof_output,
        pvk,
        value_commitment_scheme,
        &note_commitment_root,
        &nullifier_gap_root,
    )
    .map_err(|e| eyre::eyre!("Generated Sapling proof failed self-verification: {e}"))?;

    info!("Proof generated and verified successfully");
    Ok((
        to_proof_result(&proof_output, claim_input.public_inputs.airdrop_nullifier),
        SaplingClaimSecretResult {
            airdrop_nullifier: claim_input.public_inputs.airdrop_nullifier,
            alpha: alpha_bytes,
            rcv: match value_commitment_scheme {
                SaplingValueCommitmentScheme::Native => Some(rcv_bytes),
                SaplingValueCommitmentScheme::Sha256 => None,
            },
            rcv_sha256,
        },
    ))
}

/// Generate Sapling proofs in parallel using tokio's blocking thread pool.
pub async fn generate_sapling_proofs_parallel(
    sapling_inputs: Vec<ClaimInput<SaplingPrivateInputs>>,
    params: Arc<ClaimParameters>,
    pvk: Arc<PreparedVerifyingKey<Bls12>>,
    keys: Arc<SaplingProofGenerationKeys>,
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: SaplingValueCommitmentScheme,
) -> eyre::Result<(Vec<SaplingClaimProofResult>, Vec<SaplingClaimSecretResult>)> {
    let mut join_set = tokio::task::JoinSet::new();
    let task_limit = sapling_proving_task_limit();
    let mut pending_inputs = sapling_inputs.into_iter();

    for _ in 0..task_limit {
        let Some(claim_input) = pending_inputs.next() else {
            break;
        };
        let params = Arc::clone(&params);
        let pvk = Arc::clone(&pvk);
        let keys = Arc::clone(&keys);

        join_set.spawn_blocking(move || {
            generate_single_sapling_proof(
                &claim_input,
                &params,
                &pvk,
                &keys,
                note_commitment_root,
                nullifier_gap_root,
                value_commitment_scheme,
            )
        });
    }

    let mut proofs = Vec::new();
    let mut secrets = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok((proof, secret))) => {
                proofs.push(proof);
                secrets.push(secret);
            }
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(eyre::eyre!("Sapling proving task failed: {e}")),
        }

        if let Some(claim_input) = pending_inputs.next() {
            let params = Arc::clone(&params);
            let pvk = Arc::clone(&pvk);
            let keys = Arc::clone(&keys);

            join_set.spawn_blocking(move || {
                generate_single_sapling_proof(
                    &claim_input,
                    &params,
                    &pvk,
                    &keys,
                    note_commitment_root,
                    nullifier_gap_root,
                    value_commitment_scheme,
                )
            });
        }
    }
    Ok((proofs, secrets))
}

fn vec_to_orchard_depth_array(
    path: &[[u8; 32]],
) -> eyre::Result<[[u8; 32]; orchard::NOTE_COMMITMENT_TREE_DEPTH]> {
    ensure!(
        path.len() == orchard::NOTE_COMMITMENT_TREE_DEPTH,
        "Expected Orchard Merkle path length {}, got {}",
        orchard::NOTE_COMMITMENT_TREE_DEPTH,
        path.len()
    );
    path.to_owned()
        .try_into()
        .map_err(|_| eyre::eyre!("Failed to convert Orchard merkle path to fixed array"))
}

fn derive_orchard_key_material_bytes(
    usk: &UnifiedSpendingKey,
    scope: SerializableScope,
) -> eyre::Result<([u8; 32], [u8; 32], [u8; 32])> {
    let sk = usk.orchard();
    let fvk: OrchardFullViewingKey = sk.into();
    let fvk_bytes = fvk.to_bytes();

    let ak: [u8; 32] = fvk_bytes
        .get(0..32)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| eyre::eyre!("Invalid Orchard FVK encoding (ak)"))?;
    let nk: [u8; 32] = fvk_bytes
        .get(32..64)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| eyre::eyre!("Invalid Orchard FVK encoding (nk)"))?;
    let rivk_external: [u8; 32] = fvk_bytes
        .get(64..96)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| eyre::eyre!("Invalid Orchard FVK encoding (rivk)"))?;

    let rivk = match scope {
        SerializableScope::External => rivk_external,
        SerializableScope::Internal => {
            let prf_out = PrfExpand::ORCHARD_RIVK_INTERNAL.with(&rivk_external, &ak, &nk);
            pallas::Scalar::from_uniform_bytes(&prf_out).to_repr()
        }
    };

    Ok((ak, nk, rivk))
}

fn orchard_target_id_bytes(target_id: &str) -> eyre::Result<([u8; 32], u8)> {
    ensure!(
        target_id.len() <= 32,
        "Orchard target_id must be at most 32 bytes"
    );
    let mut bytes = [0_u8; 32];
    let prefix = bytes
        .get_mut(..target_id.len())
        .context("Orchard target_id length exceeds byte buffer")?;
    prefix.copy_from_slice(target_id.as_bytes());
    let len = u8::try_from(target_id.len())
        .map_err(|_| eyre::eyre!("Orchard target_id length does not fit in u8"))?;
    Ok((bytes, len))
}

#[allow(
    clippy::too_many_lines,
    reason = "Per-claim Orchard proving needs explicit material"
)]
pub fn generate_single_orchard_proof(
    params: &Params<vesta::Affine>,
    claim_input: &ClaimInput<OrchardPrivateInputs>,
    usk: &UnifiedSpendingKey,
    orchard_note_root: [u8; 32],
    orchard_gap_root: [u8; 32],
    orchard_target_id: &str,
    orchard_scheme: OrchardValueCommitmentScheme,
) -> eyre::Result<(OrchardClaimProofResult, OrchardClaimSecretResult)> {
    let mut rng = rand_core::OsRng;
    let alpha = pallas::Scalar::random(&mut rng);
    let alpha_bytes = alpha.to_repr();

    let rcv_bytes = loop {
        let mut b = [0_u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut b);
        if Option::<OrchardValueCommitTrapdoor>::from(OrchardValueCommitTrapdoor::from_bytes(b))
            .is_some()
        {
            break b;
        }
    };

    let ask = SpendAuthorizingKey::from(usk.orchard());
    let ak = SpendValidatingKey::from(&ask);
    let ak_p_bytes = pallas::Point::from(&ak).to_bytes();

    let rcv_sha256 = match orchard_scheme {
        OrchardValueCommitmentScheme::Native => None,
        OrchardValueCommitmentScheme::Sha256 => {
            let mut bytes = [0_u8; 32];
            rand_core::RngCore::fill_bytes(&mut rng, &mut bytes);
            Some(bytes)
        }
    };

    let cm_merkle_path =
        vec_to_orchard_depth_array(&claim_input.private_inputs.note_commitment_merkle_path)?;
    let nf_merkle_path =
        vec_to_orchard_depth_array(&claim_input.private_inputs.nullifier_gap_merkle_path)?;
    let cm_note_position = u32::try_from(claim_input.private_inputs.note_commitment_position)
        .map_err(|_| eyre::eyre!("Orchard note position does not fit in u32"))?;
    let nf_leaf_position = u32::try_from(claim_input.private_inputs.nullifier_gap_position)
        .map_err(|_| eyre::eyre!("Orchard non-membership leaf position does not fit in u32"))?;
    let (_ak_bytes, nk_bytes, rivk_bytes) =
        derive_orchard_key_material_bytes(usk, claim_input.private_inputs.scope)?;

    let (target_id, target_id_len) = orchard_target_id_bytes(orchard_target_id)?;

    let inputs = OrchardClaimProofInputs {
        target_id,
        target_id_len,
        airdrop_nullifier: claim_input.public_inputs.airdrop_nullifier.into(),
        note_commitment_root: orchard_note_root,
        nullifier_gap_root: orchard_gap_root,
        value_commitment_scheme: orchard_scheme,
        rcv_sha256,
        rho: claim_input.private_inputs.rho,
        rseed: claim_input.private_inputs.rseed,
        g_d: claim_input.private_inputs.g_d,
        pk_d: claim_input.private_inputs.pk_d,
        value: claim_input.private_inputs.value,
        cm_note_position,
        cm_merkle_path,
        alpha: alpha_bytes,
        ak_p: ak_p_bytes,
        nk: nk_bytes,
        rivk: rivk_bytes,
        rcv: rcv_bytes,
        left: claim_input.private_inputs.nullifier_gap_left_bound.into(),
        right: claim_input.private_inputs.nullifier_gap_right_bound.into(),
        nf_leaf_position,
        nf_merkle_path,
    };

    let proof_output = generate_orchard_claim_proof(params, &inputs)?;
    let target_id_slice = target_id
        .get(..usize::from(target_id_len))
        .context("Orchard target_id length exceeds padded target_id buffer")?;
    verify_orchard_claim_proof_output(
        params,
        &proof_output,
        orchard_note_root,
        orchard_gap_root,
        orchard_scheme,
        target_id_slice,
    )
    .map_err(|e| eyre::eyre!("Generated Orchard proof failed self-verification: {e}"))?;

    let proof = OrchardClaimProofResult {
        zkproof: proof_output.zkproof,
        rk: proof_output.rk,
        cv: proof_output.cv,
        cv_sha256: proof_output.cv_sha256,
        airdrop_nullifier: claim_input.public_inputs.airdrop_nullifier,
    };
    let secret = OrchardClaimSecretResult {
        airdrop_nullifier: claim_input.public_inputs.airdrop_nullifier,
        alpha: alpha_bytes,
        rcv: match orchard_scheme {
            OrchardValueCommitmentScheme::Native => Some(rcv_bytes),
            OrchardValueCommitmentScheme::Sha256 => None,
        },
        rcv_sha256,
    };
    Ok((proof, secret))
}

/// Generate claim proofs using the custom claim circuit.
///
/// # Arguments
///
/// * `claim_inputs_file` - Path to JSON file containing claim inputs (from `AirdropClaim`)
/// * `proofs_output_file` - Path to write generated proofs
/// * `seed_file` - Path to file containing 64-byte seed as hex string for deriving spending keys
/// * `account_id` - ZIP-32 account index used to derive Sapling keys from the seed
/// * `proving_key_file` - Path to proving key
/// * `orchard_params_file` - Path to the Orchard Halo2 params file
/// * `secrets_output_file` - Path to local-only secrets output file
/// * `airdrop_configuration_file` - Path to airdrop configuration JSON
///
/// # Errors
/// Returns an error if file I/O, parsing, key derivation, or proof generation fails.
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "Public SDK entrypoints, parameters map to CLI arguments"
)]
pub async fn generate_claim_proofs(
    claim_inputs_file: PathBuf,
    proofs_output_file: PathBuf,
    seed_file: PathBuf,
    account_id: u32,
    proving_key_file: PathBuf,
    orchard_params_file: PathBuf,
    orchard_params_mode: OrchardParamsMode,
    secrets_output_file: PathBuf,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?claim_inputs_file, "Reading claim inputs...");
    let inputs: AirdropClaimInputs =
        serde_json::from_str(&tokio::fs::read_to_string(&claim_inputs_file).await?)?;

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;

    let network = to_zcash_network(airdrop_config.network);
    let sapling_config = if inputs.sapling_claim_input.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .sapling
                .as_ref()
                .context("Sapling claims present but airdrop configuration has no sapling pool")?,
        )
    };
    let sapling_scheme = sapling_config.map_or(SaplingValueCommitmentScheme::Native, |s| {
        s.value_commitment_scheme.into()
    });
    let orchard_config = if inputs.orchard_claim_input.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .orchard
                .as_ref()
                .context("Orchard claims present but airdrop configuration has no orchard pool")?,
        )
    };
    let orchard_scheme = orchard_config.map_or(OrchardValueCommitmentScheme::Native, |o| {
        o.value_commitment_scheme.into()
    });

    info!(file = ?seed_file, "Reading seed from file...");
    let seed = read_seed_file(&seed_file).await?;
    let zip32_account =
        AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account-id"))?;
    let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), zip32_account)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    info!("Deriving spending keys...");
    let keys = derive_sapling_proof_generation_keys(network, seed.expose_secret(), account_id)?;
    info!("Derived Sapling proof generation keys (external + internal)");

    ensure!(
        inputs
            .sapling_claim_input
            .iter()
            .all(|claim| claim_matches_seed_keys(claim, &keys)),
        "Seed mismatch: seed-derived Sapling keys do not match claim file"
    );

    let (sapling_proofs, sapling_secrets) = if inputs.sapling_claim_input.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let params = load_params(proving_key_file).await?;
        let pvk = params.prepared_verifying_key();
        info!("Sapling parameters ready");

        let expected_sapling_count = inputs.sapling_claim_input.len();
        let (sapling_proofs, sapling_secrets) = generate_sapling_proofs_parallel(
            inputs.sapling_claim_input.clone(),
            Arc::new(params),
            Arc::new(pvk),
            Arc::new(keys),
            sapling_config.map_or([0_u8; 32], |s| s.note_commitment_root),
            sapling_config.map_or([0_u8; 32], |s| s.nullifier_gap_root),
            sapling_scheme,
        )
        .await?;

        ensure!(
            sapling_proofs.len() == expected_sapling_count,
            "Expected {expected_sapling_count} Sapling proofs, generated {}",
            sapling_proofs.len()
        );
        ensure!(
            sapling_secrets.len() == expected_sapling_count,
            "Expected {expected_sapling_count} Sapling secrets, generated {}",
            sapling_secrets.len()
        );
        (sapling_proofs, sapling_secrets)
    };

    info!(
        sapling_count = inputs.sapling_claim_input.len(),
        orchard_count = inputs.orchard_claim_input.len(),
        "Loaded claim inputs"
    );

    let mut orchard_proofs = Vec::with_capacity(inputs.orchard_claim_input.len());
    let mut orchard_secrets = Vec::with_capacity(inputs.orchard_claim_input.len());
    if let Some(orchard) = orchard_config {
        ensure!(
            orchard.target_id.len() <= 32,
            "Orchard target_id must be at most 32 bytes"
        );
        let params = load_or_prepare_orchard_params(
            orchard_params_file,
            orchard_scheme,
            orchard_params_mode,
        )
        .await?;
        for claim_input in &inputs.orchard_claim_input {
            let (proof, secret) = generate_single_orchard_proof(
                params.as_ref(),
                claim_input,
                &usk,
                orchard.note_commitment_root,
                orchard.nullifier_gap_root,
                &orchard.target_id,
                orchard_scheme,
            )?;
            orchard_proofs.push(proof);
            orchard_secrets.push(secret);
        }
    }

    let output = ClaimProofsOutput {
        sapling_proofs,
        orchard_proofs,
    };

    let json = serde_json::to_string_pretty(&output)?;
    tokio::fs::write(&proofs_output_file, json).await?;

    info!(
        file = ?proofs_output_file,
        sapling_count = output.sapling_proofs.len(),
        orchard_count = output.orchard_proofs.len(),
        "Claim proofs written"
    );

    let secrets = ClaimSecretsOutput {
        sapling: sapling_secrets,
        orchard: orchard_secrets,
    };
    let secrets_json = serde_json::to_string_pretty(&secrets)?;
    write_sensitive_output(&secrets_output_file, &secrets_json).await?;
    info!(file = ?secrets_output_file, "Claim secrets written");

    Ok(())
}

/// Convert `SaplingPrivateInputs` to `ClaimProofInputs`.
#[allow(
    clippy::too_many_arguments,
    reason = "Witness assembly requires all inputs"
)]
fn to_claim_proof_inputs(
    private: &SaplingPrivateInputs,
    airdrop_nullifier: [u8; 32],
    note_commitment_root: [u8; 32],
    nullifier_gap_root: [u8; 32],
    value_commitment_scheme: SaplingValueCommitmentScheme,
    alpha: [u8; 32],
    rcv: [u8; 32],
    rcv_sha256: Option<[u8; 32]>,
) -> ClaimProofInputs {
    // Convert the non-membership merkle path from Vec<[u8; 32]> to Vec<([u8; 32], bool)>
    // The bool indicates if the current node is on the right side
    let nm_merkle_path: Vec<([u8; 32], bool)> = private
        .nullifier_gap_merkle_path
        .iter()
        .enumerate()
        .map(|(i, sibling)| {
            let is_right = (private.nullifier_gap_position >> i) & 1 == 1;
            (*sibling, is_right)
        })
        .collect();

    ClaimProofInputs {
        diversifier: private.diversifier,
        pk_d: private.pk_d,
        value: private.value,
        rcm: private.rcm,
        position: private.note_commitment_position,
        merkle_path: private.note_commitment_merkle_path.clone(),
        note_commitment_root,
        airdrop_nullifier,
        nm_left_nf: private.nullifier_gap_left_bound.into(),
        nm_right_nf: private.nullifier_gap_right_bound.into(),
        nm_merkle_path,
        nullifier_gap_root,
        value_commitment_scheme,
        alpha,
        rcv,
        rcv_sha256,
    }
}

/// Convert `ClaimProofOutput` to `SaplingClaimProofResult`.
const fn to_proof_result(
    output: &ClaimProofOutput,
    airdrop_nullifier: Nullifier,
) -> SaplingClaimProofResult {
    SaplingClaimProofResult {
        zkproof: output.zkproof,
        rk: output.rk,
        cv: output.cv,
        cv_sha256: output.cv_sha256,
        airdrop_nullifier,
    }
}

// Sapling secrets are generated in the SDK and written directly.
