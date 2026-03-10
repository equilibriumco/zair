//! Claim submission signing command implementation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eyre::{Context as _, ContextCompat as _, ensure};
use secrecy::ExposeSecret;
use tracing::info;
use zair_core::base::{Pool, signature_digest};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::submission::{ClaimSubmission, OrchardSignedClaim, SaplingSignedClaim};

use super::claim_proofs::{ClaimProofsOutput, ClaimSecretsOutput};
use super::nullifier_uniqueness::ensure_unique_airdrop_nullifiers;
use super::signature_digest::{hash_orchard_proof, hash_sapling_proof};
use super::submission_auth::{orchard, sapling};
use super::submission_messages::resolve_message_hashes;
use crate::common::to_zcash_network;
use crate::seed::read_seed_file;

/// Sign claim proofs into a submission package.
///
/// # Errors
/// Returns an error if inputs are invalid, key derivation fails, or signing fails.
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names,
    reason = "CLI entrypoint parameters"
)]
pub async fn sign_claim_submission(
    proofs_file: PathBuf,
    secrets_file: PathBuf,
    seed_file: PathBuf,
    account_id: u32,
    airdrop_configuration_file: PathBuf,
    message_file: Option<PathBuf>,
    messages_file: Option<PathBuf>,
    submission_output_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?proofs_file, "Loading proofs for signing...");
    let proofs: ClaimProofsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&proofs_file).await?)
            .context("Failed to parse proofs JSON")?;

    info!(file = ?secrets_file, "Loading local secrets...");
    let secrets: ClaimSecretsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&secrets_file).await?)
            .context("Failed to parse secrets JSON")?;

    ensure!(
        !(proofs.sapling_proofs.is_empty() && proofs.orchard_proofs.is_empty()),
        "No proofs found to sign"
    );
    ensure!(
        !proofs.sapling_proofs.is_empty() || secrets.sapling.is_empty(),
        "Sapling secrets provided without Sapling proofs"
    );
    ensure!(
        !proofs.orchard_proofs.is_empty() || secrets.orchard.is_empty(),
        "Orchard secrets provided without Orchard proofs"
    );
    ensure!(
        proofs.sapling_proofs.len() == secrets.sapling.len(),
        "Proof/secret count mismatch for Sapling entries"
    );
    ensure!(
        proofs.orchard_proofs.len() == secrets.orchard.len(),
        "Proof/secret count mismatch for Orchard entries"
    );
    ensure_unique_airdrop_nullifiers(
        proofs
            .sapling_proofs
            .iter()
            .map(|proof| proof.airdrop_nullifier),
        "Sapling proof",
    )?;
    ensure_unique_airdrop_nullifiers(
        proofs
            .orchard_proofs
            .iter()
            .map(|proof| proof.airdrop_nullifier),
        "Orchard proof",
    )?;

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;

    let sapling_target_id = if proofs.sapling_proofs.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .sapling
                .as_ref()
                .context("Sapling proofs provided, but airdrop configuration has no sapling pool")?
                .target_id
                .clone(),
        )
    };
    let orchard_target_id = if proofs.orchard_proofs.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .orchard
                .as_ref()
                .context("Orchard proofs provided, but airdrop configuration has no orchard pool")?
                .target_id
                .clone(),
        )
    };

    info!(file = ?seed_file, "Reading seed from file...");
    let seed = read_seed_file(&seed_file).await?;

    let network = to_zcash_network(airdrop_config.network);
    let sapling_keys = if proofs.sapling_proofs.is_empty() {
        None
    } else {
        Some(sapling::derive_spend_auth_keys(
            network,
            seed.expose_secret(),
            account_id,
        )?)
    };
    let orchard_key = if proofs.orchard_proofs.is_empty() {
        None
    } else {
        Some(orchard::derive_spend_auth_key(
            network,
            seed.expose_secret(),
            account_id,
        )?)
    };

    let message_hashes =
        resolve_message_hashes(message_file.as_ref(), messages_file.as_ref()).await?;

    let mut sapling_secret_by_nf = BTreeMap::new();
    for secret in secrets.sapling {
        let existing = sapling_secret_by_nf.insert(secret.airdrop_nullifier, secret);
        ensure!(
            existing.is_none(),
            "Duplicate Sapling secret entry for airdrop nullifier"
        );
    }

    let mut sapling = Vec::with_capacity(proofs.sapling_proofs.len());
    for proof in &proofs.sapling_proofs {
        let secret = sapling_secret_by_nf
            .get(&proof.airdrop_nullifier)
            .context("Missing secret material for Sapling proof entry")?;
        let target_id = sapling_target_id
            .as_deref()
            .context("Sapling target_id must be present for Sapling signing")?;
        let message_hash = message_hashes
            .sapling_hash(proof.airdrop_nullifier)
            .with_context(|| {
                format!(
                    "No message provided for Sapling claim with airdrop nullifier {}. Provide --message or --messages entry",
                    proof.airdrop_nullifier
                )
            })?;
        let proof_hash = hash_sapling_proof(proof);
        let digest = signature_digest(
            Pool::Sapling,
            target_id.as_bytes(),
            &proof_hash,
            &message_hash,
        )?;

        let keys = sapling_keys
            .as_ref()
            .context("Sapling signing key should be initialized")?;
        let spend_auth_sig = sapling::sign_claim(proof, secret, keys, &digest)?;
        sapling.push(SaplingSignedClaim {
            zkproof: proof.zkproof,
            rk: proof.rk,
            cv: proof.cv,
            cv_sha256: proof.cv_sha256,
            airdrop_nullifier: proof.airdrop_nullifier,
            proof_hash,
            message_hash,
            spend_auth_sig,
        });
    }

    let mut orchard_secret_by_nf = BTreeMap::new();
    for secret in secrets.orchard {
        let existing = orchard_secret_by_nf.insert(secret.airdrop_nullifier, secret);
        ensure!(
            existing.is_none(),
            "Duplicate Orchard secret entry for airdrop nullifier"
        );
    }

    let mut orchard = Vec::with_capacity(proofs.orchard_proofs.len());
    for proof in &proofs.orchard_proofs {
        let secret = orchard_secret_by_nf
            .get(&proof.airdrop_nullifier)
            .context("Missing secret material for Orchard proof entry")?;
        let target_id = orchard_target_id
            .as_deref()
            .context("Orchard target_id must be present for Orchard signing")?;
        let message_hash = message_hashes
            .orchard_hash(proof.airdrop_nullifier)
            .with_context(|| {
                format!(
                    "No message provided for Orchard claim with airdrop nullifier {}. Provide --message or --messages entry",
                    proof.airdrop_nullifier
                )
            })?;
        let proof_hash = hash_orchard_proof(proof)?;
        let digest = signature_digest(
            Pool::Orchard,
            target_id.as_bytes(),
            &proof_hash,
            &message_hash,
        )?;

        let key = orchard_key
            .as_ref()
            .context("Orchard signing key should be initialized")?;
        let spend_auth_sig = orchard::sign_claim(proof, secret, key, &digest)?;
        orchard.push(OrchardSignedClaim {
            zkproof: proof.zkproof.clone(),
            rk: proof.rk,
            cv: proof.cv,
            cv_sha256: proof.cv_sha256,
            airdrop_nullifier: proof.airdrop_nullifier,
            proof_hash,
            message_hash,
            spend_auth_sig,
        });
    }

    let submission = ClaimSubmission { sapling, orchard };

    let json = serde_json::to_string_pretty(&submission)?;
    tokio::fs::write(&submission_output_file, json).await?;
    info!(
        file = ?submission_output_file,
        sapling_count = submission.sapling.len(),
        orchard_count = submission.orchard.len(),
        "Signed claim submission written"
    );

    Ok(())
}
