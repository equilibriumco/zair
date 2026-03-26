//! Claim submission signing command implementation.

use std::path::PathBuf;

use eyre::Context as _;
use secrecy::ExposeSecret;
use tracing::info;
use zair_core::schema::config::AirdropConfiguration;

use super::claim_proofs::{ClaimProofsOutput, ClaimSecretsOutput};
use super::submission_messages::resolve_message_hashes;
use crate::api::sign::sign_claim_submission_from_bytes;
use crate::seed::read_seed_file;

/// Sign claim proofs into a submission package.
///
/// # Errors
/// Returns an error if inputs are invalid, key derivation fails, or signing fails.
#[allow(clippy::too_many_arguments)]
pub async fn sign_claim_submission(
    proofs_file: PathBuf,
    secrets_file: PathBuf,
    seed_file: PathBuf,
    account_id: u32,
    airdrop_configuration_file: PathBuf,
    message_file: Option<PathBuf>,
    messages_path: Option<PathBuf>,
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

    info!(file = ?airdrop_configuration_file, "Loading airdrop configuration...");
    let config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;

    info!(file = ?seed_file, "Reading seed from file...");
    let seed = read_seed_file(&seed_file).await?;

    let resolved = resolve_message_hashes(message_file.as_ref(), messages_path.as_ref()).await?;

    let submission = sign_claim_submission_from_bytes(
        proofs,
        secrets,
        seed.expose_secret(),
        account_id,
        &config,
        &resolved,
    )
    .await
    .context("Failed to sign submission")?;

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
