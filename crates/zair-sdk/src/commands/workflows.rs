//! End-to-end workflow command orchestrators.

#[cfg(feature = "prove")]
mod prove {
    use std::path::{Path, PathBuf};

    use eyre::Context as _;
    use secrecy::ExposeSecret;
    use zair_core::schema::config::AirdropConfiguration;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zip32::AccountId;

    use super::super::{GapTreeMode, airdrop_claim, generate_claim_proofs, sign_claim_submission};
    use crate::common::to_zcash_network;
    use crate::seed::read_seed_file;

    async fn derive_ufvk_from_seed(
        seed_file: &Path,
        account_id: u32,
        airdrop_configuration_file: &Path,
    ) -> eyre::Result<String> {
        let airdrop_config: AirdropConfiguration =
            serde_json::from_str(&tokio::fs::read_to_string(airdrop_configuration_file).await?)
                .context("Failed to parse airdrop configuration JSON")?;
        let network = to_zcash_network(airdrop_config.network);

        let seed = read_seed_file(seed_file).await?;

        let account_id =
            AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account"))?;
        let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), account_id)
            .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;
        let ufvk = usk.to_unified_full_viewing_key();
        Ok(ufvk.encode(&network))
    }

    /// Run the full claim pipeline: `claim prepare -> claim prove -> claim sign`.
    ///
    /// # Errors
    /// Returns an error if any pipeline step fails.
    #[allow(
        clippy::too_many_arguments,
        clippy::similar_names,
        reason = "CLI entrypoint parameters"
    )]
    pub async fn claim_run(
        lightwalletd_url: Option<String>,
        sapling_snapshot_nullifiers: Option<PathBuf>,
        orchard_snapshot_nullifiers: Option<PathBuf>,
        sapling_gap_tree_file: Option<PathBuf>,
        orchard_gap_tree_file: Option<PathBuf>,
        gap_tree_mode: GapTreeMode,
        birthday_height: u64,
        airdrop_claims_output_file: PathBuf,
        claim_proofs_output_file: PathBuf,
        claim_secrets_output_file: PathBuf,
        claim_submission_output_file: PathBuf,
        seed_file: PathBuf,
        account_id: u32,
        proving_key_file: PathBuf,
        orchard_params_file: PathBuf,
        orchard_params_mode: super::super::OrchardParamsMode,
        message_file: Option<PathBuf>,
        messages_file: Option<PathBuf>,
        airdrop_configuration_file: PathBuf,
    ) -> eyre::Result<()> {
        let unified_full_viewing_key =
            derive_ufvk_from_seed(&seed_file, account_id, &airdrop_configuration_file).await?;

        airdrop_claim(
            lightwalletd_url,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
            sapling_gap_tree_file,
            orchard_gap_tree_file,
            gap_tree_mode,
            unified_full_viewing_key,
            birthday_height,
            airdrop_claims_output_file.clone(),
            airdrop_configuration_file.clone(),
        )
        .await?;

        generate_claim_proofs(
            airdrop_claims_output_file,
            claim_proofs_output_file.clone(),
            seed_file.clone(),
            account_id,
            proving_key_file,
            orchard_params_file,
            orchard_params_mode,
            claim_secrets_output_file.clone(),
            airdrop_configuration_file.clone(),
        )
        .await?;

        sign_claim_submission(
            claim_proofs_output_file,
            claim_secrets_output_file,
            seed_file,
            account_id,
            airdrop_configuration_file,
            message_file,
            messages_file,
            claim_submission_output_file,
        )
        .await
    }
}

mod verify {
    use std::path::PathBuf;

    use eyre::Context as _;
    use zair_core::schema::submission::ClaimSubmission;

    use super::super::claim_proofs::{
        ClaimProofsOutput, OrchardClaimProofResult, SaplingClaimProofResult,
        verify_claim_proofs_inner,
    };
    use super::super::verify_claim_submission_signature;

    /// Run full verification: `verify proof -> verify signature`.
    ///
    /// # Errors
    /// Returns an error if either verification step fails.
    #[allow(
        clippy::similar_names,
        reason = "message_file vs messages_file are distinct CLI args"
    )]
    pub async fn verify_run(
        verifying_key_file: PathBuf,
        orchard_params_file: PathBuf,
        orchard_params_mode: super::super::OrchardParamsMode,
        submission_file: PathBuf,
        message_file: Option<PathBuf>,
        messages_file: Option<PathBuf>,
        airdrop_configuration_file: PathBuf,
    ) -> eyre::Result<()> {
        verify_claim_submission_signature(
            submission_file.clone(),
            message_file,
            messages_file,
            airdrop_configuration_file.clone(),
        )
        .await?;

        let submission: ClaimSubmission =
            serde_json::from_str(&tokio::fs::read_to_string(&submission_file).await?)
                .context("Failed to parse submission JSON")?;

        let proofs = ClaimProofsOutput {
            sapling_proofs: submission
                .sapling
                .iter()
                .map(|entry| SaplingClaimProofResult {
                    zkproof: entry.zkproof,
                    rk: entry.rk,
                    cv: entry.cv,
                    cv_sha256: entry.cv_sha256,
                    value: entry.value,
                    airdrop_nullifier: entry.airdrop_nullifier,
                })
                .collect(),
            orchard_proofs: submission
                .orchard
                .iter()
                .map(|entry| OrchardClaimProofResult {
                    zkproof: entry.zkproof.clone(),
                    rk: entry.rk,
                    cv: entry.cv,
                    cv_sha256: entry.cv_sha256,
                    value: entry.value,
                    airdrop_nullifier: entry.airdrop_nullifier,
                })
                .collect(),
        };

        verify_claim_proofs_inner(
            proofs,
            verifying_key_file,
            orchard_params_file,
            orchard_params_mode,
            airdrop_configuration_file,
        )
        .await
    }
}

#[cfg(feature = "prove")]
pub use prove::claim_run;
pub use verify::verify_run;
