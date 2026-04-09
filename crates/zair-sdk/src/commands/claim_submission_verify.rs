//! Claim submission signature verification command implementation.

use std::path::PathBuf;

use eyre::{Context as _, ContextCompat as _, ensure};
use tracing::{info, warn};
use zair_core::base::{Pool, signature_digest};
use zair_core::schema::config::AirdropConfiguration;
use zair_core::schema::submission::ClaimSubmission;

use super::nullifier_uniqueness::ensure_unique_airdrop_nullifiers;
use super::signature_digest::hash_sapling_signed_claim_proof;
use super::submission_messages::resolve_message_hashes;
use crate::commands::signature_digest::hash_orchard_signed_claim_proof;

/// Verify spend-auth signatures in a submission package.
///
/// # Errors
/// Returns an error if parsing fails, digest mismatches are found, config-binding checks fail,
/// or any signature is invalid.
#[allow(
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "Verification entrypoint intentionally keeps all pool/message checks in one flow"
)]
pub async fn verify_claim_submission_signature(
    submission_file: PathBuf,
    message_file: Option<PathBuf>,
    messages_file: Option<PathBuf>,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?submission_file, "Loading signed submission...");
    let submission: ClaimSubmission =
        serde_json::from_str(&tokio::fs::read_to_string(&submission_file).await?)
            .context("Failed to parse submission JSON")?;

    ensure!(
        !(submission.sapling.is_empty() && submission.orchard.is_empty()),
        "Submission contains no signed claims"
    );
    ensure_unique_airdrop_nullifiers(
        submission
            .sapling
            .iter()
            .map(|entry| entry.airdrop_nullifier),
        "Sapling signed claim",
    )?;
    ensure_unique_airdrop_nullifiers(
        submission
            .orchard
            .iter()
            .map(|entry| entry.airdrop_nullifier),
        "Orchard signed claim",
    )?;

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;
    let sapling_target_id = if submission.sapling.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .sapling
                .as_ref()
                .context(
                    "Sapling signed claims provided, but airdrop configuration has no sapling pool",
                )?
                .target_id
                .clone(),
        )
    };
    let orchard_target_id = if submission.orchard.is_empty() {
        None
    } else {
        Some(
            airdrop_config
                .orchard
                .as_ref()
                .context(
                    "Orchard signed claims provided, but airdrop configuration has no orchard pool",
                )?
                .target_id
                .clone(),
        )
    };

    let message_hashes =
        resolve_message_hashes(message_file.as_ref(), messages_file.as_ref()).await?;

    let mut invalid_count = 0_usize;

    for (idx, entry) in submission.sapling.iter().enumerate() {
        let expected_proof_hash = hash_sapling_signed_claim_proof(entry);
        ensure!(
            expected_proof_hash == entry.proof_hash,
            "Sapling proof hash mismatch at index {idx}"
        );

        let expected_message_hash = message_hashes
            .sapling_hash(entry.airdrop_nullifier)
            .with_context(|| {
                format!(
                    "No message provided for Sapling claim with airdrop nullifier {}. Provide --message or --messages entry",
                    entry.airdrop_nullifier
                )
            })?;
        ensure!(
            expected_message_hash == entry.message_hash,
            "Sapling message hash mismatch at index {idx}"
        );

        let target_id = sapling_target_id
            .as_deref()
            .context("Sapling target_id must be present for Sapling signature verification")?;
        let digest = signature_digest(
            Pool::Sapling,
            target_id.as_bytes(),
            &entry.proof_hash,
            &entry.message_hash,
        )?;

        let is_valid =
            zair_sapling_proofs::verify_signature(entry.rk, entry.spend_auth_sig, &digest)
                .with_context(|| format!("Invalid Sapling signature encoding at index {idx}"))
                .is_ok();
        if is_valid {
            info!(
                index = idx,
                airdrop_nullifier = %entry.airdrop_nullifier,
                "Sapling signature VALID"
            );
        } else {
            invalid_count = invalid_count.saturating_add(1);
            warn!(
                index = idx,
                airdrop_nullifier = %entry.airdrop_nullifier,
                "Sapling signature INVALID"
            );
        }
    }

    for (idx, entry) in submission.orchard.iter().enumerate() {
        let expected_proof_hash = hash_orchard_signed_claim_proof(entry)?;
        ensure!(
            expected_proof_hash == entry.proof_hash,
            "Orchard proof hash mismatch at index {idx}"
        );

        let expected_message_hash = message_hashes
            .orchard_hash(entry.airdrop_nullifier)
            .with_context(|| {
                format!(
                    "No message provided for Orchard claim with airdrop nullifier {}. Provide --message or --messages entry",
                    entry.airdrop_nullifier
                )
            })?;
        ensure!(
            expected_message_hash == entry.message_hash,
            "Orchard message hash mismatch at index {idx}"
        );

        let target_id = orchard_target_id
            .as_deref()
            .context("Orchard target_id must be present for Orchard signature verification")?;
        let digest = signature_digest(
            Pool::Orchard,
            target_id.as_bytes(),
            &entry.proof_hash,
            &entry.message_hash,
        )?;

        let is_valid =
            zair_orchard_proofs::verify_signature(entry.rk, entry.spend_auth_sig, &digest)
                .with_context(|| format!("Invalid Orchard signature encoding at index {idx}"))
                .is_ok();
        if is_valid {
            info!(
                index = idx,
                airdrop_nullifier = %entry.airdrop_nullifier,
                "Orchard signature VALID"
            );
        } else {
            invalid_count = invalid_count.saturating_add(1);
            warn!(
                index = idx,
                airdrop_nullifier = %entry.airdrop_nullifier,
                "Orchard signature INVALID"
            );
        }
    }

    ensure!(
        invalid_count == 0,
        "{invalid_count} submission signatures failed verification"
    );

    info!(
        sapling_count = submission.sapling.len(),
        orchard_count = submission.orchard.len(),
        "All submission signatures are VALID"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde::Serialize;
    use tempfile::tempdir;
    use zair_core::base::{Nullifier, hash_message};
    use zair_core::schema::config::{
        AirdropConfiguration, AirdropNetwork, SaplingSnapshot, ValueCommitmentScheme,
    };
    use zair_core::schema::submission::{ClaimSubmission, OrchardSignedClaim, SaplingSignedClaim};

    use super::*;
    use crate::commands::signature_digest::hash_sapling_signed_claim_proof;

    fn write_json<T: Serialize>(path: &Path, value: &T) {
        let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
        std::fs::write(path, bytes).expect("write json file");
    }

    fn sapling_config() -> AirdropConfiguration {
        AirdropConfiguration {
            network: AirdropNetwork::Testnet,
            snapshot_height: 1,
            sapling: Some(SaplingSnapshot {
                note_commitment_root: [0_u8; 32],
                nullifier_gap_root: [0_u8; 32],
                target_id: "ZAIRTEST".to_owned(),
                value_commitment_scheme: ValueCommitmentScheme::Native,
            }),
            orchard: None,
        }
    }

    fn sample_sapling_claim() -> SaplingSignedClaim {
        let mut claim = SaplingSignedClaim {
            zkproof: [11_u8; 192],
            rk: [22_u8; 32],
            cv: Some([33_u8; 32]),
            cv_sha256: None,
            value: None,
            airdrop_nullifier: Nullifier::from([44_u8; 32]),
            proof_hash: [0_u8; 32],
            message_hash: [0_u8; 32],
            spend_auth_sig: [0_u8; 64],
        };
        claim.proof_hash = hash_sapling_signed_claim_proof(&claim);
        claim
    }

    #[tokio::test]
    async fn verify_rejects_missing_message_for_sapling_claim() {
        let dir = tempdir().expect("tempdir");
        let submission_path = dir.path().join("submission.json");
        let config_path = dir.path().join("config.json");

        let submission = ClaimSubmission {
            sapling: vec![sample_sapling_claim()],
            orchard: vec![],
        };
        write_json(&submission_path, &submission);
        write_json(&config_path, &sapling_config());

        let err = verify_claim_submission_signature(submission_path, None, None, config_path)
            .await
            .expect_err("verification must fail without a message");

        assert!(
            err.to_string()
                .contains("No message provided for Sapling claim"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_sapling_proof_hash_mismatch_before_signature_check() {
        let dir = tempdir().expect("tempdir");
        let submission_path = dir.path().join("submission.json");
        let config_path = dir.path().join("config.json");
        let message_path = dir.path().join("message.bin");
        std::fs::write(&message_path, b"test-message").expect("write message file");

        let mut claim = sample_sapling_claim();
        claim.proof_hash = [99_u8; 32];
        claim.message_hash = hash_message(b"test-message");

        let submission = ClaimSubmission {
            sapling: vec![claim],
            orchard: vec![],
        };
        write_json(&submission_path, &submission);
        write_json(&config_path, &sapling_config());

        let err = verify_claim_submission_signature(
            submission_path,
            Some(message_path),
            None,
            config_path,
        )
        .await
        .expect_err("verification must fail for proof hash mismatch");

        assert!(
            err.to_string()
                .contains("Sapling proof hash mismatch at index 0"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_orchard_claims_when_config_has_no_orchard_pool() {
        let dir = tempdir().expect("tempdir");
        let submission_path = dir.path().join("submission.json");
        let config_path = dir.path().join("config.json");

        let submission = ClaimSubmission {
            sapling: vec![],
            orchard: vec![OrchardSignedClaim {
                zkproof: vec![1_u8, 2_u8, 3_u8],
                rk: [3_u8; 32],
                cv: Some([4_u8; 32]),
                cv_sha256: None,
                value: None,
                airdrop_nullifier: Nullifier::from([5_u8; 32]),
                proof_hash: [6_u8; 32],
                message_hash: [7_u8; 32],
                spend_auth_sig: [8_u8; 64],
            }],
        };
        write_json(&submission_path, &submission);
        write_json(&config_path, &sapling_config());

        let err = verify_claim_submission_signature(submission_path, None, None, config_path)
            .await
            .expect_err("verification must fail when orchard config is missing");

        assert!(
            err.to_string().contains(
                "Orchard signed claims provided, but airdrop configuration has no orchard pool"
            ),
            "{err:?}"
        );
    }
}
