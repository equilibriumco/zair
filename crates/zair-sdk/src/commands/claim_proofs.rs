//! Claim proof DTOs and verification command implementation.

use std::path::PathBuf;

use eyre::{Context as _, ContextCompat as _, ensure};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use tracing::{info, warn};
use zair_core::base::Nullifier;
use zair_core::schema::config::AirdropConfiguration;
use zair_orchard_proofs::{
    ClaimProofOutput as OrchardClaimProofOutput,
    ValueCommitmentScheme as OrchardValueCommitmentScheme,
    verify_claim_proof_output as verify_orchard_claim_proof_output,
};
use zair_sapling_proofs::verifier::verify_claim_proof_bytes;

use super::orchard_params::{OrchardParamsMode, load_or_prepare_orchard_params};

/// Output format for claim proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProofsOutput {
    /// Sapling claim proofs.
    pub sapling_proofs: Vec<SaplingClaimProofResult>,
    /// Orchard claim proofs.
    pub orchard_proofs: Vec<OrchardClaimProofResult>,
}

/// Serializable output of a single Sapling claim proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingClaimProofResult {
    /// The Groth16 proof (192 bytes)
    #[serde_as(as = "Hex")]
    pub zkproof: [u8; 192],
    /// The re-randomized spend verification key (rk)
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// The native value commitment (cv), if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// The SHA-256 value commitment (`cv_sha256`), if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// The plain note value, if the scheme is `plain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// The airdrop nullifier (airdrop-specific nullifier for double-claim prevention).
    pub airdrop_nullifier: Nullifier,
}

/// Serializable output of a single Orchard claim proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardClaimProofResult {
    /// The Halo2 proof bytes.
    #[serde_as(as = "Hex")]
    pub zkproof: Vec<u8>,
    /// The re-randomized spend verification key (rk).
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// The native value commitment (`cv`), if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// The SHA-256 value commitment (`cv_sha256`), if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// The plain note value, if the scheme is `plain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// The airdrop nullifier (airdrop-specific nullifier for double-claim prevention).
    pub airdrop_nullifier: Nullifier,
}

/// Local-only secrets output format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSecretsOutput {
    /// Sapling local-only secret material.
    pub sapling: Vec<SaplingClaimSecretResult>,
    /// Orchard local-only secret material.
    pub orchard: Vec<OrchardClaimSecretResult>,
}

/// Local-only secret material for a single Sapling claim proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingClaimSecretResult {
    /// The airdrop nullifier this secret material corresponds to.
    pub airdrop_nullifier: Nullifier,
    /// Spend authorization randomizer used for rk/signature binding.
    #[serde_as(as = "Hex")]
    pub alpha: [u8; 32],
    /// Native commitment randomness `rcv`, if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv: Option<[u8; 32]>,
    /// SHA-256 commitment randomness `rcv_sha256`, if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv_sha256: Option<[u8; 32]>,
}

/// Local-only secret material for a single Orchard claim proof.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardClaimSecretResult {
    /// The airdrop nullifier this secret material corresponds to.
    pub airdrop_nullifier: Nullifier,
    /// Spend authorization randomizer used for rk/signature binding.
    #[serde_as(as = "Hex")]
    pub alpha: [u8; 32],
    /// Native commitment randomness `rcv`, if the scheme is `native`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv: Option<[u8; 32]>,
    /// SHA-256 commitment randomness `rcv_sha256`, if the scheme is `sha256`.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcv_sha256: Option<[u8; 32]>,
}

/// Verify all Sapling claim proofs from a proofs file (output of prove).
///
/// # Arguments
///
/// * `proofs_file` - Path to JSON file containing the proofs (`ClaimProofsOutput` format)
/// * `verifying_key_file` - Path to the verifying key file
/// * `airdrop_configuration_file` - Airdrop configuration used to bind expected anchors/scheme
///
/// # Errors
/// Returns an error if file I/O, parsing, or proof verification fails.
#[allow(
    clippy::too_many_lines,
    reason = "End-to-end verification flow performs config binding, key loading, and batch checks"
)]
pub async fn verify_claim_proofs(
    proofs_file: PathBuf,
    verifying_key_file: PathBuf,
    orchard_params_file: PathBuf,
    orchard_params_mode: OrchardParamsMode,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    info!(file = ?proofs_file, "Loading claim proofs for verification...");

    // Load proofs from JSON (ClaimProofsOutput format from prove)
    let proofs: ClaimProofsOutput =
        serde_json::from_str(&tokio::fs::read_to_string(&proofs_file).await?)
            .context("Failed to parse proofs JSON")?;
    verify_claim_proofs_inner(
        proofs,
        verifying_key_file,
        orchard_params_file,
        orchard_params_mode,
        airdrop_configuration_file,
    )
    .await
}

/// Verify all Sapling claim proofs from an in-memory `ClaimProofsOutput`.
///
/// # Errors
/// Returns an error if parsing, key loading, or proof verification fails.
#[allow(
    clippy::too_many_lines,
    reason = "End-to-end verification flow performs config binding, key loading, and batch checks"
)]
pub(super) async fn verify_claim_proofs_inner(
    proofs: ClaimProofsOutput,
    verifying_key_file: PathBuf,
    orchard_params_file: PathBuf,
    orchard_params_mode: OrchardParamsMode,
    airdrop_configuration_file: PathBuf,
) -> eyre::Result<()> {
    let ClaimProofsOutput {
        sapling_proofs,
        orchard_proofs,
    } = proofs;

    ensure!(
        !(sapling_proofs.is_empty() && orchard_proofs.is_empty()),
        "No proofs found to verify"
    );

    let airdrop_config: AirdropConfiguration =
        serde_json::from_str(&tokio::fs::read_to_string(&airdrop_configuration_file).await?)
            .context("Failed to parse airdrop configuration JSON")?;

    let sapling_ctx = if sapling_proofs.is_empty() {
        None
    } else {
        let sapling = airdrop_config
            .sapling
            .as_ref()
            .context("Sapling proofs provided, but airdrop configuration has no sapling pool")?;
        Some((
            sapling.value_commitment_scheme.into(),
            sapling.note_commitment_root,
            sapling.nullifier_gap_root,
        ))
    };

    let orchard_ctx = if orchard_proofs.is_empty() {
        None
    } else {
        let orchard = airdrop_config
            .orchard
            .as_ref()
            .context("Orchard proofs provided, but airdrop configuration has no orchard pool")?;
        ensure!(
            orchard.target_id.len() <= 32,
            "Orchard target_id must be at most 32 bytes"
        );
        let scheme = orchard.value_commitment_scheme.into();
        Some((
            scheme,
            orchard.note_commitment_root,
            orchard.nullifier_gap_root,
            orchard.target_id.clone(),
        ))
    };

    info!(
        sapling_count = sapling_proofs.len(),
        orchard_count = orchard_proofs.len(),
        "Proofs loaded, starting verification..."
    );

    let (sapling_valid, sapling_invalid) = if let Some((
        sapling_scheme,
        note_commitment_root,
        nullifier_gap_root,
    )) = sapling_ctx
    {
        eyre::ensure!(
            tokio::fs::try_exists(&verifying_key_file).await?,
            "Verifying key not found at {}. Run `zair setup sapling --scheme native` or `zair setup sapling --scheme sha256` (matching the airdrop configuration scheme) and use the generated verifying key path.",
            verifying_key_file.display(),
        );

        let bytes = tokio::fs::read(&verifying_key_file).await?;
        let vk = bellman::groth16::VerifyingKey::read(&bytes[..])
            .context("Failed to read verifying key")?;
        let pvk = bellman::groth16::prepare_verifying_key(&vk);

        tokio::task::spawn_blocking(move || {
            let mut valid = 0_usize;
            let mut invalid = 0_usize;
            for (index, proof_result) in sapling_proofs.iter().enumerate() {
                let airdrop_nullifier: [u8; 32] = proof_result.airdrop_nullifier.into();
                match verify_claim_proof_bytes(
                    &pvk,
                    &proof_result.zkproof,
                    sapling_scheme,
                    &proof_result.rk,
                    proof_result.cv.as_ref(),
                    proof_result.cv_sha256.as_ref(),
                    proof_result.value,
                    &note_commitment_root,
                    &airdrop_nullifier,
                    &nullifier_gap_root,
                ) {
                    Ok(()) => {
                        info!(
                            index,
                            airdrop_nullifier = %proof_result.airdrop_nullifier,
                            "Sapling proof VALID"
                        );
                        valid = valid.saturating_add(1);
                    }
                    Err(error) => {
                        warn!(
                            index,
                            airdrop_nullifier = %proof_result.airdrop_nullifier,
                            %error,
                            "Sapling proof INVALID"
                        );
                        invalid = invalid.saturating_add(1);
                    }
                }
            }
            (valid, invalid)
        })
        .await?
    } else {
        (0, 0)
    };

    let (orchard_valid, orchard_invalid) =
        if let Some((orchard_scheme, note_commitment_root, nullifier_gap_root, target_id)) =
            orchard_ctx
        {
            let needs_halo2 = orchard_proofs
                .iter()
                .any(|proof_result| match orchard_scheme {
                    OrchardValueCommitmentScheme::Native => {
                        proof_result.cv.is_some() && proof_result.cv_sha256.is_none()
                    }
                    OrchardValueCommitmentScheme::Sha256 => {
                        proof_result.cv.is_none() && proof_result.cv_sha256.is_some()
                    }
                    OrchardValueCommitmentScheme::Plain => {
                        proof_result.cv.is_none() &&
                            proof_result.cv_sha256.is_none() &&
                            proof_result.value.is_some()
                    }
                });
            let params = if needs_halo2 {
                Some(
                    load_or_prepare_orchard_params(
                        orchard_params_file,
                        orchard_scheme,
                        orchard_params_mode,
                    )
                    .await?,
                )
            } else {
                None
            };
            tokio::task::spawn_blocking(move || {
            let mut valid = 0_usize;
            let mut invalid = 0_usize;
            for (index, proof_result) in orchard_proofs.iter().enumerate() {
                let scheme_ok = match orchard_scheme {
                    OrchardValueCommitmentScheme::Native => {
                        proof_result.cv.is_some() && proof_result.cv_sha256.is_none()
                    }
                    OrchardValueCommitmentScheme::Sha256 => {
                        proof_result.cv.is_none() && proof_result.cv_sha256.is_some()
                    }
                    OrchardValueCommitmentScheme::Plain => {
                        proof_result.cv.is_none() &&
                            proof_result.cv_sha256.is_none() &&
                            proof_result.value.is_some()
                    }
                };
                if !scheme_ok {
                    warn!(
                        index,
                        airdrop_nullifier = %proof_result.airdrop_nullifier,
                        "Orchard proof commitment fields are incompatible with configured scheme"
                    );
                    invalid = invalid.saturating_add(1);
                    continue;
                }

                let output = OrchardClaimProofOutput {
                    zkproof: proof_result.zkproof.clone(),
                    rk: proof_result.rk,
                    cv: proof_result.cv,
                    cv_sha256: proof_result.cv_sha256,
                    value: proof_result.value,
                    airdrop_nullifier: proof_result.airdrop_nullifier.into(),
                };

                let Some(ref halo2_params) = params else {
                    warn!(
                        index,
                        airdrop_nullifier = %proof_result.airdrop_nullifier,
                        "Orchard params not loaded but proof requires halo2 verification"
                    );
                    invalid = invalid.saturating_add(1);
                    continue;
                };

                match verify_orchard_claim_proof_output(
                    halo2_params.as_ref(),
                    &output,
                    note_commitment_root,
                    nullifier_gap_root,
                    orchard_scheme,
                    target_id.as_bytes(),
                ) {
                    Ok(()) => {
                        info!(
                            index,
                            airdrop_nullifier = %proof_result.airdrop_nullifier,
                            "Orchard proof VALID"
                        );
                        valid = valid.saturating_add(1);
                    }
                    Err(error) => {
                        warn!(
                            index,
                            airdrop_nullifier = %proof_result.airdrop_nullifier,
                            %error,
                            "Orchard proof INVALID"
                        );
                        invalid = invalid.saturating_add(1);
                    }
                }
            }
            (valid, invalid)
        })
        .await?
        } else {
            (0, 0)
        };

    let total = sapling_valid
        .saturating_add(sapling_invalid)
        .saturating_add(orchard_valid)
        .saturating_add(orchard_invalid);
    let invalid_total = sapling_invalid.saturating_add(orchard_invalid);
    info!(
        sapling_valid,
        sapling_invalid, orchard_valid, orchard_invalid, total, "Verification complete"
    );
    ensure!(
        invalid_total == 0,
        "{invalid_total} proofs failed verification"
    );
    info!("All {total} claim proofs are VALID");

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde::Serialize;
    use tempfile::tempdir;
    use zair_core::schema::config::{
        AirdropConfiguration, AirdropNetwork, OrchardSnapshot, ValueCommitmentScheme,
    };

    use super::*;

    fn write_json<T: Serialize>(path: &Path, value: &T) {
        let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
        std::fs::write(path, bytes).expect("write json file");
    }

    fn orchard_only_config(
        target_id: &str,
        value_commitment_scheme: ValueCommitmentScheme,
    ) -> AirdropConfiguration {
        AirdropConfiguration {
            network: AirdropNetwork::Testnet,
            snapshot_height: 1,
            sapling: None,
            orchard: Some(OrchardSnapshot {
                note_commitment_root: [0_u8; 32],
                nullifier_gap_root: [0_u8; 32],
                target_id: target_id.to_owned(),
                value_commitment_scheme,
            }),
        }
    }

    fn sample_orchard_proof_native_shape() -> OrchardClaimProofResult {
        OrchardClaimProofResult {
            zkproof: vec![1_u8, 2_u8, 3_u8],
            rk: [7_u8; 32],
            cv: Some([9_u8; 32]),
            cv_sha256: None,
            value: None,
            airdrop_nullifier: Nullifier::from([11_u8; 32]),
        }
    }

    #[tokio::test]
    async fn verify_allows_orchard_sha256_target_id_up_to_32_bytes() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        write_json(
            &config_path,
            &orchard_only_config("ZAIRTESTLONG", ValueCommitmentScheme::Sha256),
        );

        let proofs = ClaimProofsOutput {
            sapling_proofs: vec![],
            orchard_proofs: vec![sample_orchard_proof_native_shape()],
        };

        let err = verify_claim_proofs_inner(
            proofs,
            Path::new("unused").into(),
            Path::new("unused").into(),
            OrchardParamsMode::Require,
            config_path,
        )
        .await
        .expect_err("dummy proof should fail verification, but not due to target_id length");
        assert!(
            err.to_string().contains("1 proofs failed verification"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_orchard_proof_shape_mismatch_for_configured_scheme() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        write_json(
            &config_path,
            &orchard_only_config("ZAIRTEST", ValueCommitmentScheme::Native),
        );

        let proofs = ClaimProofsOutput {
            sapling_proofs: vec![],
            orchard_proofs: vec![OrchardClaimProofResult {
                cv: None,
                cv_sha256: Some([5_u8; 32]),
                ..sample_orchard_proof_native_shape()
            }],
        };

        let err = verify_claim_proofs_inner(
            proofs,
            Path::new("unused").into(),
            Path::new("unused").into(),
            OrchardParamsMode::Require,
            config_path,
        )
        .await
        .expect_err("verification must fail for orchard scheme mismatch");
        assert!(
            err.to_string().contains("1 proofs failed verification"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_sapling_proofs_when_config_has_no_sapling_pool() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        write_json(
            &config_path,
            &orchard_only_config("ZAIRTEST", ValueCommitmentScheme::Native),
        );

        let proofs = ClaimProofsOutput {
            sapling_proofs: vec![SaplingClaimProofResult {
                zkproof: [1_u8; 192],
                rk: [2_u8; 32],
                cv: Some([3_u8; 32]),
                cv_sha256: None,
                value: None,
                airdrop_nullifier: Nullifier::from([4_u8; 32]),
            }],
            orchard_proofs: vec![],
        };

        let err = verify_claim_proofs_inner(
            proofs,
            Path::new("unused").into(),
            Path::new("unused").into(),
            OrchardParamsMode::Require,
            config_path,
        )
        .await
        .expect_err("verification must fail when sapling config is missing");
        assert!(
            err.to_string()
                .contains("Sapling proofs provided, but airdrop configuration has no sapling pool"),
            "{err:?}"
        );
    }
}
