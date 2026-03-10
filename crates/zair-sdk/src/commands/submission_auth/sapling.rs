//! Sapling spend-auth key derivation/signature helpers.

use eyre::{ContextCompat as _, ensure};
use jubjub::Fr;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

use super::super::claim_proofs::{SaplingClaimProofResult, SaplingClaimSecretResult};

/// Seed-derived Sapling spend-auth keys for both scopes.
pub struct SaplingSpendAuthKeys {
    external: sapling::keys::SpendAuthorizingKey,
    internal: sapling::keys::SpendAuthorizingKey,
}

/// Derive Sapling spend-authorizing keys for external and internal scopes.
pub fn derive_spend_auth_keys(
    network: Network,
    seed: &[u8; 64],
    account_id: u32,
) -> eyre::Result<SaplingSpendAuthKeys> {
    let account_id =
        AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account-id"))?;

    let usk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    let extsk = usk.sapling();
    Ok(SaplingSpendAuthKeys {
        external: extsk.expsk.ask.clone(),
        internal: extsk.derive_internal().expsk.ask,
    })
}

/// Sign a Sapling claim proof entry digest.
pub fn sign_claim(
    proof: &SaplingClaimProofResult,
    secret: &SaplingClaimSecretResult,
    keys: &SaplingSpendAuthKeys,
    digest: &[u8; 32],
) -> eyre::Result<[u8; 64]> {
    ensure!(
        proof.airdrop_nullifier == secret.airdrop_nullifier,
        "Proof/secret mismatch: airdrop nullifier differs"
    );

    let alpha = Fr::from_bytes(&secret.alpha)
        .into_option()
        .context("Invalid alpha in secrets file")?;

    let mut matched_signing_key: Option<redjubjub::SigningKey<redjubjub::SpendAuth>> = None;

    let external_signing_key = keys.external.randomize(&alpha);
    let external_rk_bytes: [u8; 32] =
        redjubjub::VerificationKey::from(&external_signing_key).into();
    if external_rk_bytes == proof.rk {
        matched_signing_key = Some(external_signing_key);
    }

    let internal_signing_key = keys.internal.randomize(&alpha);
    let internal_rk_bytes: [u8; 32] =
        redjubjub::VerificationKey::from(&internal_signing_key).into();
    if internal_rk_bytes == proof.rk && matched_signing_key.is_none() {
        matched_signing_key = Some(internal_signing_key);
    }

    ensure!(
        matched_signing_key.is_some(),
        "Cannot match proof rk to a seed-derived Sapling spend key"
    );

    let signing_key = matched_signing_key.context("Missing matched Sapling signing key")?;
    let signature = signing_key.sign(rand_core::OsRng, digest);
    Ok(signature.into())
}
