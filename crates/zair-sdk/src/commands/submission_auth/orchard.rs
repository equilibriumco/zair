//! Orchard spend-auth key derivation/signature helpers.

use eyre::{ContextCompat as _, ensure};
use group::ff::PrimeField as _;
use orchard::keys::SpendAuthorizingKey;
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use pasta_curves::pallas;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Network;
use zip32::AccountId;

use super::super::claim_proofs::{OrchardClaimProofResult, OrchardClaimSecretResult};

/// Seed-derived Orchard spend-authorizing key.
pub struct OrchardSpendAuthKey {
    key: SpendAuthorizingKey,
}

/// Derive the Orchard spend-authorizing key for an account.
pub fn derive_spend_auth_key(
    network: Network,
    seed: &[u8; 64],
    account_id: u32,
) -> eyre::Result<OrchardSpendAuthKey> {
    let account_id =
        AccountId::try_from(account_id).map_err(|_| eyre::eyre!("Invalid account-id"))?;

    let usk = UnifiedSpendingKey::from_seed(&network, seed, account_id)
        .map_err(|e| eyre::eyre!("Failed to derive spending key: {e:?}"))?;

    Ok(OrchardSpendAuthKey {
        key: SpendAuthorizingKey::from(usk.orchard()),
    })
}

/// Sign an Orchard claim proof entry digest.
pub fn sign_claim(
    proof: &OrchardClaimProofResult,
    secret: &OrchardClaimSecretResult,
    key: &OrchardSpendAuthKey,
    digest: &[u8; 32],
) -> eyre::Result<[u8; 64]> {
    ensure!(
        proof.airdrop_nullifier == secret.airdrop_nullifier,
        "Proof/secret mismatch: airdrop nullifier differs"
    );

    let alpha = pallas::Scalar::from_repr(secret.alpha)
        .into_option()
        .context("Invalid Orchard alpha in secrets file")?;

    let signing_key = key.key.randomize(&alpha);
    let verifying_key = VerificationKey::<SpendAuth>::from(&signing_key);
    let rk_bytes: [u8; 32] = (&verifying_key).into();

    ensure!(
        rk_bytes == proof.rk,
        "Cannot match Orchard proof rk to a seed-derived Orchard spend key"
    );

    let signature = signing_key.sign(rand_core::OsRng, digest);
    Ok((&signature).into())
}
