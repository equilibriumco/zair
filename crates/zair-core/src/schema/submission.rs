//! Submission/signature schema models.

use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use crate::base::Nullifier;

/// A signed Sapling claim entry ready for target-chain submission.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingSignedClaim {
    /// The Groth16 proof bytes.
    #[serde_as(as = "Hex")]
    pub zkproof: [u8; 192],
    /// The re-randomized spend verification key.
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// Native value commitment bytes, if the active scheme is native.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// SHA-256 value commitment bytes, if the active scheme is sha256.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// Plain note value, if the active scheme is plain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// Airdrop nullifier used for double-claim prevention.
    pub airdrop_nullifier: Nullifier,
    /// Spend authorization signature over the submission digest.
    #[serde_as(as = "Hex")]
    pub spend_auth_sig: [u8; 64],
}

/// A signed Orchard claim entry ready for target-chain submission.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchardSignedClaim {
    /// The Halo2 proof bytes.
    #[serde_as(as = "Hex")]
    pub zkproof: Vec<u8>,
    /// The randomized spend verification key.
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// Native value commitment bytes, if the active scheme is native.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// SHA-256 value commitment bytes, if the active scheme is sha256.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// Plain note value, if the active scheme is plain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// Airdrop nullifier used for double-claim prevention.
    pub airdrop_nullifier: Nullifier,
    /// Spend authorization signature over the submission digest.
    #[serde_as(as = "Hex")]
    pub spend_auth_sig: [u8; 64],
}

/// Signed claims grouped by pool for submission.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSubmission {
    /// Signed Sapling claims.
    #[serde(default)]
    pub sapling: Vec<SaplingSignedClaim>,
    /// Signed Orchard claims.
    #[serde(default)]
    pub orchard: Vec<OrchardSignedClaim>,
}
