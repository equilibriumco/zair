use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use crate::base::ReversedHex;

/// Configuration for an airdrop snapshot.
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AirdropConfiguration {
    /// Zcash network this snapshot belongs to.
    pub network: AirdropNetwork,
    /// Snapshot block height (inclusive).
    pub snapshot_height: u64,
    /// Sapling snapshot configuration. Present when Sapling pool is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sapling: Option<SaplingSnapshot>,
    /// Orchard snapshot configuration. Present when Orchard pool is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orchard: Option<OrchardSnapshot>,
}

/// Value commitment scheme selection.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValueCommitmentScheme {
    /// Native pool commitment (`cv`).
    #[default]
    Native,
    /// SHA-256 commitment (`cv_sha256`).
    Sha256,
    /// Plain value (no commitment, public value).
    Plain,
}

/// Network identifier for an airdrop snapshot.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AirdropNetwork {
    /// Zcash mainnet.
    Mainnet,
    /// Zcash testnet.
    Testnet,
}

/// Sapling-specific snapshot data.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct SaplingSnapshot {
    /// Sapling note commitment tree root at `snapshot_height`.
    #[serde_as(as = "ReversedHex")]
    #[schemars(with = "String")]
    pub note_commitment_root: [u8; 32],
    /// Sapling nullifier non-membership tree root at `snapshot_height`.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub nullifier_gap_root: [u8; 32],
    /// Domain-separation identifier used for Sapling hiding nullifiers.
    pub target_id: String,
    /// Value commitment scheme used by Sapling proofs.
    #[serde(default)]
    pub value_commitment_scheme: ValueCommitmentScheme,
}

/// Orchard-specific snapshot data.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct OrchardSnapshot {
    /// Orchard note commitment tree root at `snapshot_height`.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub note_commitment_root: [u8; 32],
    /// Orchard nullifier non-membership tree root at `snapshot_height`.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub nullifier_gap_root: [u8; 32],
    /// Domain-separation identifier used for Orchard hiding nullifiers.
    pub target_id: String,
    /// Value commitment scheme used by Orchard proofs.
    #[serde(default)]
    pub value_commitment_scheme: ValueCommitmentScheme,
}

impl AirdropConfiguration {
    /// Create a new airdrop configuration.
    #[must_use]
    pub const fn new(
        network: AirdropNetwork,
        snapshot_height: u64,
        sapling: Option<SaplingSnapshot>,
        orchard: Option<OrchardSnapshot>,
    ) -> Self {
        Self {
            network,
            snapshot_height,
            sapling,
            orchard,
        }
    }

    /// Build note commitment tree roots in the claim-input shape.
    #[must_use]
    pub fn note_commitment_tree_anchors(&self) -> CommitmentTreeAnchors {
        CommitmentTreeAnchors {
            sapling: self
                .sapling
                .as_ref()
                .map_or([0u8; 32], |pool| pool.note_commitment_root),
            orchard: self
                .orchard
                .as_ref()
                .map_or([0u8; 32], |pool| pool.note_commitment_root),
        }
    }

    /// Build non-membership roots in the claim-input shape.
    #[must_use]
    pub fn non_membership_tree_anchors(&self) -> NonMembershipTreeAnchors {
        NonMembershipTreeAnchors {
            sapling: self
                .sapling
                .as_ref()
                .map_or([0u8; 32], |pool| pool.nullifier_gap_root),
            orchard: self
                .orchard
                .as_ref()
                .map_or([0u8; 32], |pool| pool.nullifier_gap_root),
        }
    }
}

/// Commitment tree anchors for Sapling and Orchard pools.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct CommitmentTreeAnchors {
    /// Sapling commitment tree anchor.
    #[serde_as(as = "ReversedHex")]
    #[schemars(with = "String")]
    pub sapling: [u8; 32],
    /// Orchard commitment tree anchor.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub orchard: [u8; 32],
}

/// Non-membership tree roots for Sapling and Orchard nullifiers.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct NonMembershipTreeAnchors {
    /// Sapling non-membership tree root.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub sapling: [u8; 32],
    /// Orchard non-membership tree root.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub orchard: [u8; 32],
}

impl AirdropNetwork {
    /// Parse from CLI/network string.
    #[must_use]
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            _ => None,
        }
    }
}
