use std::fmt;

use zair_orchard_circuit::circuit::airdrop::ValueCommitmentScheme as CircuitValueCommitmentScheme;

/// Orchard value-commitment scheme selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueCommitmentScheme {
    /// Expose the native Orchard value commitment point.
    Native,
    /// Expose only `cv_sha256` (standard SHA-256 digest bytes).
    Sha256,
    /// Expose the note value directly as a public input (no commitment).
    Plain,
}

impl fmt::Display for ValueCommitmentScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => f.write_str("native"),
            Self::Sha256 => f.write_str("sha256"),
            Self::Plain => f.write_str("plain"),
        }
    }
}

impl From<zair_core::schema::config::ValueCommitmentScheme> for ValueCommitmentScheme {
    fn from(scheme: zair_core::schema::config::ValueCommitmentScheme) -> Self {
        match scheme {
            zair_core::schema::config::ValueCommitmentScheme::Native => Self::Native,
            zair_core::schema::config::ValueCommitmentScheme::Sha256 => Self::Sha256,
            zair_core::schema::config::ValueCommitmentScheme::Plain => Self::Plain,
        }
    }
}

impl From<ValueCommitmentScheme> for CircuitValueCommitmentScheme {
    fn from(scheme: ValueCommitmentScheme) -> Self {
        match scheme {
            ValueCommitmentScheme::Native => Self::Native,
            ValueCommitmentScheme::Sha256 => Self::Sha256,
            ValueCommitmentScheme::Plain => Self::Plain,
        }
    }
}

/// Claim proof output (public fields + proof bytes).
///
/// Public input ordering mirrors Sapling: rk first, then value commitment(s), then anchors,
/// then airdrop nullifier.
#[derive(Clone, Debug)]
pub struct ClaimProofOutput {
    /// Halo2 proof bytes.
    pub zkproof: Vec<u8>,
    /// Randomized spend validating key `rk` (`RedPallas` verification key encoding).
    pub rk: [u8; 32],
    /// Orchard value commitment `cv` (Pallas point encoding), when using the native scheme.
    pub cv: Option<[u8; 32]>,
    /// SHA-256 value commitment digest bytes, when enabled.
    pub cv_sha256: Option<[u8; 32]>,
    /// Plain note value, when using the `plain` scheme.
    pub value: Option<u64>,
    /// Airdrop nullifier (canonical `pallas::Base` encoding).
    pub airdrop_nullifier: [u8; 32],
}

/// Inputs required to generate an Orchard airdrop proof.
#[derive(Clone, Debug)]
pub struct ClaimProofInputs {
    /// Orchard target id bytes (first `target_id_len` bytes are used).
    pub target_id: [u8; 32],
    /// Length of `target_id` in bytes.
    pub target_id_len: u8,

    /// Public airdrop nullifier (canonical `pallas::Base` encoding).
    pub airdrop_nullifier: [u8; 32],
    /// Orchard note commitment tree root (canonical `pallas::Base` encoding).
    pub note_commitment_root: [u8; 32],
    /// Orchard spent-nullifier gap tree root (canonical `pallas::Base` encoding).
    pub nullifier_gap_root: [u8; 32],
    /// Which value commitment scheme to expose.
    pub value_commitment_scheme: ValueCommitmentScheme,
    /// Randomness `rcv_sha256` for the SHA-256 value commitment, when enabled.
    pub rcv_sha256: Option<[u8; 32]>,

    /// Note preimage / identity.
    /// Note commitment randomness input `rho` (canonical Pallas base encoding).
    pub rho: [u8; 32],
    /// Note seed `rseed` (32 bytes) used to derive `psi` and `rcm` given `rho`.
    pub rseed: [u8; 32],
    /// Diversified basepoint `g_d` (Pallas point encoding).
    pub g_d: [u8; 32],
    /// Diversified public key `pk_d` (Pallas point encoding).
    pub pk_d: [u8; 32],
    /// Note value (zatoshis).
    pub value: u64,

    /// Note commitment tree inclusion witness (leaf-to-root).
    /// Note commitment leaf position in the note commitment tree.
    pub cm_note_position: u32,
    /// Note commitment tree authentication path (sibling nodes, leaf-to-root).
    pub cm_merkle_path: [[u8; 32]; orchard::NOTE_COMMITMENT_TREE_DEPTH],

    /// Key material.
    /// Randomizer `alpha` used for `rk` (canonical scalar encoding).
    pub alpha: [u8; 32],
    /// Spend authorizing key `ak_P` (Pallas point encoding).
    pub ak_p: [u8; 32],
    /// Nullifier deriving key `nk` (canonical Pallas base encoding).
    pub nk: [u8; 32],
    /// Randomized incoming viewing key component `rivk` (canonical scalar encoding).
    pub rivk: [u8; 32],
    /// Value commitment trapdoor `rcv` (canonical scalar encoding).
    pub rcv: [u8; 32],

    /// Gap tree witness.
    /// Left boundary `L` for the spent-nullifier gap, as a canonical Pallas base encoding.
    pub left: [u8; 32],
    /// Right boundary `R` for the spent-nullifier gap, as a canonical Pallas base encoding.
    pub right: [u8; 32],
    /// Position of the gap leaf in the gap tree.
    pub nf_leaf_position: u32,
    /// Gap tree authentication path (sibling nodes, leaf-to-root).
    pub nf_merkle_path: [[u8; 32]; orchard::NOTE_COMMITMENT_TREE_DEPTH],
}
