//! Orchard airdrop proof circuit.
//!
//! This circuit is an adaptation of the Orchard Action spend circuit for use in airdrops:
//! - It proves ownership of an Orchard note by proving knowledge of note opening and keys
//!   consistent with the recipient.
//! - It keeps the **standard Orchard nullifier** private.
//! - It exposes an **airdrop nullifier** derived with a domain-separated base point.
//! - It verifies a non-membership ("gap tree") Merkle path over spent nullifiers.
//! - It exposes a value commitment `cv` for binding to a target chain.

use std::vec::Vec;

use ff::PrimeField as _;
use group::{Curve as _, Group as _};
use halo2_gadgets::ecc::chip::{EccChip, EccConfig};
use halo2_gadgets::ecc::{FixedPoint, NonIdentityPoint, ScalarFixed, ScalarFixedShort, ScalarVar};
use halo2_gadgets::poseidon::{
    Hash as PoseidonHash, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    primitives as poseidon,
};
use halo2_gadgets::sha256::{self, Sha256Instructions};
use halo2_gadgets::sinsemilla::HashDomains;
use halo2_gadgets::sinsemilla::chip::{SinsemillaChip, SinsemillaConfig};
use halo2_gadgets::sinsemilla::merkle::chip::{MerkleChip, MerkleConfig};
use halo2_gadgets::sinsemilla::merkle::{MerkleInstructions, MerklePath};
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::circuit::{Chip as _, Layouter, Value, floor_planner};
use halo2_proofs::plonk::{
    self, Advice, Column, ConstraintSystem, Constraints, Expression, Instance as InstanceColumn,
    Selector,
};
use halo2_proofs::poly::Rotation;
use orchard::circuit::commit_ivk::{CommitIvkChip, CommitIvkConfig};
use orchard::circuit::note_commit::{NoteCommitChip, NoteCommitConfig};
use pasta_curves::arithmetic::{CurveAffine as _, CurveExt as _};
use pasta_curves::{pallas, vesta};
use zair_core::base::VALUE_COMMIT_SHA256_PREFIX;

use super::gadget::{AddChip, AddConfig, AddInstruction, assign_free_advice};
use crate::constants::{
    MERKLE_DEPTH_ORCHARD, OrchardCommitDomains, OrchardFixedBases, OrchardFixedBasesFull,
    OrchardHashDomains, T_P,
};
use crate::note::{RandomSeed, Rho};
use crate::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};

/// Circuit size parameter for the native value-commitment scheme (2^12 rows).
pub const K_AIRDROP_NATIVE: u32 = 12;

/// Circuit size parameter for the SHA-256 value-commitment scheme (2^17 rows).
///
/// The SHA-256 table chip requires significantly more rows than the native Pedersen
/// commitment.
pub const K_AIRDROP_SHA256: u32 = 17;

/// Circuit size parameter for the plain value-commitment scheme (2^12 rows).
pub const K_AIRDROP_PLAIN: u32 = 12;

// Public input offsets.
//
// Ordering mirrors Sapling: rk first, then value commitment(s), then anchors, then airdrop
// nullifier.
const RK_X: usize = 0;
const RK_Y: usize = 1;

const CV_X: usize = 2;
const CV_Y: usize = 3;

const NOTE_ANCHOR_NATIVE: usize = 4;
const GAP_ROOT_NATIVE: usize = 5;
const AIRDROP_NF_NATIVE: usize = 6;

const DIGEST_0_SHA: usize = 2; // inclusive, 8 words total
const NOTE_ANCHOR_SHA: usize = 10;
const GAP_ROOT_SHA: usize = 11;
const AIRDROP_NF_SHA: usize = 12;

const VALUE_PLAIN: usize = 2;
const NOTE_ANCHOR_PLAIN: usize = 3;
const GAP_ROOT_PLAIN: usize = 4;
const AIRDROP_NF_PLAIN: usize = 5;

/// Value commitment scheme selection for the Orchard airdrop circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ValueCommitmentScheme {
    /// Expose the native Orchard value commitment point.
    #[default]
    Native,
    /// Expose only `cv_sha256` (standard SHA-256 digest bytes).
    Sha256,
    /// Expose the note value directly as a public input (no commitment).
    Plain,
}

impl ValueCommitmentScheme {
    /// Circuit size parameter `k` (the circuit uses 2^k rows).
    #[must_use]
    pub const fn k(self) -> u32 {
        match self {
            Self::Native => K_AIRDROP_NATIVE,
            Self::Sha256 => K_AIRDROP_SHA256,
            Self::Plain => K_AIRDROP_PLAIN,
        }
    }
}

type OrchardMerkleConfig =
    MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>;
type OrchardSinsemillaConfig =
    SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>;

/// Configuration for the Orchard airdrop circuit.
#[derive(Clone, Debug)]
pub struct Config {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    sha256_config: sha256::Table16Config,
    ecc_config: EccConfig<OrchardFixedBases>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_config_1: OrchardMerkleConfig,
    merkle_config_2: OrchardMerkleConfig,
    sinsemilla_config_1: OrchardSinsemillaConfig,
    sinsemilla_config_2: OrchardSinsemillaConfig,
    commit_ivk_config: CommitIvkConfig,
    note_commit_config: NoteCommitConfig,

    // Custom selectors for decomposition and comparisons.
    q_decompose_255: Selector,
    q_lt: Selector,
    q_order: Selector,
    q_u32_add_iv: Selector,
}

impl Config {
    fn add_chip(&self) -> AddChip {
        AddChip::construct(self.add_config.clone())
    }

    fn ecc_chip(&self) -> EccChip<OrchardFixedBases> {
        EccChip::construct(self.ecc_config.clone())
    }

    fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }

    fn sinsemilla_chip_1(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_1.clone())
    }

    fn sinsemilla_chip_2(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_2.clone())
    }

    fn merkle_chip_1(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_1.clone())
    }

    fn merkle_chip_2(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_2.clone())
    }

    fn commit_ivk_chip(&self) -> CommitIvkChip {
        CommitIvkChip::construct(self.commit_ivk_config.clone())
    }

    fn note_commit_chip(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.note_commit_config.clone())
    }

    fn sha256_chip(&self) -> sha256::Table16Chip {
        sha256::Table16Chip::construct(self.sha256_config.clone())
    }
}

/// A private witness for a single Orchard airdrop claim.
#[derive(Clone, Debug, Default)]
pub struct Circuit {
    /// Orchard airdrop target id bytes (first `target_id_len` bytes are used).
    pub target_id: [u8; 32],
    /// Length of `target_id` in bytes.
    pub target_id_len: u8,

    // Orchard note tree membership.
    /// Note commitment tree authentication path (leaf-to-root).
    pub note_path: Value<[pallas::Base; MERKLE_DEPTH_ORCHARD]>,
    /// Note position within the note commitment tree.
    pub note_pos: Value<u32>,

    // Note preimage.
    /// Diversified basepoint `g_d`.
    pub g_d: Value<pallas::Affine>,
    /// Diversified public key `pk_d`.
    pub pk_d: Value<pallas::Affine>,
    /// Note value.
    pub value: Value<NoteValue>,
    /// Note randomness `ρ`.
    pub rho: Value<pallas::Base>,
    /// Random seed derived scalar `ψ`.
    pub psi: Value<pallas::Base>,
    /// Commitment randomness `rcm`.
    pub rcm: Value<pallas::Scalar>,

    // Key material.
    /// Spend authorizing scalar `α`.
    pub alpha: Value<pallas::Scalar>,
    /// Spend authorizing key `ak_P` (Pallas point).
    pub ak_p: Value<pallas::Affine>,
    /// Nullifier deriving key `nk`.
    pub nk: Value<pallas::Base>,
    /// Randomized incoming viewing key component `rivk`.
    pub rivk: Value<pallas::Scalar>,

    // Value commitment trapdoor.
    /// Value commitment trapdoor `rcv`.
    pub rcv: Value<ValueCommitTrapdoor>,
    /// Value commitment scheme selection.
    pub value_commitment_scheme: ValueCommitmentScheme,
    /// Randomness `rcv_sha256` for SHA-256 value commitment preimage.
    pub rcv_sha256: Value<[u8; 32]>,

    // Gap tree membership for (left, right).
    /// Left boundary of the gap (as a field element).
    pub left: Value<pallas::Base>,
    /// Right boundary of the gap (as a field element).
    pub right: Value<pallas::Base>,
    /// Gap tree authentication path (leaf-to-root).
    pub gap_path: Value<[pallas::Base; MERKLE_DEPTH_ORCHARD]>,
    /// Gap leaf position within the gap tree.
    pub gap_pos: Value<u32>,
}

/// Public inputs to the Orchard airdrop circuit.
#[derive(Clone, Debug)]
pub struct Instance {
    /// Orchard note commitment tree anchor.
    pub note_anchor: pallas::Base,
    /// Orchard value commitment `cv`.
    pub cv: ValueCommitment,
    /// Airdrop nullifier `nf_air`.
    pub airdrop_nf: pallas::Base,
    /// Re-randomized validating key `rk`.
    pub rk: pallas::Affine,
    /// Gap tree root for non-membership.
    pub gap_root: pallas::Base,
    /// Which value commitment scheme is exposed by this proof.
    pub value_commitment_scheme: ValueCommitmentScheme,
    /// SHA-256 value commitment digest bytes, when enabled.
    pub cv_sha256: Option<[u8; 32]>,
    /// Plain note value as a field element, when using the `plain` scheme.
    pub value: pallas::Base,
}

impl Instance {
    fn to_halo2_instance(&self) -> [Vec<vesta::Scalar>; 1] {
        let mut instance = match self.value_commitment_scheme {
            ValueCommitmentScheme::Native => vec![vesta::Scalar::zero(); 7],
            ValueCommitmentScheme::Sha256 => vec![vesta::Scalar::zero(); 13],
            ValueCommitmentScheme::Plain => vec![vesta::Scalar::zero(); 6],
        };

        let rk = self.rk.coordinates().expect("rk is non-identity");
        instance[RK_X] = *rk.x();
        instance[RK_Y] = *rk.y();

        match self.value_commitment_scheme {
            ValueCommitmentScheme::Native => {
                instance[CV_X] = self.cv.x();
                instance[CV_Y] = self.cv.y();
                instance[NOTE_ANCHOR_NATIVE] = self.note_anchor;
                instance[GAP_ROOT_NATIVE] = self.gap_root;
                instance[AIRDROP_NF_NATIVE] = self.airdrop_nf;
            }
            ValueCommitmentScheme::Sha256 => {
                let digest = self.cv_sha256.expect("sha256 scheme requires digest");
                for (i, word) in digest.chunks_exact(4).enumerate() {
                    let w: [u8; 4] = word.try_into().expect("chunk length");
                    instance[DIGEST_0_SHA + i] = vesta::Scalar::from(u32::from_be_bytes(w) as u64);
                }
                instance[NOTE_ANCHOR_SHA] = self.note_anchor;
                instance[GAP_ROOT_SHA] = self.gap_root;
                instance[AIRDROP_NF_SHA] = self.airdrop_nf;
            }
            ValueCommitmentScheme::Plain => {
                instance[VALUE_PLAIN] = self.value;
                instance[NOTE_ANCHOR_PLAIN] = self.note_anchor;
                instance[GAP_ROOT_PLAIN] = self.gap_root;
                instance[AIRDROP_NF_PLAIN] = self.airdrop_nf;
            }
        }

        [instance]
    }
}

fn two_pow_128() -> pallas::Base {
    pallas::Base::from_u128(1u128 << 64).square()
}

fn two_pow_254() -> pallas::Base {
    pallas::Base::from_u128(1u128 << 127).square()
}

fn airdrop_nullifier_basepoint(target_id: &[u8; 32], target_id_len: u8) -> pallas::Affine {
    let target_id_len = usize::from(target_id_len);
    debug_assert!(target_id_len <= 32);
    let domain =
        std::str::from_utf8(&target_id[..target_id_len]).expect("target_id should be valid utf-8");

    let p = pallas::Point::hash_to_curve(domain)(b"K");
    debug_assert!(!bool::from(p.is_identity()));
    p.to_affine()
}

/// Constructs the single 512-bit SHA-256 message block used for the SHA-256 value commitment.
///
/// Preimage = `PREFIX(4 bytes) || LE64(value) || rcv_sha256(32 bytes)`.
///
/// Because the preimage is always 44 bytes, it always fits in a single padded block.
fn value_commitment_sha256_block(
    value: Value<NoteValue>,
    rcv_sha256: Value<[u8; 32]>,
) -> [sha256::BlockWord; sha256::BLOCK_SIZE] {
    let mut words = [sha256::BlockWord(Value::known(0)); sha256::BLOCK_SIZE];
    let mut word_index = 0usize;
    while word_index < sha256::BLOCK_SIZE {
        words[word_index] = sha256::BlockWord(value.zip(rcv_sha256).map(|(v, rv)| {
            let mut block = [0u8; 64];
            block[0..4].copy_from_slice(&VALUE_COMMIT_SHA256_PREFIX);
            block[4..12].copy_from_slice(&v.inner().to_le_bytes());
            block[12..44].copy_from_slice(&rv);

            const MESSAGE_LEN: usize = 44;
            block[MESSAGE_LEN] = 0x80;
            const BIT_LEN: u64 = (MESSAGE_LEN as u64) * 8;
            block[56..64].copy_from_slice(&BIT_LEN.to_be_bytes());

            let j = word_index * 4;
            u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]])
        }));
        word_index += 1;
    }

    words
}

/// Decompose a `pallas::Base` element `x` into `(msb, mid, low)` where:
/// - `msb` is bit 254 (0/1),
/// - `mid` is bits 128..=253 (126 bits) as an integer,
/// - `low` is bits 0..=127 (128 bits) as an integer.
fn decompose_u128_parts(x: &pallas::Base) -> (bool, u128, u128) {
    let repr = x.to_repr();
    let bytes: &[u8] = repr.as_ref();

    let low = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
    let high = u128::from_le_bytes(bytes[16..32].try_into().unwrap());

    let mid = high & ((1u128 << 126) - 1);
    let msb = (high >> 126) & 1 == 1;

    (msb, mid, low)
}

impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = Config;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self {
            value_commitment_scheme: self.value_commitment_scheme,
            ..Self::default()
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Instance column used for public inputs.
        let primary = meta.instance_column();
        meta.enable_equality(primary);
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Addition of two field elements (used by gadgets).
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        // Fixed columns for the Sinsemilla generator lookup table.
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Share fixed columns between ECC and Poseidon.
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();
        meta.enable_constant(lagrange_coeffs[0]);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let ecc_config =
            EccChip::<OrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());
            (sinsemilla_config_1, merkle_config_1)
        };

        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());
            (sinsemilla_config_2, merkle_config_2)
        };

        let commit_ivk_config = CommitIvkChip::configure(meta, advices);
        let note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone());

        // Table16 SHA-256 gadget configuration (used for SHA-256 value commitments).
        let sha256_config = sha256::Table16Chip::configure(meta);

        // Canonical decomposition gate for 255-bit Pallas base field elements.
        // Enforces:
        // - msb is boolean
        // - x = low + mid*2^128 + msb*2^254
        // - msb => mid == 0
        // - msb => low < t_P (implemented as low + d + 1 = t_P)
        let q_decompose_255 = meta.selector();
        meta.create_gate("Canonical decomposition (msb, mid, low)", |meta| {
            let q = meta.query_selector(q_decompose_255);
            let x = meta.query_advice(advices[0], Rotation::cur());
            let low = meta.query_advice(advices[1], Rotation::cur());
            let mid = meta.query_advice(advices[2], Rotation::cur());
            let msb = meta.query_advice(advices[3], Rotation::cur());
            let d = meta.query_advice(advices[4], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let two_pow_128 = Expression::Constant(two_pow_128());
            let two_pow_254 = Expression::Constant(two_pow_254());
            let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

            let msb_bool = msb.clone() * (one.clone() - msb.clone());
            let reconstruct =
                x - (low.clone() + mid.clone() * two_pow_128 + msb.clone() * two_pow_254);
            let msb_implies_mid_zero = msb.clone() * mid.clone();
            let msb_implies_low_lt_tp = msb.clone() * (low + d + one - t_p);

            Constraints::with_selector(
                q,
                [
                    ("msb_bool", msb_bool),
                    ("reconstruct", reconstruct),
                    ("msb_implies_mid_zero", msb_implies_mid_zero),
                    ("msb_implies_low_lt_tp", msb_implies_low_lt_tp),
                ],
            )
        });

        // n-bit less-than helper:
        // a - b + lt*2^n = diff, with lt boolean and diff range-checked separately.
        let q_lt = meta.selector();
        meta.create_gate("lt_nbits core", |meta| {
            let q = meta.query_selector(q_lt);
            let a = meta.query_advice(advices[0], Rotation::cur());
            let b = meta.query_advice(advices[1], Rotation::cur());
            let lt = meta.query_advice(advices[2], Rotation::cur());
            let diff = meta.query_advice(advices[3], Rotation::cur());
            let two_pow_n = meta.query_advice(advices[4], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let lt_bool = lt.clone() * (one - lt.clone());
            let eq = a - b + lt * two_pow_n - diff;
            Constraints::with_selector(q, [("lt_bool", lt_bool), ("eq", eq)])
        });

        // Combine msb/mid/low comparisons into an asserted 255-bit ordering.
        //
        // Inputs are booleans:
        // - a_msb, b_msb,
        // - mid_lt (a_mid < b_mid),
        // - mid_gt (a_mid > b_mid),
        // - low_lt (a_low < b_low).
        //
        // Enforces: (a < b) == 1.
        let q_order = meta.selector();
        meta.create_gate("order_255 asserted", |meta| {
            let q = meta.query_selector(q_order);
            let a_msb = meta.query_advice(advices[0], Rotation::cur());
            let b_msb = meta.query_advice(advices[1], Rotation::cur());
            let mid_lt = meta.query_advice(advices[2], Rotation::cur());
            let mid_gt = meta.query_advice(advices[3], Rotation::cur());
            let low_lt = meta.query_advice(advices[4], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let two = Expression::Constant(pallas::Base::from(2u64));

            let a_msb_bool = a_msb.clone() * (one.clone() - a_msb.clone());
            let b_msb_bool = b_msb.clone() * (one.clone() - b_msb.clone());
            let mid_lt_bool = mid_lt.clone() * (one.clone() - mid_lt.clone());
            let mid_gt_bool = mid_gt.clone() * (one.clone() - mid_gt.clone());
            let low_lt_bool = low_lt.clone() * (one.clone() - low_lt.clone());

            let msb_lt = (one.clone() - a_msb.clone()) * b_msb.clone();
            let msb_eq =
                one.clone() - (a_msb.clone() + b_msb.clone() - two * a_msb.clone() * b_msb.clone());

            let mid_eq = one.clone() - mid_lt.clone() - mid_gt.clone();
            let t = mid_eq.clone() * low_lt.clone();
            let inner = mid_lt.clone() + t.clone() - mid_lt.clone() * t;
            let u = msb_eq * inner;
            let lt = msb_lt.clone() + u.clone() - msb_lt * u;

            Constraints::with_selector(
                q,
                [
                    ("a_msb_bool", a_msb_bool),
                    ("b_msb_bool", b_msb_bool),
                    ("mid_lt_bool", mid_lt_bool),
                    ("mid_gt_bool", mid_gt_bool),
                    ("low_lt_bool", low_lt_bool),
                    ("assert_lt", lt - one),
                ],
            )
        });

        // 32-bit addition with a boolean carry:
        // delta + iv = digest + carry*2^32, with carry ∈ {0,1}.
        let q_u32_add_iv = meta.selector();
        meta.create_gate("sha256 u32 add iv", |meta| {
            let q = meta.query_selector(q_u32_add_iv);
            let delta = meta.query_advice(advices[0], Rotation::cur());
            let digest = meta.query_advice(advices[1], Rotation::cur());
            let carry = meta.query_advice(advices[2], Rotation::cur());
            let iv = meta.query_advice(advices[3], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let two_pow_32 = Expression::Constant(pallas::Base::from_u128(1u128 << 32));

            let carry_bool = carry.clone() * (one - carry.clone());
            let eq = delta + iv - digest - carry * two_pow_32;
            Constraints::with_selector(q, [("carry_bool", carry_bool), ("eq", eq)])
        });

        Config {
            primary,
            advices,
            add_config,
            sha256_config,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            sinsemilla_config_2,
            commit_ivk_config,
            note_commit_config,
            q_decompose_255,
            q_lt,
            q_order,
            q_u32_add_iv,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), &mut layouter)?;

        let ecc_chip = config.ecc_chip();
        let scheme = self.value_commitment_scheme;
        let (note_anchor_idx, gap_root_idx, airdrop_nf_idx) = match scheme {
            ValueCommitmentScheme::Native => {
                (NOTE_ANCHOR_NATIVE, GAP_ROOT_NATIVE, AIRDROP_NF_NATIVE)
            }
            ValueCommitmentScheme::Sha256 => (NOTE_ANCHOR_SHA, GAP_ROOT_SHA, AIRDROP_NF_SHA),
            ValueCommitmentScheme::Plain => (NOTE_ANCHOR_PLAIN, GAP_ROOT_PLAIN, AIRDROP_NF_PLAIN),
        };

        // === Witness note preimage + keys ===
        let (g_d, pk_d, rho, psi, nk, ak_p, v, rcm, alpha, rivk) = {
            let g_d = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness g_d"),
                self.g_d,
            )?;

            let pk_d = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness pk_d"),
                self.pk_d,
            )?;

            let rho = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                config.advices[0],
                self.rho,
            )?;
            let psi = assign_free_advice(
                layouter.namespace(|| "witness psi"),
                config.advices[0],
                self.psi,
            )?;

            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                config.advices[0],
                self.nk,
            )?;

            let ak_p = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness ak_p"),
                self.ak_p,
            )?;

            let v = assign_free_advice(
                layouter.namespace(|| "witness value"),
                config.advices[0],
                self.value,
            )?;

            let rcm = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness rcm"),
                self.rcm,
            )?;

            let alpha = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness alpha"),
                self.alpha,
            )?;

            let rivk = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness rivk"),
                self.rivk,
            )?;

            (g_d, pk_d, rho, psi, nk, ak_p, v, rcm, alpha, rivk)
        };

        // === Spend validating key randomization => rk ===
        {
            let spend_auth_g =
                FixedPoint::from_inner(ecc_chip.clone(), OrchardFixedBasesFull::SpendAuthG);
            let (alpha_commitment, _alpha) =
                spend_auth_g.mul(layouter.namespace(|| "[alpha] SpendAuthG"), alpha)?;
            let rk = alpha_commitment.add(layouter.namespace(|| "rk"), &ak_p)?;
            layouter.constrain_instance(rk.inner().x().cell(), config.primary, RK_X)?;
            layouter.constrain_instance(rk.inner().y().cell(), config.primary, RK_Y)?;
        }

        // === Recipient integrity: pk_d == [ivk] g_d ===
        {
            let ivk = super::gadget::commit_ivk(
                config.sinsemilla_chip_1(),
                ecc_chip.clone(),
                config.commit_ivk_chip(),
                layouter.namespace(|| "CommitIvk"),
                ak_p.extract_p().inner().clone(),
                nk.clone(),
                rivk,
            )?;
            let ivk =
                ScalarVar::from_base(ecc_chip.clone(), layouter.namespace(|| "ivk"), ivk.inner())?;
            let (derived_pk_d, _ivk) = g_d.mul(layouter.namespace(|| "[ivk] g_d"), ivk)?;
            derived_pk_d.constrain_equal(layouter.namespace(|| "pk_d equality"), &pk_d)?;
        }

        // === Note commitment integrity: cmx ===
        let cm = {
            super::gadget::note_commit(
                layouter.namespace(|| "NoteCommit"),
                config.sinsemilla_chip_1(),
                ecc_chip.clone(),
                config.note_commit_chip(),
                g_d.inner(),
                pk_d.inner(),
                v.clone(),
                rho.clone(),
                psi.clone(),
                rcm,
            )?
        };
        let cmx = cm.extract_p().inner().clone();

        // === Note commitment tree membership: anchor ===
        {
            let path = self.note_path;
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::MerkleCrh,
                self.note_pos,
                path,
            );
            let root =
                merkle_inputs.calculate_root(layouter.namespace(|| "note Merkle path"), cmx)?;
            layouter.constrain_instance(root.cell(), config.primary, note_anchor_idx)?;
        }

        // === Value commitment: cv ===
        if scheme == ValueCommitmentScheme::Native {
            let magnitude = assign_free_advice(
                layouter.namespace(|| "cv magnitude"),
                config.advices[9],
                v.value().map(|v| pallas::Base::from(v.inner())),
            )?;
            let sign = assign_free_advice(
                layouter.namespace(|| "cv sign"),
                config.advices[9],
                Value::known(pallas::Base::one()),
            )?;

            let v_mag_sign = (magnitude, sign);
            let v_short =
                ScalarFixedShort::new(ecc_chip.clone(), layouter.namespace(|| "v"), v_mag_sign)?;

            let rcv = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcv"),
                self.rcv.clone().map(|rcv| rcv.inner()),
            )?;

            let cv = super::gadget::value_commit_orchard(
                layouter.namespace(|| "cv = ValueCommit^Orchard_rcv(v)"),
                ecc_chip.clone(),
                v_short,
                rcv,
            )?;
            layouter.constrain_instance(cv.inner().x().cell(), config.primary, CV_X)?;
            layouter.constrain_instance(cv.inner().y().cell(), config.primary, CV_Y)?;
        }

        // === Value commitment: SHA-256 ===
        if scheme == ValueCommitmentScheme::Sha256 {
            // Load the Table16 lookup table, but only if we are actually using SHA-256.
            sha256::Table16Chip::load(config.sha256_config.clone(), &mut layouter)?;
            let sha256_chip = config.sha256_chip();

            // Construct the single padded message block:
            // PREFIX || LE64(value) || rcv_sha256 || pad || len.
            let block = value_commitment_sha256_block(self.value, self.rcv_sha256);

            let init = sha256_chip.initialization_vector(&mut layouter)?;
            let state = sha256_chip.compress(&mut layouter, &init, block)?;
            let deltas = sha256_chip.digest_cells(&mut layouter, &state)?;

            let digest_start = match scheme {
                ValueCommitmentScheme::Sha256 => DIGEST_0_SHA,
                ValueCommitmentScheme::Native | ValueCommitmentScheme::Plain => unreachable!(),
            };

            let mut digest_cells: Vec<
                halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
            > = Vec::with_capacity(sha256::DIGEST_SIZE);
            layouter.assign_region(
                || "sha256 digest = iv + delta",
                |mut region| {
                    for (i, delta) in deltas.iter().enumerate() {
                        config.q_u32_add_iv.enable(&mut region, i)?;

                        // Copy delta word into our local column.
                        let _delta = delta.cell.copy_advice(
                            || "delta",
                            &mut region,
                            config.advices[0],
                            i,
                        )?;

                        // Witness digest word and carry.
                        let digest_u32 = delta.value.map(|d| {
                            let sum = d as u64 + sha256::IV[i] as u64;
                            (sum & 0xffff_ffff) as u32
                        });
                        let carry_bit = delta.value.map(|d| {
                            let sum = d as u64 + sha256::IV[i] as u64;
                            sum >> 32
                        });

                        let digest_cell = region.assign_advice(
                            || "digest word",
                            config.advices[1],
                            i,
                            || digest_u32.map(|w| pallas::Base::from(w as u64)),
                        )?;
                        digest_cells.push(digest_cell.clone());

                        region.assign_advice(
                            || "carry",
                            config.advices[2],
                            i,
                            || carry_bit.map(pallas::Base::from),
                        )?;

                        let iv_cell = region.assign_advice(
                            || "iv word",
                            config.advices[3],
                            i,
                            || Value::known(pallas::Base::from(sha256::IV[i] as u64)),
                        )?;
                        region.constrain_constant(
                            iv_cell.cell(),
                            pallas::Base::from(sha256::IV[i] as u64),
                        )?;
                    }
                    Ok(())
                },
            )?;

            // Expose digest words as public inputs.
            for (i, cell) in digest_cells.iter().enumerate() {
                layouter.constrain_instance(cell.cell(), config.primary, digest_start + i)?;
            }
        }

        // === Value commitment: plain ===
        if scheme == ValueCommitmentScheme::Plain {
            layouter.constrain_instance(v.cell(), config.primary, VALUE_PLAIN)?;
        }

        // === Standard nullifier (private) ===
        let nf_old = super::gadget::derive_nullifier(
            layouter.namespace(|| "nf_old"),
            config.poseidon_chip(),
            config.add_chip(),
            ecc_chip.clone(),
            rho.clone(),
            &psi,
            &cm,
            nk.clone(),
        )?;

        // === Airdrop nullifier (public) ===
        {
            let kair_affine = airdrop_nullifier_basepoint(&self.target_id, self.target_id_len);
            let coords = kair_affine.coordinates().expect("kair non-identity");
            let kair = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "kair"),
                Value::known(kair_affine),
            )?;
            layouter.assign_region(
                || "constrain kair constants",
                |mut region| {
                    region.constrain_constant(kair.inner().x().cell(), *coords.x())?;
                    region.constrain_constant(kair.inner().y().cell(), *coords.y())?;
                    Ok(())
                },
            )?;

            let poseidon_hash = {
                let poseidon_message = [nk.clone(), rho.clone()];
                let poseidon_hasher = PoseidonHash::<
                    pallas::Base,
                    PoseidonChip<pallas::Base, 3, 2>,
                    poseidon::P128Pow5T3,
                    poseidon::ConstantLength<2>,
                    3,
                    2,
                >::init(
                    config.poseidon_chip(),
                    layouter.namespace(|| "Poseidon init (air)"),
                )?;
                poseidon_hasher.hash(
                    layouter.namespace(|| "Poseidon hash (nk, rho) (air)"),
                    poseidon_message,
                )?
            };
            let scalar_base = config.add_chip().add(
                layouter.namespace(|| "scalar_base = poseidon_hash + psi"),
                &poseidon_hash,
                &psi,
            )?;

            let scalar = ScalarVar::from_base(
                ecc_chip.clone(),
                layouter.namespace(|| "scalar (air)"),
                &scalar_base,
            )?;

            let (product, _scalar) = kair.mul(layouter.namespace(|| "[scalar] kair"), scalar)?;
            let nfair = cm
                .add(layouter.namespace(|| "airdrop nf point"), &product)?
                .extract_p()
                .inner()
                .clone();

            layouter.constrain_instance(nfair.cell(), config.primary, airdrop_nf_idx)?;
        }

        // === Gap tree: witness bounds and enforce left < nf_old < right ===
        let (left_cell, right_cell) = {
            let left = assign_free_advice(
                layouter.namespace(|| "left bound"),
                config.advices[0],
                self.left,
            )?;
            let right = assign_free_advice(
                layouter.namespace(|| "right bound"),
                config.advices[0],
                self.right,
            )?;
            (left, right)
        };

        // Canonical decomposition for comparisons (left, nf_old, right).
        let (left_msb, left_mid, left_low) =
            decompose_for_compare(&config, &mut layouter, left_cell.clone())?;
        let (nf_msb, nf_mid, nf_low) =
            decompose_for_compare(&config, &mut layouter, nf_old.inner().clone())?;
        let (right_msb, right_mid, right_low) =
            decompose_for_compare(&config, &mut layouter, right_cell.clone())?;

        // Comparators: low and mid.
        let left_mid_lt_nf_mid = lt_nbits(
            &config,
            &mut layouter,
            left_mid.clone(),
            nf_mid.clone(),
            126,
        )?;
        let left_mid_gt_nf_mid = lt_nbits(
            &config,
            &mut layouter,
            nf_mid.clone(),
            left_mid.clone(),
            126,
        )?;
        let left_low_lt_nf_low = lt_nbits(
            &config,
            &mut layouter,
            left_low.clone(),
            nf_low.clone(),
            128,
        )?;

        assert_order_255(
            &config,
            &mut layouter,
            left_msb,
            nf_msb.clone(),
            left_mid_lt_nf_mid,
            left_mid_gt_nf_mid,
            left_low_lt_nf_low,
            "left < nf_old",
        )?;

        let nf_mid_lt_right_mid = lt_nbits(
            &config,
            &mut layouter,
            nf_mid.clone(),
            right_mid.clone(),
            126,
        )?;
        let nf_mid_gt_right_mid = lt_nbits(
            &config,
            &mut layouter,
            right_mid.clone(),
            nf_mid.clone(),
            126,
        )?;
        let nf_low_lt_right_low = lt_nbits(&config, &mut layouter, nf_low, right_low.clone(), 128)?;

        assert_order_255(
            &config,
            &mut layouter,
            nf_msb,
            right_msb,
            nf_mid_lt_right_mid,
            nf_mid_gt_right_mid,
            nf_low_lt_right_low,
            "nf_old < right",
        )?;

        // === Gap tree membership (Sinsemilla-only in this milestone) ===
        let q = OrchardHashDomains::MerkleCrh.Q();
        let leaf = <MerkleChip<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
        > as MerkleInstructions<pallas::Affine, MERKLE_DEPTH_ORCHARD, 10, 253>>::hash_layer(
            &config.merkle_chip_1(),
            layouter.namespace(|| "gap leaf"),
            q,
            62,
            left_cell.clone(),
            right_cell.clone(),
        )?;

        let merkle_inputs = MerklePath::construct(
            [config.merkle_chip_1(), config.merkle_chip_2()],
            OrchardHashDomains::MerkleCrh,
            self.gap_pos,
            self.gap_path,
        );
        let root = merkle_inputs.calculate_root(layouter.namespace(|| "gap Merkle path"), leaf)?;
        layouter.constrain_instance(root.cell(), config.primary, gap_root_idx)?;

        Ok(())
    }
}

fn decompose_for_compare(
    config: &Config,
    layouter: &mut impl Layouter<pallas::Base>,
    x: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
) -> Result<
    (
        halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
        halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
        halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    ),
    plonk::Error,
> {
    let parts = x.value().map(decompose_u128_parts);

    let msb_v = parts.map(|(msb, _, _)| pallas::Base::from(msb));
    let mid_v = parts.map(|(_, mid, _)| pallas::Base::from_u128(mid));
    let low_v = parts.map(|(_, _, low)| pallas::Base::from_u128(low));
    let d_v = parts.map(|(msb, _, low)| {
        pallas::Base::from_u128(if msb { (T_P - 1).wrapping_sub(low) } else { 0 })
    });

    let (msb, mid, low, d) = layouter.assign_region(
        || "decompose255",
        |mut region| {
            let x0 = x.copy_advice(|| "x", &mut region, config.advices[0], 0)?;
            let low = region.assign_advice(|| "low", config.advices[1], 0, || low_v)?;
            let mid = region.assign_advice(|| "mid", config.advices[2], 0, || mid_v)?;
            let msb = region.assign_advice(|| "msb", config.advices[3], 0, || msb_v)?;
            let d = region.assign_advice(|| "d", config.advices[4], 0, || d_v)?;
            config.q_decompose_255.enable(&mut region, 0)?;

            // Basic sanity: x0 is used by the gate; keep it alive.
            let _ = x0;
            let _ = d;
            Ok((msb, mid, low, d))
        },
    )?;

    // Range checks for mid (126 bits) and low (128 bits), and for d (128 bits).
    let lookup = config.sinsemilla_chip_1().config().lookup_config();

    // mid: 13 words of 10 bits (130) strict, then constrain top word to 6 bits.
    let zs = lookup.copy_check(layouter.namespace(|| "mid rc"), mid.clone(), 13, true)?;
    lookup.copy_short_check(layouter.namespace(|| "mid top6"), zs[12].clone(), 6)?;

    // low: 13 words strict, then constrain top word to 8 bits.
    let zs = lookup.copy_check(layouter.namespace(|| "low rc"), low.clone(), 13, true)?;
    lookup.copy_short_check(layouter.namespace(|| "low top8"), zs[12].clone(), 8)?;

    // d: 13 words strict, then constrain top word to 8 bits.
    let zs = lookup.copy_check(layouter.namespace(|| "d rc"), d.clone(), 13, true)?;
    lookup.copy_short_check(layouter.namespace(|| "d top8"), zs[12].clone(), 8)?;

    Ok((msb, mid, low))
}

fn lt_nbits(
    config: &Config,
    layouter: &mut impl Layouter<pallas::Base>,
    a: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    b: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    n: u8,
) -> Result<halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
    debug_assert!(n <= 128);
    let two_pow_const = match n {
        128 => two_pow_128(),
        0..=127 => pallas::Base::from_u128(1u128 << n),
        _ => unreachable!("lt_nbits only supports n in 0..=128"),
    };
    let two_pow_v = Value::known(two_pow_const);
    let lt_v = a.value().zip(b.value()).map(|(a, b)| {
        let a_u = u128::from_le_bytes(a.to_repr()[0..16].try_into().unwrap());
        let b_u = u128::from_le_bytes(b.to_repr()[0..16].try_into().unwrap());
        pallas::Base::from(u64::from(a_u < b_u))
    });
    let diff_v = a.value().zip(b.value()).map(|(a, b)| {
        let a_u = u128::from_le_bytes(a.to_repr()[0..16].try_into().unwrap());
        let b_u = u128::from_le_bytes(b.to_repr()[0..16].try_into().unwrap());
        let diff = if a_u < b_u {
            match n {
                128 => a_u.wrapping_sub(b_u),
                0..=127 => (a_u + (1u128 << n)).wrapping_sub(b_u),
                _ => 0u128,
            }
        } else {
            a_u.wrapping_sub(b_u)
        };
        pallas::Base::from_u128(diff)
    });

    let lt = layouter.assign_region(
        || format!("lt_{n}"),
        |mut region| {
            let a0 = a.copy_advice(|| "a", &mut region, config.advices[0], 0)?;
            let b0 = b.copy_advice(|| "b", &mut region, config.advices[1], 0)?;
            let lt = region.assign_advice(|| "lt", config.advices[2], 0, || lt_v)?;
            let diff = region.assign_advice(|| "diff", config.advices[3], 0, || diff_v)?;
            let pow2 = region.assign_advice(|| "2^n", config.advices[4], 0, || two_pow_v)?;
            region.constrain_constant(pow2.cell(), two_pow_const)?;
            config.q_lt.enable(&mut region, 0)?;
            let _ = (a0, b0);
            Ok((lt, diff))
        },
    )?;

    // Range check diff to n bits (n <= 128 in this circuit).
    let lookup = config.sinsemilla_chip_1().config().lookup_config();
    let num_words = (n as usize).div_ceil(10);
    let top_bits = (n as usize) - (num_words - 1) * 10;
    let zs = lookup.copy_check(
        layouter.namespace(|| format!("diff rc {n}")),
        lt.1.clone(),
        num_words,
        true,
    )?;
    if top_bits < 10 {
        lookup.copy_short_check(
            layouter.namespace(|| format!("diff top {top_bits}")),
            zs[num_words - 1].clone(),
            top_bits,
        )?;
    }

    Ok(lt.0)
}

fn assert_order_255(
    config: &Config,
    layouter: &mut impl Layouter<pallas::Base>,
    a_msb: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    b_msb: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    mid_lt: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    mid_gt: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    low_lt: halo2_proofs::circuit::AssignedCell<pallas::Base, pallas::Base>,
    name: &str,
) -> Result<(), plonk::Error> {
    layouter.assign_region(
        || format!("order {name}"),
        |mut region| {
            a_msb.copy_advice(|| "a_msb", &mut region, config.advices[0], 0)?;
            b_msb.copy_advice(|| "b_msb", &mut region, config.advices[1], 0)?;
            mid_lt.copy_advice(|| "mid_lt", &mut region, config.advices[2], 0)?;
            mid_gt.copy_advice(|| "mid_gt", &mut region, config.advices[3], 0)?;
            low_lt.copy_advice(|| "low_lt", &mut region, config.advices[4], 0)?;
            config.q_order.enable(&mut region, 0)?;
            Ok(())
        },
    )
}

impl Circuit {
    /// Helper constructor from basic note components.
    ///
    /// This is intended for external tooling: it derives `psi` and `rcm` from `rseed` and `rho`,
    /// and constructs a circuit witness.
    pub fn from_parts(
        note_path: [pallas::Base; MERKLE_DEPTH_ORCHARD],
        note_pos: u32,
        g_d: pallas::Affine,
        pk_d: pallas::Affine,
        value: NoteValue,
        rho_bytes: [u8; 32],
        rseed_bytes: [u8; 32],
        alpha: pallas::Scalar,
        ak_p: pallas::Affine,
        nk: pallas::Base,
        rivk: pallas::Scalar,
        rcv: ValueCommitTrapdoor,
        left: pallas::Base,
        right: pallas::Base,
        gap_path: [pallas::Base; MERKLE_DEPTH_ORCHARD],
        gap_pos: u32,
    ) -> Option<Self> {
        if bool::from(g_d.coordinates().is_none()) ||
            bool::from(pk_d.coordinates().is_none()) ||
            bool::from(ak_p.coordinates().is_none())
        {
            return None;
        }

        let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho))?;
        let psi = rseed.psi(&rho);
        let rcm = rseed.rcm_scalar(&rho);

        Some(Self {
            target_id: [0u8; 32],
            target_id_len: 0,
            note_path: Value::known(note_path),
            note_pos: Value::known(note_pos),
            g_d: Value::known(g_d),
            pk_d: Value::known(pk_d),
            value: Value::known(value),
            rho: Value::known(rho.into_inner()),
            psi: Value::known(psi),
            rcm: Value::known(rcm),
            alpha: Value::known(alpha),
            ak_p: Value::known(ak_p),
            nk: Value::known(nk),
            rivk: Value::known(rivk),
            rcv: Value::known(rcv),
            value_commitment_scheme: ValueCommitmentScheme::Native,
            rcv_sha256: Value::unknown(),
            left: Value::known(left),
            right: Value::known(right),
            gap_path: Value::known(gap_path),
            gap_pos: Value::known(gap_pos),
        })
    }
}
