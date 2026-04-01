//! The Sapling Claim circuit.
//!
//! This circuit replicates the Sapling Spend circuit to prove ownership of an unspent note.
//! It will be extended with non-membership proofs for the airdrop claim.

// ZK circuit code requires patterns that trigger these lints.
// The code closely follows the original Sapling Spend circuit implementation.

use bellman::gadgets::{Assignment, blake2s, boolean, multipack, num, sha256};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use group::ff::PrimeField;
use sapling::circuit::constants::{
    NOTE_COMMITMENT_RANDOMNESS_GENERATOR, NULLIFIER_POSITION_GENERATOR,
    PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
    VALUE_COMMITMENT_VALUE_GENERATOR,
};
use sapling::circuit::{ecc, pedersen_hash};
use sapling::constants::{CRH_IVK_PERSONALIZATION, PRF_NF_PERSONALIZATION};
use sapling::value::NoteValue;
use sapling::{PaymentAddress, ProofGenerationKey};

use crate::gadgets::enforce_less_than;

/// Personalization for the hiding nullifier (airdrop-specific).
/// This is used to derive a nullifier that doesn't reveal the Zcash nullifier.
pub const HIDING_NF_PERSONALIZATION: &[u8; 8] = b"ZAIRTEST";

/// Prefix for SHA-256 value commitments (`cv_sha256`).
pub const VALUE_COMMIT_SHA256_PREFIX: &[u8; 4] = &zair_core::base::VALUE_COMMIT_SHA256_PREFIX;

/// The opening (value and randomness) of a Sapling value commitment.
#[derive(Clone)]
pub struct ValueCommitmentOpening {
    /// The note value.
    pub value: NoteValue,
    /// The randomness for the value commitment.
    pub randomness: jubjub::Scalar,
}

/// Which value commitment is exposed by the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ValueCommitmentScheme {
    /// Expose the native Sapling value commitment point.
    #[default]
    Native,
    /// Expose a SHA-256 value commitment digest.
    Sha256,
    /// Expose the note value directly as a public input (no commitment).
    Plain,
}

/// Level used for hashing nullifier pairs into non-membership tree leaves.
///
/// This provides domain separation from internal Pedersen hashes which use
/// levels 0-31. Using level 62 (max valid for Sapling Pedersen hash, which
/// requires level < 63) ensures no collision with any internal node hash.
pub const NM_LEAF_HASH_LEVEL: usize = 62;

/// This is an instance of the `Claim` circuit.
///
/// This circuit proves ownership of a Sapling note by demonstrating:
/// 1. Knowledge of the spending key (via `proof_generation_key`)
/// 2. The note commitment is in the Merkle tree
/// 3. The nullifier is correctly computed
/// 4. The nullifier is NOT in the spent nullifier set (non-membership proof)
#[derive(Clone)]
pub struct Claim {
    /// The opening of a Pedersen commitment to the value being spent.
    pub value_commitment_opening: Option<ValueCommitmentOpening>,

    /// Key required to construct proofs for spending notes
    /// for a particular spending key
    pub proof_generation_key: Option<ProofGenerationKey>,

    /// The payment address associated with the note
    pub payment_address: Option<PaymentAddress>,

    /// The randomness of the note commitment
    pub commitment_randomness: Option<jubjub::Fr>,

    /// Re-randomization of the public key
    pub ar: Option<jubjub::Fr>,

    /// The authentication path of the commitment in the tree
    pub auth_path: Vec<Option<(bls12_381::Scalar, bool)>>,

    /// The anchor; the root of the tree. If the note being
    /// spent is zero-value, this can be anything.
    pub anchor: Option<bls12_381::Scalar>,

    // =========================================================================
    // Non-membership proof inputs
    // =========================================================================
    /// The left nullifier bound of the gap (must be < the Zcash nullifier).
    /// For the leftmost gap, this is all zeros.
    pub nm_left_nf: Option<[u8; 32]>,

    /// The right nullifier bound of the gap (must be > the Zcash nullifier).
    /// For the rightmost gap, this is all ones.
    pub nm_right_nf: Option<[u8; 32]>,

    /// The merkle path in the non-membership tree.
    pub nm_merkle_path: Vec<Option<(bls12_381::Scalar, bool)>>,

    /// The root of the non-membership tree.
    pub nm_anchor: Option<bls12_381::Scalar>,

    /// Which value commitment scheme to expose publicly.
    pub value_commitment_scheme: ValueCommitmentScheme,

    /// Randomness used for SHA-256 value commitment preimage.
    pub rcv_sha256: Option<[u8; 32]>,
}

impl core::fmt::Debug for Claim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Claim")
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}

/// Traverse a Merkle tree path in the circuit, computing the root.
///
/// Returns the computed root and the position bits (one bit per level indicating left/right).
fn merkle_tree_traverse<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: &mut CS,
    initial: num::AllocatedNum<bls12_381::Scalar>,
    path: Vec<Option<(bls12_381::Scalar, bool)>>,
    namespace_prefix: &str,
) -> Result<(num::AllocatedNum<bls12_381::Scalar>, Vec<boolean::Boolean>), SynthesisError> {
    let mut position_bits = vec![];
    let mut cur = initial;

    for (i, e) in path.into_iter().enumerate() {
        let cs = &mut cs.namespace(|| format!("{namespace_prefix} {i}"));

        let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
            cs.namespace(|| "position bit"),
            e.map(|e| e.1),
        )?);

        position_bits.push(cur_is_right.clone());

        let path_element =
            num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.0))?;

        let (ul, ur) = num::AllocatedNum::conditionally_reverse(
            cs.namespace(|| "conditional reversal of preimage"),
            &cur,
            &path_element,
            &cur_is_right,
        )?;

        let mut preimage = vec![];
        preimage.extend(ul.to_bits_le(cs.namespace(|| "ul into bits"))?);
        preimage.extend(ur.to_bits_le(cs.namespace(|| "ur into bits"))?);

        cur = pedersen_hash::pedersen_hash(
            cs.namespace(|| "computation of pedersen hash"),
            pedersen_hash::Personalization::MerkleTree(i),
            &preimage,
        )?
        .get_u()
        .clone();
    }

    Ok((cur, position_bits))
}

/// Witness a 32-byte array as 256 boolean bits (little-endian).
#[allow(
    clippy::indexing_slicing,
    reason = "byte ranges 0..32 and bytes is [u8; 32]"
)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "byte_idx in 0..32, bit_idx in 0..8, max result 255"
)]
fn witness_bytes_as_bits<CS>(
    mut cs: CS,
    bytes: Option<&[u8; 32]>,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    let mut bits = Vec::with_capacity(256);
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let bit = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", byte_idx * 8 + bit_idx)),
                bytes.map(|b| (b[byte_idx] >> bit_idx) & 1 == 1),
            )?);
            bits.push(bit);
        }
    }
    Ok(bits)
}

/// Computes value bits and the Sapling value commitment point.
fn compute_value_commitment<CS>(
    mut cs: CS,
    value_commitment_opening: Option<&ValueCommitmentOpening>,
) -> Result<(Vec<boolean::Boolean>, ecc::EdwardsPoint), SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Booleanize the value into little-endian bit order
    let value_bits = boolean::u64_into_boolean_vec_le(
        cs.namespace(|| "value"),
        value_commitment_opening.as_ref().map(|c| c.value.inner()),
    )?;

    // Compute the note value in the exponent
    let value = ecc::fixed_base_multiplication(
        cs.namespace(|| "compute the value in the exponent"),
        &VALUE_COMMITMENT_VALUE_GENERATOR,
        &value_bits,
    )?;

    // Booleanize the randomness. This does not ensure
    // the bit representation is "in the field" because
    // it doesn't matter for security.
    let rcv = boolean::field_into_boolean_vec_le(
        cs.namespace(|| "rcv"),
        value_commitment_opening.as_ref().map(|c| c.randomness),
    )?;

    // Compute the randomness in the exponent
    let rcv = ecc::fixed_base_multiplication(
        cs.namespace(|| "computation of rcv"),
        &VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        &rcv,
    )?;

    // Compute the Pedersen commitment to the value
    let cv = value.add(cs.namespace(|| "computation of cv"), &rcv)?;

    Ok((value_bits, cv))
}

/// Exposes a Pedersen commitment to the value as an input to the circuit.
fn expose_value_commitment<CS>(
    mut cs: CS,
    value_commitment_opening: Option<&ValueCommitmentOpening>,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    let (value_bits, cv) = compute_value_commitment(
        cs.namespace(|| "compute value commitment"),
        value_commitment_opening,
    )?;
    cv.inputize(cs.namespace(|| "commitment point"))?;
    Ok(value_bits)
}

/// Exposes the note value directly as a single public input (Plain scheme).
fn expose_plain_value<CS>(
    mut cs: CS,
    value_commitment_opening: Option<&ValueCommitmentOpening>,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Witness value bits for note commitment recomputation.
    let value_bits = boolean::u64_into_boolean_vec_le(
        cs.namespace(|| "value bits"),
        value_commitment_opening.as_ref().map(|c| c.value.inner()),
    )?;

    // Allocate the value as a single scalar public input.
    let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value num"), || {
        let v = value_commitment_opening
            .ok_or(SynthesisError::AssignmentMissing)?
            .value
            .inner();
        Ok(bls12_381::Scalar::from(v))
    })?;
    value_num.inputize(cs.namespace(|| "value public input"))?;

    // Enforce consistency: value_num == sum(value_bits[i] * 2^i).
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "Bellman linear combination arithmetic is safe and required for constraint construction"
    )]
    cs.enforce(
        || "value_num equals value_bits",
        |mut lc| {
            let mut coeff = bls12_381::Scalar::one();
            for bit in &value_bits {
                lc = lc + &bit.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + value_num.get_variable(),
    );

    Ok(value_bits)
}

#[must_use]
fn bytes_to_bits_be_const(bytes: &[u8]) -> Vec<boolean::Boolean> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(8));
    for byte in bytes {
        // Big-endian within each byte.
        out.push(boolean::Boolean::constant(byte & 0b1000_0000 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0100_0000 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0010_0000 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0001_0000 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0000_1000 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0000_0100 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0000_0010 != 0));
        out.push(boolean::Boolean::constant(byte & 0b0000_0001 != 0));
    }
    out
}

#[must_use]
fn reverse_bits_within_each_byte(bits: &[boolean::Boolean]) -> Vec<boolean::Boolean> {
    let mut out = Vec::with_capacity(bits.len());
    for byte in bits.chunks(8) {
        out.extend(byte.iter().rev().cloned());
    }
    out
}

/// Computes SHA-256 commitment bits (little-endian per byte for multipacking).
fn value_commitment_sha256_bits_le<CS>(
    mut cs: CS,
    value_bits_le: &[boolean::Boolean],
    rcv_sha256: Option<[u8; 32]>,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Preimage = PREFIX(4 bytes) || LE64(value) || rcv_sha256(32 bytes).
    let prefix_bits_be = bytes_to_bits_be_const(VALUE_COMMIT_SHA256_PREFIX);

    // Value bits are little-endian per-byte; SHA gadget expects big-endian per-byte.
    let mut value_bits_for_sha = Vec::with_capacity(64);
    for byte_bits_le in value_bits_le.chunks_exact(8) {
        value_bits_for_sha.extend(byte_bits_le.iter().rev().cloned());
    }

    let rcv_sha256_bits_input =
        witness_bytes_as_bits(cs.namespace(|| "rcv_sha256 bits"), rcv_sha256.as_ref())?;
    let rcv_sha256_bits_for_sha = reverse_bits_within_each_byte(&rcv_sha256_bits_input);

    let mut preimage_bits_be = Vec::with_capacity(352);
    preimage_bits_be.extend(prefix_bits_be);
    preimage_bits_be.extend(value_bits_for_sha);
    preimage_bits_be.extend(rcv_sha256_bits_for_sha);

    let digest_bits_be = sha256::sha256(
        cs.namespace(|| "sha256(value commitment)"),
        &preimage_bits_be,
    )?;
    Ok(reverse_bits_within_each_byte(&digest_bits_be))
}

#[allow(
    clippy::too_many_lines,
    reason = "ZK circuit synthesis is inherently complex and mirrors Sapling's structure"
)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "R1CS constraint building uses +/- operators for linear combinations"
)]
impl Circuit<bls12_381::Scalar> for Claim {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Prover witnesses ak (ensures that it's on the curve)
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| (&k.ak).into()),
        )?;

        // There are no sensible attacks on small order points
        // of ak (that we're aware of!) but it's a cheap check,
        // so we do it.
        ak.assert_not_small_order(cs.namespace(|| "ak not small order"))?;

        // Rerandomize ak and expose it as an input to the circuit
        {
            let ar = boolean::field_into_boolean_vec_le(cs.namespace(|| "ar"), self.ar)?;

            // Compute the randomness in the exponent
            let ar = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of randomization for the signing key"),
                &SPENDING_KEY_GENERATOR,
                &ar,
            )?;

            let rk = ak.add(cs.namespace(|| "computation of rk"), &ar)?;

            rk.inputize(cs.namespace(|| "rk"))?;
        }

        // Compute nk = [nsk] ProofGenerationKey
        let nk;
        {
            // Witness nsk as bits
            let nsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "nsk"),
                self.proof_generation_key.as_ref().map(|k| k.nsk),
            )?;

            // NB: We don't ensure that the bit representation of nsk
            // is "in the field" (jubjub::Fr) because it's not used
            // except to demonstrate the prover knows it. If they know
            // a congruency then that's equivalent.

            // Compute nk = [nsk] ProvingPublicKey
            nk = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of nk"),
                &PROOF_GENERATION_KEY_GENERATOR,
                &nsk,
            )?;
        }

        // This is the "viewing key" preimage for CRH^ivk
        let mut ivk_preimage = vec![];

        // Place ak in the preimage for CRH^ivk
        ivk_preimage.extend(ak.repr(cs.namespace(|| "representation of ak"))?);

        // This is the nullifier preimage for PRF^nf
        let mut nf_preimage = vec![];

        // Extend ivk and nf preimages with the representation of
        // nk.
        {
            let repr_nk = nk.repr(cs.namespace(|| "representation of nk"))?;

            ivk_preimage.extend(repr_nk.iter().cloned());
            nf_preimage.extend(repr_nk);
        }

        assert_eq!(ivk_preimage.len(), 512);
        assert_eq!(nf_preimage.len(), 256);

        // Compute the incoming viewing key ivk
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &ivk_preimage,
            CRH_IVK_PERSONALIZATION,
        )?;

        // drop_5 to ensure it's in the field
        ivk.truncate(
            usize::try_from(jubjub::Fr::CAPACITY).map_err(|_| SynthesisError::Unsatisfiable)?, // CAPACITY is ~251, always fits in usize
        );

        // Witness g_d, checking that it's on the curve.
        let g_d = {
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness g_d"),
                self.payment_address.as_ref().map(|a| {
                    a.diversifier()
                        .g_d()
                        .expect("checked at construction")
                        .into()
                }),
            )?
        };

        // Check that g_d is not small order. Technically, this check
        // is already done in the Output circuit, and this proof ensures
        // g_d is bound to a product of that check, but for defense in
        // depth let's check it anyway. It's cheap.
        g_d.assert_not_small_order(cs.namespace(|| "g_d not small order"))?;

        // Compute pk_d = g_d^ivk
        let pk_d = g_d.mul(cs.namespace(|| "compute pk_d"), &ivk)?;

        // Compute note contents:
        // value (in big endian) followed by g_d and pk_d
        let mut note_contents = vec![];

        // Expose the configured value commitment and keep the note value bits
        // for note-commitment recomputation.
        let value_bits = match self.value_commitment_scheme {
            ValueCommitmentScheme::Native => expose_value_commitment(
                cs.namespace(|| "value commitment"),
                self.value_commitment_opening.as_ref(),
            )?,
            ValueCommitmentScheme::Sha256 => {
                let (value_bits, _) = compute_value_commitment(
                    cs.namespace(|| "compute value commitment"),
                    self.value_commitment_opening.as_ref(),
                )?;
                let digest_bits_le = value_commitment_sha256_bits_le(
                    cs.namespace(|| "value commitment sha256"),
                    &value_bits,
                    self.rcv_sha256,
                )?;
                multipack::pack_into_inputs(
                    cs.namespace(|| "pack value commitment sha256"),
                    &digest_bits_le,
                )?;
                value_bits
            }
            ValueCommitmentScheme::Plain => expose_plain_value(
                cs.namespace(|| "plain value"),
                self.value_commitment_opening.as_ref(),
            )?,
        };
        note_contents.extend(value_bits);

        // Place g_d in the note
        note_contents.extend(g_d.repr(cs.namespace(|| "representation of g_d"))?);

        // Place pk_d in the note
        note_contents.extend(pk_d.repr(cs.namespace(|| "representation of pk_d"))?);

        assert_eq!(
            note_contents.len(),
            64 + // value
            256 + // g_d
            256 // p_d
        );

        // Compute the hash of the note contents
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
        )?;

        {
            // Booleanize the randomness for the note commitment
            let rcm = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "rcm"),
                self.commitment_randomness,
            )?;

            // Compute the note commitment randomness in the exponent
            let rcm = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of commitment randomness"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &rcm,
            )?;

            // Randomize the note commitment. Pedersen hashes are not
            // themselves hiding commitments.
            cm = cm.add(cs.namespace(|| "randomization of note commitment"), &rcm)?;
        }

        // Ascend the merkle tree authentication path, collecting position bits for nullifier
        let (cur, position_bits) =
            merkle_tree_traverse(cs, cm.get_u().clone(), self.auth_path, "merkle tree hash")?;

        {
            let real_anchor_value = self.anchor;

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                Ok(*real_anchor_value.get()?)
            })?;

            // Always enforce note-tree root equality for airdrop claims.
            cs.enforce(
                || "enforce correct root",
                |lc| lc + cur.get_variable() - rt.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))?;
        }

        // Compute the cm + g^position for preventing
        // faerie gold attacks
        let mut rho = cm;
        {
            // Compute the position in the exponent
            let position = ecc::fixed_base_multiplication(
                cs.namespace(|| "g^position"),
                &NULLIFIER_POSITION_GENERATOR,
                &position_bits,
            )?;

            // Add the position to the commitment
            rho = rho.add(cs.namespace(|| "faerie gold prevention"), &position)?;
        }

        // Let's compute nf = BLAKE2s(nk || rho)
        nf_preimage.extend(rho.repr(cs.namespace(|| "representation of rho"))?);

        assert_eq!(nf_preimage.len(), 512);

        // Compute the Zcash nullifier (not exposed - used for non-membership proof)
        let nf = blake2s::blake2s(
            cs.namespace(|| "nf computation"),
            &nf_preimage,
            PRF_NF_PERSONALIZATION,
        )?;

        // Compute the hiding nullifier for the airdrop
        // This uses the same preimage (nk || rho) but with a different personalization
        let hiding_nf = blake2s::blake2s(
            cs.namespace(|| "hiding nf computation"),
            &nf_preimage,
            HIDING_NF_PERSONALIZATION,
        )?;

        // Expose the hiding nullifier as a public input
        multipack::pack_into_inputs(cs.namespace(|| "pack hiding nullifier"), &hiding_nf)?;

        // =====================================================================
        // Non-membership proof: verify the Zcash nullifier is not in the spent set
        // =====================================================================

        // Witness the left nullifier bound (as bits, little-endian)
        let nm_left_nf_bits =
            witness_bytes_as_bits(cs.namespace(|| "nm left nf bits"), self.nm_left_nf.as_ref())?;

        // Witness the right nullifier bound (as bits, little-endian)
        let nm_right_nf_bits = witness_bytes_as_bits(
            cs.namespace(|| "nm right nf bits"),
            self.nm_right_nf.as_ref(),
        )?;

        // Enforce: left_nf < nf < right_nf (lexicographic ordering)
        // This proves the nullifier lies within the gap (i.e., it's not in the spent set)
        // Uses lexicographic comparison to match the non-membership tree's ordering
        enforce_less_than(cs.namespace(|| "left_nf < nf"), &nm_left_nf_bits, &nf)?;
        enforce_less_than(cs.namespace(|| "nf < right_nf"), &nf, &nm_right_nf_bits)?;

        // Compute the non-membership leaf hash: pedersen_hash(level=62, left_nf || right_nf)
        // This uses level 62 for domain separation from internal nodes (levels 0-31)
        let mut nm_leaf_preimage = vec![];
        nm_leaf_preimage.extend(nm_left_nf_bits);
        nm_leaf_preimage.extend(nm_right_nf_bits);

        let nm_leaf = pedersen_hash::pedersen_hash(
            cs.namespace(|| "nm leaf hash"),
            pedersen_hash::Personalization::MerkleTree(NM_LEAF_HASH_LEVEL),
            &nm_leaf_preimage,
        )?;

        // Ascend the non-membership merkle tree
        let (nm_cur, _) = merkle_tree_traverse(
            cs,
            nm_leaf.get_u().clone(),
            self.nm_merkle_path,
            "nm merkle tree hash",
        )?;

        // Expose the non-membership anchor as a public input
        {
            let nm_anchor_value = self.nm_anchor;

            let nm_rt = num::AllocatedNum::alloc(cs.namespace(|| "nm anchor"), || {
                Ok(*nm_anchor_value.get()?)
            })?;

            // Enforce that the computed root matches the claimed anchor
            cs.enforce(
                || "enforce correct nm root",
                |lc| lc + nm_cur.get_variable() - nm_rt.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );

            // Expose the nm anchor
            nm_rt.inputize(cs.namespace(|| "nm anchor input"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::too_many_lines,
        clippy::as_conversions,
        reason = "unit-test"
    )]

    use bellman::gadgets::test::TestConstraintSystem;
    use group::ff::{Field, PrimeFieldBits};
    use group::{Curve, Group, GroupEncoding};
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sapling::keys::SpendValidatingKey;
    use sapling::{Diversifier, Note, Rseed};

    use super::*;

    #[test]
    fn test_claim_circuit_with_bls12_381() {
        let mut rng = XorShiftRng::from_seed([
            0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let tree_depth = 32;

        for _ in 0..10 {
            let value_commitment = ValueCommitmentOpening {
                value: NoteValue::from_raw(rng.next_u64()),
                randomness: jubjub::Fr::random(&mut rng),
            };

            // Generate a valid SpendValidatingKey by trying random subgroup points
            let ak = loop {
                let point = jubjub::SubgroupPoint::random(&mut rng);
                if let Some(k) = SpendValidatingKey::from_bytes(&point.to_bytes()) {
                    break k;
                }
            };

            let proof_generation_key = ProofGenerationKey {
                ak,
                nsk: jubjub::Fr::random(&mut rng),
            };

            let viewing_key = proof_generation_key.to_viewing_key();

            let payment_address;

            loop {
                let diversifier = {
                    let mut d = [0; 11];
                    rng.fill_bytes(&mut d);
                    Diversifier(d)
                };

                if let Some(p) = viewing_key.to_payment_address(diversifier) {
                    payment_address = p;
                    break;
                }
            }

            let commitment_randomness = jubjub::Fr::random(&mut rng);
            let auth_path = vec![
                Some((
                    bls12_381::Scalar::random(&mut rng),
                    !rng.next_u32() % 2 == 0
                ));
                tree_depth
            ];
            let ar = jubjub::Fr::random(&mut rng);

            // Non-membership proof inputs
            // Use bounds that will always satisfy left_nf < nf < right_nf:
            // - left bound = 0 (smallest possible value)
            // - right bound = max (largest possible value)
            // Any blake2s output will satisfy 0 < nf < max
            let nm_left_nf = [0u8; 32];
            let nm_right_nf = [0xFFu8; 32];

            let nm_merkle_path: Vec<Option<(bls12_381::Scalar, bool)>> = (0..tree_depth)
                .map(|_| {
                    Some((
                        bls12_381::Scalar::random(&mut rng),
                        !rng.next_u32() % 2 == 0,
                    ))
                })
                .collect();

            {
                let rk =
                    jubjub::AffinePoint::from_bytes(viewing_key.rk(ar).into()).expect("valid rk");
                let expected_value_commitment = {
                    let cv = (sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR *
                        jubjub::Fr::from(value_commitment.value.inner())) +
                        (sapling::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR *
                            value_commitment.randomness);
                    jubjub::ExtendedPoint::from(cv).to_affine()
                };
                let note = Note::from_parts(
                    payment_address,
                    value_commitment.value,
                    Rseed::BeforeZip212(commitment_randomness),
                );

                let cmu = note.cmu();
                let mut cur = bls12_381::Scalar::from_bytes(&cmu.to_bytes()).expect("valid cmu");

                for (i, val) in auth_path.clone().into_iter().enumerate() {
                    let (uncle, b) = val.expect("auth path element");

                    let mut lhs = cur;
                    let mut rhs = uncle;

                    if b {
                        core::mem::swap(&mut lhs, &mut rhs);
                    }

                    let lhs = lhs.to_le_bits();
                    let rhs = rhs.to_le_bits();

                    cur = jubjub::ExtendedPoint::from(sapling::pedersen_hash::pedersen_hash(
                        sapling::pedersen_hash::Personalization::MerkleTree(i),
                        lhs.iter()
                            .by_vals()
                            .take(bls12_381::Scalar::NUM_BITS as usize)
                            .chain(
                                rhs.iter()
                                    .by_vals()
                                    .take(bls12_381::Scalar::NUM_BITS as usize),
                            ),
                    ))
                    .to_affine()
                    .get_u();
                }

                // Note: nullifier is computed inside the circuit but NOT exposed
                // (to preserve privacy for the airdrop claim)

                // Compute expected nm_anchor from leaf and merkle path
                let nm_anchor = {
                    // Compute leaf hash: pedersen_hash(level=62, left_nf || right_nf)
                    let left_bits = nm_left_nf
                        .iter()
                        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1));
                    let right_bits = nm_right_nf
                        .iter()
                        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1));

                    let mut nm_cur =
                        jubjub::ExtendedPoint::from(sapling::pedersen_hash::pedersen_hash(
                            sapling::pedersen_hash::Personalization::MerkleTree(NM_LEAF_HASH_LEVEL),
                            left_bits.chain(right_bits),
                        ))
                        .to_affine()
                        .get_u();

                    // Ascend the nm merkle tree
                    for (i, val) in nm_merkle_path.iter().enumerate() {
                        let (uncle, b) = val.expect("nm path element");

                        let mut lhs = nm_cur;
                        let mut rhs = uncle;

                        if b {
                            core::mem::swap(&mut lhs, &mut rhs);
                        }

                        let lhs = lhs.to_le_bits();
                        let rhs = rhs.to_le_bits();

                        nm_cur =
                            jubjub::ExtendedPoint::from(sapling::pedersen_hash::pedersen_hash(
                                sapling::pedersen_hash::Personalization::MerkleTree(i),
                                lhs.iter()
                                    .by_vals()
                                    .take(bls12_381::Scalar::NUM_BITS as usize)
                                    .chain(
                                        rhs.iter()
                                            .by_vals()
                                            .take(bls12_381::Scalar::NUM_BITS as usize),
                                    ),
                            ))
                            .to_affine()
                            .get_u();
                    }

                    nm_cur
                };

                let mut cs = TestConstraintSystem::new();

                let instance = Claim {
                    value_commitment_opening: Some(value_commitment.clone()),
                    proof_generation_key: Some(proof_generation_key.clone()),
                    payment_address: Some(payment_address),
                    commitment_randomness: Some(commitment_randomness),
                    ar: Some(ar),
                    auth_path: auth_path.clone(),
                    anchor: Some(cur),
                    nm_left_nf: Some(nm_left_nf),
                    nm_right_nf: Some(nm_right_nf),
                    nm_merkle_path: nm_merkle_path.clone(),
                    nm_anchor: Some(nm_anchor),
                    value_commitment_scheme: ValueCommitmentScheme::Native,
                    rcv_sha256: None,
                };

                instance.synthesize(&mut cs).expect("synthesis failed");

                assert!(cs.is_satisfied());
                // Circuit constraints breakdown:
                // - 98775 base Sapling spend (nullifier not packed)
                // - +21006 for hiding nullifier blake2s
                // - +2 for multipack (hiding_nf)
                // - +1750 for nm leaf hash (pedersen of 512 bits)
                // - +32 * ~1413 for nm merkle path (32 pedersen hashes of 512 bits each)
                // - +1 for nm_anchor enforcement
                // - +6 for packing bits to limbs (3 limb packs * 2 constraints each)
                // - +2070 for two u256 comparisons (limb-based subtraction with range checks)
                // Total: 167949 (bit-by-bit lexicographic comparison)
                assert_eq!(cs.num_constraints(), 167_949_usize);

                assert_eq!(
                    cs.get("randomization of note commitment/u3/num").to_repr(),
                    cmu.to_bytes()
                );

                // 9 public inputs: ONE, rk.u, rk.v, cv.u, cv.v, anchor, hiding_nf[0], hiding_nf[1],
                // nm_anchor The Zcash nullifier is NOT exposed (computed internally
                // for integrity) The hiding nullifier IS exposed (for airdrop
                // double-claim prevention) The nm_anchor IS exposed (for
                // non-membership verification)
                assert_eq!(cs.num_inputs(), 9);
                assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
                assert_eq!(cs.get_input(1, "rk/u/input variable"), rk.get_u());
                assert_eq!(cs.get_input(2, "rk/v/input variable"), rk.get_v());
                assert_eq!(
                    cs.get_input(3, "value commitment/commitment point/u/input variable"),
                    expected_value_commitment.get_u()
                );
                assert_eq!(
                    cs.get_input(4, "value commitment/commitment point/v/input variable"),
                    expected_value_commitment.get_v()
                );
                assert_eq!(
                    cs.get_input(5, "anchor/input variable").to_repr(),
                    cur.to_bytes()
                );
                // hiding_nf inputs at indices 6 and 7 are verified by the circuit
                assert_eq!(
                    cs.get_input(8, "nm anchor input/input variable").to_repr(),
                    nm_anchor.to_bytes()
                );
            }
        }
    }
}
