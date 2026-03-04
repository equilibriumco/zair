# Airdrop Proofs: Sapling

The Sapling claim proof is a Groth16 proof adapted from the Sapling Spend circuit.

Implementation:

- Circuit: `crates/zair-sapling-circuit/`
- Prover / verifier: `crates/zair-sapling-proofs/`

Patched dependency:

- `sapling-crypto/` from [https://github.com/eigerco/sapling-crypto](/url)

## Proof statement

For a Sapling note, the circuit proves:

- Ownership / spend-style consistency (recipient binding and public rk)
- Snapshot inclusion: the note commitment opens to the note commitment root (anchor)
- Snapshot unspentness: for the note’s private (standard) Sapling nullifier nf, the witness provides adjacent bounds (left, right) and the circuit enforces left < nf < right, plus a
  Merkle opening of the corresponding gap leaf to the gap-root
- Double-claim prevention: a public airdrop nullifier is derived from the same nullifier preimage, using an airdrop-specific BLAKE2s personalization
- Value binding: a public value commitment matches the note value (native cv or cv_sha256)

## Public instance

The public input vector is defined by `ClaimPublicInputs::to_vec` in
`crates/zair-sapling-proofs/src/verifier/mod.rs`. The length depends on the value commitment
scheme:

- **Native**: 8 BLS12-381 scalars
  1. `rk.u`, `rk.v`: randomization key
  2. `cv.u`, `cv.v`: value commitment (native)
  3. `anchor`: note commitment tree root
  4. `hiding_nf`: airdrop nullifier (256 bits multipacked into 2 scalars)
  5. `nm_anchor`: spent-nullifier gap-tree root

- **SHA-256**: 8 BLS12-381 scalars
  1. `rk.u`, `rk.v`: randomization key
  2. `cv_sha256`: value commitment (256-bit digest multipacked into 2 scalars)
  3. `anchor`: note commitment tree root
  4. `hiding_nf`: airdrop nullifier (multipacked into 2 scalars)
  5. `nm_anchor`: spent-nullifier gap-tree root

The standard Zcash nullifier `nf` is computed in-circuit but is never a public input.

## Private witness

Spend-style (reused from Sapling Spend):

- `ak`, `nsk`: proof generation key, derives `rk` and `nk`
- `alpha` (`ar`): randomization scalar for `rk`
- `g_d`: from diversifier, used to derive `pk_d`
- `rcv`: value commitment randomness
- `rcm`: note commitment randomness
- `auth_path`: Merkle path to `anchor`
- `value`: note value

ZAIR-specific:

- `nm_left_nf`, `nm_right_nf`: 32-byte gap bounds
- `nm_merkle_path`: gap-tree Merkle path to `nm_anchor`.
- `rcv_sha256`: 32-byte randomness (used only with the SHA-256 scheme)

```admonish note
Standard Sapling Spend-circuits skips anchor equality when `value = 0` via constraint:

$$(root_{anchor} - root_{computed}) \cdot value = 0$$

We remove this feature and always require root equality:

$$root_{anchor} - root_{computed} = 0$$

```
