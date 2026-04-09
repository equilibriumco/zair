# Airdrop Proofs: Orchard

Orchard claim proofs are Halo2 proofs adapted from the Orchard Action spend circuit.

Implementation:

- Circuit: `crates/zair-orchard-circuit/`
- Prover / verifier: `crates/zair-orchard-proofs/`

Patched dependencies:

- `orchard/` from [https://github.com/eigerco/orchard](/url)
- `halo2-gadgets/` from [https://github.com/eigerco/halo2](/url)

## Proof statement

For an Orchard note, the circuit proves:

- Ownership / spend-style consistency (recipient binding and public rk)
- Snapshot inclusion: the note commitment opens to the note commitment root (note_anchor)
- Snapshot unspentness: for the note’s private (standard) Orchard nullifier nf_old, the witness provides adjacent bounds (left, right) and the circuit enforces left < nf_old < right,
  plus a Merkle opening of the corresponding gap leaf to the gap-root
- Double-claim prevention: a public airdrop nullifier is derived from the same nullifier preimage, using an airdrop-specific nullifier basepoint derived from target_id
- Value binding: a public value commitment matches the note value (native cv, cv_sha256, or plain value)

## Public instance

The instance layout is defined by `Instance::to_halo2_instance` in
`crates/zair-orchard-circuit/src/circuit/airdrop.rs`. The length depends on the value commitment
scheme:

- **Native**: 7 field elements
  1. `rk.x`, `rk.y`
  2. `cv.x`, `cv.y`
  3. `note_anchor`
  4. `gap_root`
  5. `airdrop_nf`

- **SHA-256**: 13 field elements
  1. `rk.x`, `rk.y`
  2. `cv_sha256` as 8 words (`u32::from_be_bytes(digest[4i..4i+4])` for i=0..7)
  3. `note_anchor`
  4. `gap_root`
  5. `airdrop_nf`

- **Plain**: 6 field elements
  1. `rk.x`, `rk.y`
  2. `value`: note value (single field element)
  3. `note_anchor`
  4. `gap_root`
  5. `airdrop_nf`

The standard Zcash nullifier `nf_old` is computed in-circuit but is never a public input.

## Private witness

Spend-style (adapted from Orchard Action):

- `g_d`: diversified basepoint (recipient)
- `pk_d`: diversified transmission key (recipient)
- `value`: note value
- `rho`: note randomness input
- `psi`: note scalar (derived host-side from rseed + rho, witnessed in-circuit)
- `rcm: note`: commitment trapdoor (derived host-side from rseed + rho, witnessed in-circuit)
- `note_pos`: note commitment tree leaf position
- `note_path`: note commitment tree Merkle path (siblings, leaf-to-root)
- `ak_p`: spend authorizing key (point)
- `nk`: nullifier deriving key (field element)
- `rivk`: randomized incoming viewing key component (scalar)
- `alpha`: randomizer for rk
- `rcv`: native value commitment trapdoor (used when value_commitment_scheme = Native)
- `rcv_sha256`: SHA-256 value commitment randomness (used when value_commitment_scheme = Sha256)
- Neither `rcv` nor `rcv_sha256` is used when value_commitment_scheme = Plain

ZAIR-specific:

- `target_id`: airdrop target id bytes
- `target_id_len`: length of target_id in bytes
- `left`: gap lower bound (enforce left < nf_old)
- `right`: gap upper bound (enforce nf_old < right)
- `gap_pos`: gap-tree leaf position
- `gap_path`: gap-tree Merkle path (siblings, leaf-to-root)
