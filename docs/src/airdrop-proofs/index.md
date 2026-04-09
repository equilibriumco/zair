# Airdrop Proofs

Our tool produces one ZK proof per eligible shielded note:

- [Sapling](./sapling.md) (Groth16 / bellman; adapted from Sapling Spend)
- [Orchard](./orchard.md) (Halo2; adapted from Orchard Action):

These are **not** Zcash spend proofs. They prove note ownership and snapshot eligibility
without authorizing a transaction, and expose an airdrop-scoped nullifier for double-claim
prevention.

## What the ZK proof establishes (high level)

In-circuit (pool-specific details in sub-sections):

- Ownership/spend consistency (recipient binding + public `rk`)
- Snapshot inclusion (note membership of the note commitment root)
- Snapshot unspentness (gap-tree non-membership against the spent-nullifier gap-root)
- Airdrop nullifier derivation (public, domain-separated from Zcash nullifier)
- Value binding via `cv` (native), `cv_sha256` (SHA-256 scheme), or plain value

Outside the circuit:

- A spend-authorizing signature under `rk` binds the proof to an external message/context.

## Crate layout

Each pool has two crates and one or more patched upstream dependencies:

|                   | Sapling                | Orchard                    |
| ----------------- | ---------------------- | -------------------------- |
| Circuit           | `zair-sapling-circuit` | `zair-orchard-circuit`     |
| Prover / verifier | `zair-sapling-proofs`  | `zair-orchard-proofs`      |
| Patched deps      | `sapling-crypto`       | `orchard`, `halo2-gadgets` |

The patches expose internal APIs (nullifier derivation with configurable domain, Pedersen/Sinsemilla
hash internals, key types) so that host-side code can compute the same airdrop nullifiers and
commitments that the circuits enforce. See the per-pool pages for details.

## Key differences from standard Zcash spend circuits

Both circuits are closely aligned with the Sapling Spend Circuit and the Orchard Spend Action and reuse their note-integrity and ownership checks (recipient binding, `rk` derivation, note commitment, Merkle membership).
The ZAIR-specific additions are:

**Airdrop nullifier.**
The circuit computes _two_ nullifiers from the same preimage: the standard Zcash nullifier
(kept private) and an airdrop nullifier under a domain-separated derivation (exposed as a
public input). Sapling uses BLAKE2s with a different personalization (`b"ZAIRTEST"`); Orchard
uses a different hash-to-curve basepoint derived from a `target_id` string.

**Gap-tree non-membership.**
Instead of exposing the real nullifier for double-spend prevention, the circuit proves that
the private nullifier falls inside a gap in the sorted spent-nullifier set. The prover
witnesses adjacent bounds (`left < nf < right`) and a Merkle path to the gap-tree root.
Leaf hashing uses level 62 for domain separation from internal note-tree levels.

**Unconditional note-anchor binding (Sapling).**
Upstream Sapling Spend skips anchor enforcement for zero-value dummy spends. ZAIR always
enforces the note commitment root, so even zero-valued notes are bound to the snapshot.

**SHA-256 value commitment (optional).**
When the `sha256` scheme is selected, the circuit computes
`SHA256(b"Zair" || LE64(value) || rcv_sha256)` and exposes the digest as public input
instead of the native Pedersen commitment point. Orchard's SHA-256 mode uses the Table16
gadget from patched `halo2-gadgets` and requires K=17 (vs K=12 for native, and K=11 for standard spend).

**Plain value exposure (optional).**
When the `plain` scheme is selected, the note value is exposed directly as a single public
field element with no commitment or randomness. This provides no value privacy but produces
a simpler proof with fewer public inputs. Both Sapling and Orchard use K=12 for this mode.
