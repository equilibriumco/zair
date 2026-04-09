# Security

## Audit and Status

```admonish warning
This project is under active development and has not been externally audited.
```

## Trust assumptions

- **Sapling trusted setup**: the Sapling claim circuit uses Groth16, which requires a trusted setup to produce the proving and verifying keys. The `zair setup sapling` command generates keys locally for testing. A production deployment would need a trusted multi-party ceremony.
- **Orchard (no trusted setup)**: the Orchard claim circuit uses Halo2, which relies on a universal SRS (structured reference string) and does not require a per-circuit trusted setup.
- **lightwalletd**: the `config build` and `claim prepare` steps connect to a lightwalletd node to fetch chain data. A malicious node could serve incorrect nullifier sets or note commitment trees. In production, the organizer should verify snapshot data against a trusted full node.

## Privacy guarantees

The goal of the ZK proofs is protecting **private** information:

- The Zcash nullifier of any claimed note.
- The value of any claimed notes.
- The note position of any claimed notes.

The following information is **public** per claim:

- An airdrop-scoped nullifier.
- A value commitment (native Pedersen, SHA256, or plain value).
- A randomized verification key.
