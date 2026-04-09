# `zair config`

Build the airdrop snapshot configuration from on-chain data.

## `zair config build`

Connects to a lightwalletd node, fetches Sapling and/or Orchard nullifiers up to the snapshot height, builds gap trees for non-membership proofs, and writes the configuration and artifacts to files.

```bash
zair config build --network testnet --height 3663119
```

### Parameters

| Flag             | Default     | Description                           |
| ---------------- | ----------- | ------------------------------------- |
| `--network`      | `mainnet`   | Network: `mainnet` or `testnet`       |
| `--height`       | (required)  | Height of snapshot                    |
| `--lightwalletd` | (hardcoded) | Endpoint for lightwalletd             |
| `--pool`         | `both`      | Pool: `sapling`, `orchard`, or `both` |

### Airdrop parameters

| Flag               | Default      | Description                                                         |
| ------------------ | ------------ | ------------------------------------------------------------------- |
| `--target-sapling` | `ZAIRTEST`   | Sapling target ID for hiding nullifier derivation (exactly 8 bytes) |
| `--target-orchard` | `ZAIRTEST:O` | Orchard target ID for hiding nullifier derivation (up to 32 bytes)  |
| `--scheme-sapling` | `native`     | Sapling value commitment scheme: `native`, `sha256`, or `plain`     |
| `--scheme-orchard` | `native`     | Orchard value commitment scheme: `native`, `sha256`, or `plain`     |

```admonish info
When choosing a custom `--target-sapling` for deployment, you must update the constant

`HIDING_NF_PERSONALIZATION = "ZAIRTEST"`

in

`crates/zair-sapling-circuit/src/circuit.rs`

as well, and run a trusted setup for Sapling using the new custom circuit.
```

### Output files

| Flag                     | Default                | Description                      |
| ------------------------ | ---------------------- | -------------------------------- |
| `--config-out`           | `config.json`          | Configuration output             |
| `--snapshot-out-sapling` | `snapshot-sapling.bin` | Sapling snapshot nullifiers      |
| `--snapshot-out-orchard` | `snapshot-orchard.bin` | Orchard snapshot nullifiers      |
| `--gap-tree-out-sapling` | `gaptree-sapling.bin`  | Sapling gap tree                 |
| `--gap-tree-out-orchard` | `gaptree-orchard.bin`  | Orchard gap tree                 |
| `--no-gap-tree`          | `false`                | Do not output gap-tree artifacts |
