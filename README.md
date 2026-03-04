<p align="center">
  <img src="docs/logo.png" alt="zair" width="400">
</p>

# Zair

Zair offers privacy-preserving tools for Zcash airdrops by allowing users to prove they own eligible notes on Zcash while preserving the privacy of the notes owned and the amounts claimed.

**[Link to Documentation](https://eigerco.github.io/zair)**

**This project has not been audited.**

## How it works

An organizer publishes a snapshot of the Zcash chain at a given height. Claimants scan for their eligible notes, then generate a ZK proof per note that demonstrates note ownership and unspentness without revealing the Zcash nullifier. Each proof instead exposes a domain-separated _airdrop nullifier_ for double-claim prevention and is signed with a spend-authorizing key bound to a target-chain message. Verifiers then check the proofs against the snapshot and de-duplicate by airdrop nullifier.

See the [Introduction](https://eigerco.github.io/zair/introduction.html) for more details.

## Crates

| Crate                  | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| `zair-cli`             | Primary `zair` CLI binary tool                              |
| `zair-sdk`             | The SDK and entrypoint for `zair` airdrops, used by the CLI |
| `zair-core`            | Core crate with shared types, config and schemas            |
| `zair-nonmembership`   | Non-membership Merkle-tree primitive                        |
| `zair-scan`            | Lightwalletd gRPC client and chain scanning                 |
| `zair-sapling-proofs`  | Sapling proving and verification                            |
| `zair-sapling-circuit` | Sapling claim circuit (Bellman/Groth16)                     |
| `zair-orchard-proofs`  | Orchard proving and verification                            |
| `zair-orchard-circuit` | Orchard claim circuit (Halo2)                               |

## Getting started

See [Getting Started](https://eigerco.github.io/zair/getting-started/index.html) for build instructions and setup. The quickest path is using Nix:

```bash
nix develop
cargo build --release
```

## Usage

Below is a minimal example workflow. See the [CLI Reference](https://eigerco.github.io/zair/cli/index.html) for details or check `zair --help` for command options.

### 1. Derive keys

Extract the seed from your wallet mnemonic:

```bash
zair key derive-seed --mnemonic-file mnemonic.txt --no-passphrase
```

### 2. Generate parameters

Generate the trusted Sapling setup (required once):

```bash
zair setup sapling
```

### 3. Build configuration

Build the airdrop snapshot against a chain height:

```bash
zair config build --network testnet --height <SNAPSHOT_HEIGHT>
```

### 4. Claim

Run the full claim pipeline (prepare, prove, sign) in one step:

```bash
zair claim run \
  --config config.json \
  --seed seed.txt \
  --birthday <WALLET_BIRTHDAY> \
  --message claim-message.bin
```

### 5. Verify

Verify the submission (proofs and signatures):

```bash
zair verify run \
  --config config.json \
  --message claim-message.bin
```

## License

Released under the MIT License.
