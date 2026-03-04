# Getting Started

This section covers setting up the repository, building `zair`, and running a quick sanity check. Afterwards, follow the step-by-step guide in the [CLI Reference](../cli/index.md).

## Setup and Building

### With Nix (recommended)

The repo includes a Nix flake that provides all dependencies (Rust, `protoc`):

```bash
nix develop
cargo build --release
```

### Without Nix

#### Prerequisites

- Rust 1.91+ (2024 edition)
- Protobuf (`protoc`) for lightwalletd gRPC bindings

Build with:

```bash
cargo build --release
```

## Sanity check

Verify the CLI is available:

```bash
./target/release/zair --help
```

and inspect the command groups:

```bash
./target/release/zair key --help
./target/release/zair setup --help
./target/release/zair config --help
./target/release/zair claim --help
./target/release/zair verify --help
```

## Feature flags

The proving pipeline is gated behind the `prove` feature for some crates/binaries, enabled by default.

If you only need verification, you may build without proving support for a lighter dependency.
