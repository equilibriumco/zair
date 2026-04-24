# Benchmarks

Indicative single-run timings and preprocessed data sizes for the three main `zair` commands.

## Hardware

- **CPU:** AMD Ryzen 9 3900X (12 cores / 24 threads)
- **Memory:** 32 GiB DDR4-2666
- **Disk:** Samsung SSD 970 EVO Plus

## Results

| Command  | Time     | Notes                                  |
| -------- | -------- | -------------------------------------- |
| `setup`  | 24m 25s  | Sapling + Orchard parameter generation |
| `claim`  | 25s      | 2 claims total (1 Sapling, 1 Orchard)  |
| `verify` | 1.4s     | 2 claims total (1 Sapling, 1 Orchard)  |

## Preprocessed Data Size

Measured at block height `3319090`.

| File                  | Size     |
| --------------------- | -------- |
| `snapshot-sapling.bin` | 67.4 MB  |
| `snapshot-orchard.bin` | 1.6 GB   |
| `gaptree-sapling.bin`  | 134.8 MB |
| `gaptree-orchard.bin`  | 3.2 GB   |
