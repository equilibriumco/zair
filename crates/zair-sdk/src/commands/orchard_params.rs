//! Orchard Halo2 params cache management.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eyre::Context as _;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use tracing::info;
use zair_orchard_proofs::ValueCommitmentScheme as OrchardValueCommitmentScheme;

/// How to handle missing Orchard params.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchardParamsMode {
    /// Require the params file to exist; error otherwise.
    Require,
    /// Generate params if missing, and persist them to disk.
    Auto,
}

fn tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("orchard-params.bin");
    path.with_file_name(format!("{file_name}.tmp.{}", std::process::id()))
}

pub fn read_params(bytes: Vec<u8>) -> eyre::Result<Params<vesta::Affine>> {
    let mut cursor = Cursor::new(bytes);
    Params::<vesta::Affine>::read(&mut cursor).context("Failed to read Orchard params")
}

fn write_params_file(
    params_file: &Path,
    overwrite: bool,
    expected_k: u32,
) -> eyre::Result<Params<vesta::Affine>> {
    if let Some(parent) = params_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    let tmp_file = tmp_path(params_file);
    let params = Params::<vesta::Affine>::new(expected_k);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_file)
        .with_context(|| format!("Failed to create {}", tmp_file.display()))?;

    params
        .write(&mut file)
        .with_context(|| format!("Failed to write {}", tmp_file.display()))?;

    if let Err(err) = std::fs::rename(&tmp_file, params_file) {
        if params_file.exists() {
            if overwrite {
                // On some platforms, `rename` fails if the destination already exists.
                // Remove and retry.
                std::fs::remove_file(params_file).with_context(|| {
                    format!(
                        "Failed to remove existing Orchard params {}",
                        params_file.display()
                    )
                })?;
                std::fs::rename(&tmp_file, params_file).with_context(|| {
                    format!(
                        "Failed to rename {} -> {}",
                        tmp_file.display(),
                        params_file.display()
                    )
                })?;
            } else {
                // Another process generated the cache while we were working; keep our in-memory
                // params.
                let _ = std::fs::remove_file(&tmp_file);
            }
        } else {
            return Err(err).with_context(|| {
                format!(
                    "Failed to rename {} -> {}",
                    tmp_file.display(),
                    params_file.display()
                )
            });
        }
    }

    Ok(params)
}

/// Generate Orchard params for `scheme` and overwrite `params_file`.
///
/// This is intended for explicit setup commands (`zair setup orchard`), mirroring Sapling setup:
/// running it always regenerates params.
///
/// # Errors
/// Returns an error if param generation fails.
pub async fn generate_orchard_params_file(
    params_file: PathBuf,
    scheme: OrchardValueCommitmentScheme,
) -> eyre::Result<()> {
    let expected_k = zair_orchard_proofs::k_for_scheme(scheme);
    tokio::task::spawn_blocking(move || -> eyre::Result<()> {
        let _ = write_params_file(&params_file, true, expected_k)?;
        Ok(())
    })
    .await??;
    Ok(())
}

/// Load Orchard params from disk, or generate-and-persist them according to `mode`.
///
/// # Errors
/// Returns an error if params are missing in `Require` mode, or if generation fails.
pub async fn load_or_prepare_orchard_params(
    params_file: PathBuf,
    scheme: OrchardValueCommitmentScheme,
    mode: OrchardParamsMode,
) -> eyre::Result<Arc<Params<vesta::Affine>>> {
    let expected_k = zair_orchard_proofs::k_for_scheme(scheme);

    if tokio::fs::try_exists(&params_file).await? {
        let bytes = tokio::fs::read(&params_file).await?;
        let params = tokio::task::spawn_blocking(move || read_params(bytes)).await??;
        let actual_k = params.k();

        if actual_k == expected_k {
            return Ok(Arc::new(params));
        }

        match mode {
            OrchardParamsMode::Require => {
                eyre::bail!(
                    "Orchard params `k` mismatch for {}: expected {expected_k} (scheme={scheme:?}), got {actual_k}. Regenerate with `zair setup orchard --scheme {}` or use a different `--orchard-params` path.",
                    params_file.display(),
                    scheme,
                );
            }
            OrchardParamsMode::Auto => {
                info!(
                    file = ?params_file,
                    scheme = ?scheme,
                    expected_k,
                    actual_k,
                    "Orchard params cache has wrong k; regenerating and overwriting"
                );
                let params = tokio::task::spawn_blocking(move || {
                    write_params_file(&params_file, true, expected_k)
                })
                .await??;
                return Ok(Arc::new(params));
            }
        }
    }

    match mode {
        OrchardParamsMode::Require => {
            eyre::bail!(
                "Orchard params not found at {}. Run `zair setup orchard --scheme {}` (or use `--orchard-params-mode auto`) and retry.",
                params_file.display(),
                scheme,
            );
        }
        OrchardParamsMode::Auto => {
            info!(
                file = ?params_file,
                scheme = ?scheme,
                k = expected_k,
                "Orchard params cache not found; generating and persisting"
            );

            let params = tokio::task::spawn_blocking(move || {
                // For missing-file generation, do not overwrite if another process won the race.
                write_params_file(&params_file, false, expected_k)
            })
            .await??;
            Ok(Arc::new(params))
        }
    }
}
