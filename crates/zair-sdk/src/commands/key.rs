//! Key derivation utilities.

use std::path::{Path, PathBuf};

use bip39::Language;
use eyre::Context as _;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use tracing::info;
use zcash_protocol::consensus::Network;

use super::sensitive_output::write_sensitive_output;
use crate::seed::read_seed_file;

/// Source of a BIP-39 mnemonic.
#[derive(Debug, Default, Clone)]
pub enum MnemonicSource {
    /// Prompt interactively (no echo).
    #[default]
    Prompt,
    /// Read from file.
    File(PathBuf),
    /// Read from stdin (pipe).
    Stdin,
}

async fn prompt_secret(prompt: &'static str) -> eyre::Result<SecretString> {
    tokio::task::spawn_blocking(move || {
        rpassword::prompt_password(prompt)
            .map(|s| SecretString::new(s.into_boxed_str()))
            .context("Failed to read secret input")
    })
    .await?
}

async fn read_secret_file(path: &Path) -> eyre::Result<SecretString> {
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(SecretString::new(text.trim().to_owned().into_boxed_str()))
}

async fn read_secret_stdin() -> eyre::Result<SecretString> {
    tokio::task::spawn_blocking(|| -> eyre::Result<SecretString> {
        use std::io::Read as _;

        use zeroize::Zeroize as _;

        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read stdin")?;
        let secret = SecretString::new(buf.trim().to_owned().into_boxed_str());
        buf.zeroize();
        Ok(secret)
    })
    .await?
}

async fn read_mnemonic(source: MnemonicSource) -> eyre::Result<SecretString> {
    match source {
        MnemonicSource::Prompt => prompt_secret("BIP-39 mnemonic: ").await,
        MnemonicSource::File(path) => read_secret_file(&path).await,
        MnemonicSource::Stdin => read_secret_stdin().await,
    }
}

async fn read_passphrase(no_passphrase: bool) -> eyre::Result<SecretString> {
    if no_passphrase {
        return Ok(SecretString::new(Box::<str>::from("")));
    }
    prompt_secret("BIP-39 passphrase (optional): ").await
}

async fn derive_seed_from_mnemonic(
    mnemonic_source: MnemonicSource,
    no_passphrase: bool,
) -> eyre::Result<SecretBox<[u8; 64]>> {
    let mnemonic = read_mnemonic(mnemonic_source).await?;
    let passphrase = read_passphrase(no_passphrase).await?;

    let mnemonic =
        bip39::Mnemonic::parse_in_normalized(Language::English, mnemonic.expose_secret())
            .context("Failed to parse BIP-39 mnemonic")?;

    let seed = mnemonic.to_seed(passphrase.expose_secret());
    Ok(SecretBox::new(Box::new(seed)))
}

/// Derive a 64-byte seed and write it as hex to `output`.
///
/// # Errors
/// Returns an error if mnemonic parsing or file I/O fails.
pub async fn key_derive_seed(
    output: PathBuf,
    mnemonic_source: MnemonicSource,
    no_passphrase: bool,
) -> eyre::Result<()> {
    use zeroize::Zeroize as _;

    info!(file = ?output, "Deriving seed...");
    let seed = derive_seed_from_mnemonic(mnemonic_source, no_passphrase).await?;

    let mut hex = format!("{}\n", hex::encode(seed.expose_secret()));
    write_sensitive_output(&output, &hex).await?;
    hex.zeroize();
    info!(file = ?output, "Seed written");
    Ok(())
}

/// Derive a UFVK and write it to `output`.
///
/// # Errors
/// Returns an error if seed loading, key derivation, or file I/O fails.
pub async fn key_derive_ufvk(
    network: Network,
    account: u32,
    seed_file: Option<PathBuf>,
    mnemonic_source: Option<MnemonicSource>,
    no_passphrase: bool,
    output: PathBuf,
) -> eyre::Result<()> {
    let seed = if let Some(source) = mnemonic_source {
        derive_seed_from_mnemonic(source, no_passphrase).await?
    } else {
        let seed_path = seed_file.unwrap_or_else(|| PathBuf::from("seed.txt"));
        info!(file = ?seed_path, "Reading seed from file...");
        read_seed_file(&seed_path).await?
    };

    let ufvk = crate::api::key::derive_ufvk_from_seed(network, account, seed.expose_secret())?;

    let text = format!("{ufvk}\n");
    write_sensitive_output(&output, &text).await?;
    info!(file = ?output, "UFVK written");
    Ok(())
}
