//! ZAIR SDK/workflow library.

pub mod api;
pub mod commands;
pub mod common;
pub mod network_params;

mod seed;

/// Installs the default rustls crypto provider (ring).
/// Must be called before any TLS connections (e.g., `LightWalletd::connect`).
///
/// # Errors
///
/// Returns an error if a crypto provider has already been installed.
pub fn install_default_crypto_provider() -> eyre::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| eyre::eyre!("Failed to install rustls crypto provider: {e:?}"))
}
