//! ZAIR CLI Application

mod cli;

use clap::Parser as _;
#[cfg(feature = "prove")]
use cli::SetupCommands;
use cli::{ClaimCommands, Cli, Commands, ConfigCommands, KeyCommands, VerifyCommands};
use eyre::Context as _;
use zair_sdk::commands::build_airdrop_configuration;

fn init_tracing() -> eyre::Result<()> {
    #[cfg(feature = "tokio-console")]
    {
        // tokio-console: layers the console subscriber with fmt
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(console_subscriber::spawn())
            .with(
                tracing_subscriber::fmt::layer().with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
            )
            .try_init()
            .map_err(|e| eyre::eyre!("Failed to initialize tracing: {:?}", e))?;
    }

    #[cfg(not(feature = "tokio-console"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_target(false)
            .try_init()
            .map_err(|e| eyre::eyre!("Failed to initialize tracing: {:?}", e))?;
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "Top-level CLI dispatch keeps all command wiring in one place"
)]
async fn main() -> eyre::Result<()> {
    // Initialize rustls crypto provider (required for TLS connections)
    zair_sdk::install_default_crypto_provider()?;

    // Load .env file (fails silently if not found)
    let _ = dotenvy::dotenv();

    init_tracing()?;

    let cli = Cli::parse();

    let res = match cli.command {
        #[cfg(feature = "prove")]
        Commands::Setup { command } => match command {
            SetupCommands::Sapling {
                scheme,
                pk_out,
                vk_out,
            } => zair_sdk::commands::generate_claim_params(pk_out, vk_out, scheme).await,
            SetupCommands::Orchard { scheme, params_out } => {
                zair_sdk::commands::generate_orchard_params(params_out, scheme).await
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Build { args } => {
                build_airdrop_configuration(
                    args.config.into(),
                    args.pool,
                    args.config_out,
                    args.snapshot_out_sapling,
                    args.snapshot_out_orchard,
                    args.gap_tree_out_sapling,
                    args.gap_tree_out_orchard,
                    args.no_gap_tree,
                    args.target_sapling,
                    args.scheme_sapling,
                    args.target_orchard,
                    args.scheme_orchard,
                )
                .await
            }
        },
        Commands::Claim { command } => match command {
            #[cfg(feature = "prove")]
            ClaimCommands::Run { args } => {
                zair_sdk::commands::claim_run(
                    args.lightwalletd,
                    args.snapshot_sapling,
                    args.snapshot_orchard,
                    args.gap_tree_sapling,
                    args.gap_tree_orchard,
                    args.gap_tree_mode,
                    args.birthday,
                    args.claims_out,
                    args.proofs_out,
                    args.secrets_out,
                    args.submission_out,
                    args.seed,
                    args.account,
                    args.sapling_pk,
                    args.orchard_params,
                    args.orchard_params_mode,
                    args.message,
                    args.messages,
                    args.config,
                )
                .await
            }
            ClaimCommands::Prepare { args } => {
                let ufvk = tokio::fs::read_to_string(&args.ufvk)
                    .await
                    .with_context(|| format!("Failed to read UFVK file {}", args.ufvk.display()))?;
                zair_sdk::commands::airdrop_claim(
                    args.lightwalletd,
                    args.snapshot_sapling,
                    args.snapshot_orchard,
                    args.gap_tree_sapling,
                    args.gap_tree_orchard,
                    args.gap_tree_mode,
                    ufvk.trim().to_owned(),
                    args.birthday,
                    args.claims_out,
                    args.config,
                )
                .await
            }
            #[cfg(feature = "prove")]
            ClaimCommands::Prove { args } => {
                zair_sdk::commands::generate_claim_proofs(
                    args.claims_in,
                    args.proofs_out,
                    args.seed,
                    args.account,
                    args.sapling_pk,
                    args.orchard_params,
                    args.orchard_params_mode,
                    args.secrets_out,
                    args.config,
                )
                .await
            }
            ClaimCommands::Sign { args } => {
                zair_sdk::commands::sign_claim_submission(
                    args.proofs_in,
                    args.secrets_in,
                    args.seed,
                    args.account,
                    args.config,
                    args.message,
                    args.messages,
                    args.submission_out,
                )
                .await
            }
        },
        Commands::Verify { command } => match command {
            VerifyCommands::Run { args } => {
                zair_sdk::commands::verify_run(
                    args.sapling_vk,
                    args.orchard_params,
                    args.orchard_params_mode,
                    args.submission_in,
                    args.message,
                    args.messages,
                    args.config,
                )
                .await
            }
            VerifyCommands::Proof { args } => {
                zair_sdk::commands::verify_claim_proofs(
                    args.proofs_in,
                    args.sapling_vk,
                    args.orchard_params,
                    args.orchard_params_mode,
                    args.config,
                )
                .await
            }
            VerifyCommands::Signature { args } => {
                zair_sdk::commands::verify_claim_submission_signature(
                    args.submission_in,
                    args.message,
                    args.messages,
                    args.config,
                )
                .await
            }
        },
        Commands::Key { command } => match command {
            KeyCommands::DeriveSeed { args } => {
                let mnemonic_source = if args.mnemonic_stdin {
                    zair_sdk::commands::MnemonicSource::Stdin
                } else if let Some(path) = args.mnemonic_file {
                    zair_sdk::commands::MnemonicSource::File(path)
                } else {
                    zair_sdk::commands::MnemonicSource::Prompt
                };
                zair_sdk::commands::key_derive_seed(
                    args.output,
                    mnemonic_source,
                    args.no_passphrase,
                )
                .await
            }
            KeyCommands::DeriveUfvk { args } => {
                let mnemonic_source = if args.mnemonic_stdin {
                    Some(zair_sdk::commands::MnemonicSource::Stdin)
                } else {
                    args.mnemonic_file
                        .map(zair_sdk::commands::MnemonicSource::File)
                };
                zair_sdk::commands::key_derive_ufvk(
                    args.network,
                    args.account,
                    args.seed,
                    mnemonic_source,
                    args.no_passphrase,
                    args.output,
                )
                .await
            }
        },
    };

    if let Err(e) = res {
        tracing::error!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}
