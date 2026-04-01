//! Command-line interface for the `zair` CLI application.

mod claim;
mod config;
pub mod constants;
mod key;
#[cfg(feature = "prove")]
mod setup;
mod verify;

use clap::Parser;
use eyre::{Result, ensure, eyre};
use zair_core::schema::config::ValueCommitmentScheme;
use zair_sdk::commands::{GapTreeMode, OrchardParamsMode};
use zair_sdk::common::{CommonConfig, PoolSelection};
use zcash_protocol::consensus::Network;

pub use self::claim::ClaimCommands;
pub use self::config::ConfigCommands;
use self::constants::{DEFAULT_NETWORK, ZAIR_LIGHTWALLETD_URL, ZAIR_NETWORK, ZAIR_SNAPSHOT_HEIGHT};
pub use self::key::KeyCommands;
#[cfg(feature = "prove")]
pub use self::setup::SetupCommands;
pub use self::verify::VerifyCommands;

/// Command-line interface definition.
#[derive(Debug, Parser)]
#[command(name = "zair")]
#[command(about = "Zcash airdrop tools")]
pub struct Cli {
    /// CLI top-level command group.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level command groups.
#[derive(Debug, clap::Subcommand)]
pub enum Commands {
    /// Key derivation utilities.
    Key {
        /// Key subcommands.
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Setup utilities (organizer/developer focused).
    #[cfg(feature = "prove")]
    Setup {
        /// Setup subcommands.
        #[command(subcommand)]
        command: SetupCommands,
    },
    /// Airdrop configuration utilities.
    Config {
        /// Config subcommands.
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Claim pipeline commands.
    Claim {
        /// Claim subcommands.
        #[command(subcommand)]
        command: ClaimCommands,
    },
    /// Verification pipeline commands.
    Verify {
        /// Verify subcommands.
        #[command(subcommand)]
        command: VerifyCommands,
    },
}

/// Common arguments for `config build`.
#[derive(Debug, clap::Args)]
pub struct BuildConfigArgs {
    /// Network to use (mainnet or testnet).
    #[arg(
        long,
        env = ZAIR_NETWORK,
        default_value = DEFAULT_NETWORK,
        value_parser = parse_network
    )]
    pub network: Network,
    /// Snapshot block height (inclusive).
    #[arg(long, env = ZAIR_SNAPSHOT_HEIGHT)]
    pub height: u64,
    /// Optional lightwalletd gRPC endpoint URL override.
    #[arg(long, env = ZAIR_LIGHTWALLETD_URL)]
    pub lightwalletd: Option<String>,
}

impl From<BuildConfigArgs> for CommonConfig {
    fn from(args: BuildConfigArgs) -> Self {
        Self {
            network: args.network,
            snapshot_height: args.height,
            lightwalletd_url: args.lightwalletd,
        }
    }
}

pub fn parse_network(s: &str) -> Result<Network> {
    match s {
        "mainnet" => Ok(Network::MainNetwork),
        "testnet" => Ok(Network::TestNetwork),
        other => Err(eyre!(
            "Invalid network: {other}. Expected 'mainnet' or 'testnet'."
        )),
    }
}

pub fn parse_pool_selection(s: &str) -> Result<PoolSelection> {
    match s {
        "sapling" => Ok(PoolSelection::Sapling),
        "orchard" => Ok(PoolSelection::Orchard),
        "both" => Ok(PoolSelection::Both),
        other => Err(eyre!(
            "Invalid pool: {other}. Expected 'sapling', 'orchard', or 'both'."
        )),
    }
}

pub fn parse_sapling_target_id(s: &str) -> Result<String> {
    ensure!(s.len() == 8, "Sapling target_id must be exactly 8 bytes");
    Ok(s.to_string())
}

pub fn parse_orchard_target_id(s: &str) -> Result<String> {
    ensure!(s.len() <= 32, "Orchard target_id must be at most 32 bytes");
    Ok(s.to_string())
}

pub fn parse_value_commitment_scheme(s: &str) -> Result<ValueCommitmentScheme> {
    match s {
        "native" => Ok(ValueCommitmentScheme::Native),
        "sha256" => Ok(ValueCommitmentScheme::Sha256),
        "plain" => Ok(ValueCommitmentScheme::Plain),
        other => Err(eyre!(
            "Invalid value commitment scheme: {other}. Expected 'native', 'sha256', or 'plain'."
        )),
    }
}

pub fn parse_gap_tree_mode(s: &str) -> Result<GapTreeMode> {
    match s {
        "none" => Ok(GapTreeMode::None),
        "rebuild" => Ok(GapTreeMode::Rebuild),
        "sparse" => Ok(GapTreeMode::Sparse),
        other => Err(eyre!(
            "Invalid gap-tree mode: {other}. Expected 'none', 'rebuild', or 'sparse'."
        )),
    }
}

pub fn parse_orchard_params_mode(s: &str) -> Result<OrchardParamsMode> {
    match s {
        "require" => Ok(OrchardParamsMode::Require),
        "auto" => Ok(OrchardParamsMode::Auto),
        other => Err(eyre!(
            "Invalid orchard params mode: {other}. Expected 'require' or 'auto'."
        )),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn network_parse() {
        let network = parse_network("mainnet").expect("Failed to parse mainnet");
        assert_eq!(network, Network::MainNetwork);
        let network = parse_network("testnet").expect("Failed to parse testnet");
        assert_eq!(network, Network::TestNetwork);
        assert!(parse_network("invalid_network").is_err());
    }

    #[test]
    fn pool_selection_parse() {
        assert!(matches!(
            parse_pool_selection("sapling").expect("sapling should parse"),
            PoolSelection::Sapling
        ));
        assert!(matches!(
            parse_pool_selection("orchard").expect("orchard should parse"),
            PoolSelection::Orchard
        ));
        assert!(matches!(
            parse_pool_selection("both").expect("both should parse"),
            PoolSelection::Both
        ));
        assert!(parse_pool_selection("nope").is_err());
    }

    #[test]
    fn gap_tree_mode_parse() {
        assert!(matches!(
            parse_gap_tree_mode("none").expect("none should parse"),
            GapTreeMode::None
        ));
        assert!(matches!(
            parse_gap_tree_mode("rebuild").expect("rebuild should parse"),
            GapTreeMode::Rebuild
        ));
        assert!(matches!(
            parse_gap_tree_mode("sparse").expect("sparse should parse"),
            GapTreeMode::Sparse
        ));
        assert!(parse_gap_tree_mode("invalid").is_err());
    }

    #[test]
    fn orchard_params_mode_parse() {
        assert!(matches!(
            parse_orchard_params_mode("require").expect("require should parse"),
            OrchardParamsMode::Require
        ));
        assert!(matches!(
            parse_orchard_params_mode("auto").expect("auto should parse"),
            OrchardParamsMode::Auto
        ));
        assert!(parse_orchard_params_mode("invalid").is_err());
    }

    #[cfg(feature = "prove")]
    #[test]
    fn parse_claim_run_command_requires_message_input() {
        let cli = Cli::try_parse_from([
            "zair",
            "claim",
            "run",
            "--seed",
            "seed.txt",
            "--birthday",
            "3663119",
        ]);
        assert!(cli.is_err());

        let cli = Cli::try_parse_from([
            "zair",
            "claim",
            "run",
            "--seed",
            "seed.txt",
            "--birthday",
            "3663119",
            "--message",
            "claim-message.bin",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn parse_verify_run_command_requires_message_input() {
        let cli = Cli::try_parse_from(["zair", "verify", "run"]);
        assert!(cli.is_err());

        let cli =
            Cli::try_parse_from(["zair", "verify", "run", "--messages", "claim-messages.json"]);
        assert!(cli.is_ok());
    }
}
