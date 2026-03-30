//! Connection to lightwalletd gRPC service

/// Configuration for lightwalletd connection.
pub mod config;
/// Errors that can occur when interacting with lightwalletd.
pub mod error;
mod retry;

use std::ops::RangeInclusive;
use std::time::Duration;

pub use config::LightWalletdConfig;
use futures::{Stream, StreamExt as _};
use tonic::transport::{Channel, ClientTlsConfig, Uri};
use tracing::warn;
use zcash_client_backend::data_api::BlockMetadata;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, TreeState};
use zcash_protocol::consensus::BlockHeight;

use crate::light_walletd::config::ValidatedLightWalletdConfig;
use crate::light_walletd::error::LightWalletdError;
use crate::light_walletd::retry::retry_with_backoff;
use crate::scanner::{BlockScanner, ScanVisitor, extract_nullifiers};

/// Default connection timeout in seconds
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default request timeout in seconds
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Maximum number of retry attempts for transient errors
const MAX_RETRIES: u32 = 3;
/// Initial retry delay in milliseconds
const INITIAL_RETRY_DELAY_MS: u64 = 1000;
/// Maximum retry delay in milliseconds
const MAX_RETRY_DELAY_MS: u64 = 10000;
/// Factor for exponential backoff
const BACKOFF_FACTOR: u32 = 2;
/// Timeout for receiving stream messages in seconds
const STREAM_MESSAGE_TIMEOUT_SECS: u64 = 60;

/// A lightwalletd client
pub struct LightWalletd {
    client: CompactTxStreamerClient<Channel>,
    config: ValidatedLightWalletdConfig,
}

/// Commitment tree anchors for Sapling and Orchard at a specific block height.
pub struct CommitmentTreeAnchors {
    /// Sapling commitment tree anchor
    pub sapling: [u8; 32],
    /// Orchard commitment tree anchor
    pub orchard: [u8; 32],
}

impl LightWalletd {
    /// Connect to a lightwalletd endpoint
    ///
    /// # Prerequisite
    ///
    /// `zair_sdk::install_default_crypto_provider()` needs to be called
    /// before this function is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the endpoint fails.
    pub async fn connect(endpoint: Uri) -> Result<Self, LightWalletdError> {
        Self::connect_with_config(endpoint, LightWalletdConfig::default().validate()?).await
    }

    /// Connect to lightwallerd endpoint with custom configuration
    ///
    /// # Prerequisite
    ///
    /// `zair_sdk::install_default_crypto_provider()` needs to be called
    /// before this function is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the endpoint fails.
    pub async fn connect_with_config(
        endpoint: Uri,
        config: ValidatedLightWalletdConfig,
    ) -> Result<Self, LightWalletdError> {
        // Enable TLS for HTTPS endpoints
        let enable_tls = endpoint.scheme() == Some(&http::uri::Scheme::HTTPS);

        let mut channel = Channel::builder(endpoint)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout);

        if enable_tls {
            channel = channel.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
        } else {
            warn!(
                "Connecting to lightwalletd without TLS. This is not recommended for production use."
            );
        }

        let channel = channel.connect().await?;
        let client = CompactTxStreamerClient::new(channel);

        Ok(Self { client, config })
    }

    /// Creates a block range stream with retry logic.
    async fn get_block_range_stream(
        client: &CompactTxStreamerClient<Channel>,
        config: &ValidatedLightWalletdConfig,
        range: &RangeInclusive<u64>,
    ) -> Result<tonic::Streaming<CompactBlock>, LightWalletdError> {
        retry_with_backoff(config, || {
            let mut client = client.clone();
            let request = BlockRange {
                start: Some(BlockId {
                    height: *range.start(),
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: *range.end(),
                    hash: vec![],
                }),
            };
            async move {
                client
                    .get_block_range(request)
                    .await
                    .map(tonic::Response::into_inner)
            }
        })
        .await
    }

    /// Get commitment tree anchor at a specific block height for Sapling and Orchard.
    ///
    /// # Errors
    /// todo write errors
    pub async fn commitment_tree_anchors(
        &self,
        height: BlockHeight,
    ) -> Result<CommitmentTreeAnchors, LightWalletdError> {
        let request = BlockId {
            height: height.into(),
            hash: vec![],
        };

        let response = retry_with_backoff(&self.config, || {
            let mut client = self.client.clone();
            let request = request.clone();
            async move {
                client
                    .get_tree_state(request)
                    .await
                    .map(tonic::Response::into_inner)
            }
        })
        .await?;

        Ok(CommitmentTreeAnchors {
            sapling: response
                .sapling_tree()
                .map_err(|e| LightWalletdError::CommitRootToString(format!("Sapling: {e}")))?
                .root()
                .to_bytes(),
            orchard: response
                .orchard_tree()
                .map_err(|e| LightWalletdError::CommitRootToString(format!("Orchard: {e}")))?
                .root()
                .to_bytes(),
        })
    }

    /// Scan blocks using a channel-based approach that keeps non-Send types off async tasks.
    ///
    /// This method uses a bounded channel to stream blocks from an async fetcher task
    /// to a blocking scanner task. The `BlockScanner` is created inside `spawn_blocking`,
    /// avoiding the `Send` requirement.
    ///
    /// # Arguments
    /// * `ufvk` - The unified full viewing key to create the scanner
    /// * `network` - The network to scan on
    /// * `visitor` - The visitor to process scan events (will be returned)
    /// * `range` - The block range to scan
    /// * `initial_metadata` - Optional initial block metadata
    ///
    /// # Returns
    /// A tuple of the visitor (with accumulated state) and the final block metadata
    ///
    /// # Errors
    /// Returns an error if block fetching or scanning fails
    pub async fn scan_blocks_spawned<V: ScanVisitor + Send + 'static>(
        &self,
        ufvk: zcash_keys::keys::UnifiedFullViewingKey,
        network: zcash_protocol::consensus::Network,
        visitor: V,
        range: &RangeInclusive<u64>,
        initial_metadata: Option<BlockMetadata>,
    ) -> Result<(V, Option<BlockMetadata>), LightWalletdError> {
        const CHANNEL_BUFFER_SIZE: usize = 100;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<CompactBlock>(CHANNEL_BUFFER_SIZE);

        let client = self.client.clone();
        let config = self.config.clone();
        let range_clone = range.clone();

        let fetcher_handle = tokio::spawn(async move {
            let mut stream = Self::get_block_range_stream(&client, &config, &range_clone).await?;

            while let Some(block) =
                receive_next_block(&mut stream, config.stream_message_timeout).await?
            {
                tx.send(block).await?;
            }

            Ok::<_, LightWalletdError>(())
        });

        let scanner_handle = tokio::task::spawn_blocking(move || {
            let scanner = BlockScanner::from_ufvk(ufvk, network);
            let mut visitor = visitor;
            let mut prior_metadata = initial_metadata;

            while let Some(block) = rx.blocking_recv() {
                let metadata = scanner.scan_block(block, &mut visitor, prior_metadata.as_ref())?;
                prior_metadata = Some(metadata);
            }

            Ok::<_, LightWalletdError>((visitor, prior_metadata))
        });

        fetcher_handle
            .await
            .map_err(|e| LightWalletdError::TaskJoin(e.to_string()))??;

        scanner_handle
            .await
            .map_err(|e| LightWalletdError::TaskJoin(e.to_string()))?
    }

    /// Get tree state at a height
    ///
    /// # Errors
    /// Returns an error if the request fails
    pub async fn get_tree_state(&self, height: u64) -> Result<TreeState, LightWalletdError> {
        let request = BlockId {
            height,
            hash: vec![],
        };

        retry_with_backoff(&self.config, || {
            let mut client = self.client.clone();
            let request = request.clone();
            async move {
                client
                    .get_tree_state(request)
                    .await
                    .map(tonic::Response::into_inner)
            }
        })
        .await
    }

    /// Scan blocks for nullifiers only (no decryption needed)
    ///
    /// # Errors
    /// Returns an error if scanning fails
    pub async fn scan_nullifiers<V: ScanVisitor>(
        &self,
        visitor: &mut V,
        range: &RangeInclusive<u64>,
    ) -> Result<(), LightWalletdError> {
        self.scan_nullifiers_with_progress(visitor, range, |_, _, _| {})
            .await
    }

    /// Scan blocks for nullifiers only (no decryption needed), with progress callback.
    ///
    /// Calls `on_progress(height, scanned, total)` after each block is processed.
    ///
    /// # Errors
    /// Returns an error if scanning fails.
    pub async fn scan_nullifiers_with_progress<V: ScanVisitor>(
        &self,
        visitor: &mut V,
        range: &RangeInclusive<u64>,
        mut on_progress: impl FnMut(u64, usize, usize),
    ) -> Result<(), LightWalletdError> {
        let mut stream = Self::get_block_range_stream(&self.client, &self.config, range).await?;
        let total_blocks_u64 = range.end().saturating_sub(*range.start()).saturating_add(1);
        let total_blocks = usize::try_from(total_blocks_u64).unwrap_or(usize::MAX);
        let mut scanned_blocks = 0usize;

        while let Some(block) =
            receive_next_block(&mut stream, self.config.stream_message_timeout).await?
        {
            extract_nullifiers(&block, visitor);
            scanned_blocks = scanned_blocks.saturating_add(1);
            on_progress(block.height, scanned_blocks, total_blocks);
        }

        Ok(())
    }
}

/// Receives the next block from a stream with timeout.
async fn receive_next_block<S>(
    stream: &mut S,
    timeout_duration: Duration,
) -> Result<Option<CompactBlock>, LightWalletdError>
where
    S: Stream<Item = Result<CompactBlock, tonic::Status>> + Unpin,
{
    match tokio::time::timeout(timeout_duration, stream.next()).await {
        Ok(Some(Ok(block))) => Ok(Some(block)),
        Ok(Some(Err(status))) => Err(LightWalletdError::from(status)),
        Ok(None) => Ok(None),
        Err(_elapsed) => {
            warn!(
                "Timeout receiving block from lightwalletd after {}ms",
                timeout_duration.as_millis()
            );
            Err(LightWalletdError::StreamTimeout {
                timeout_duration: timeout_duration.as_millis(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "Tests")]

    use std::pin::pin;

    use futures::stream;
    use tonic::Status;

    use super::*;

    fn make_block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            ..Default::default()
        }
    }

    mod receive_next_block_tests {
        use super::*;

        #[tokio::test]
        async fn success_and_end_of_stream() {
            let mut s = stream::iter(vec![Ok(make_block(100)), Ok(make_block(101))]);
            let timeout = Duration::from_secs(1);

            let b1 = receive_next_block(&mut s, timeout)
                .await
                .expect("first block")
                .expect("some block");
            assert_eq!(b1.height, 100);

            let b2 = receive_next_block(&mut s, timeout)
                .await
                .expect("second block")
                .expect("some block");
            assert_eq!(b2.height, 101);

            let end = receive_next_block(&mut s, timeout)
                .await
                .expect("end of stream");
            assert!(end.is_none());
        }

        #[tokio::test]
        async fn grpc_error() {
            let mut s = stream::iter(vec![Err(Status::unavailable("down"))]);
            let result = receive_next_block(&mut s, Duration::from_secs(1)).await;
            assert!(matches!(result, Err(LightWalletdError::Grpc(_))));
        }

        #[tokio::test]
        async fn timeout() {
            let mut s = pin!(stream::pending::<Result<CompactBlock, Status>>());
            let result = receive_next_block(&mut s, Duration::from_millis(10)).await;
            assert!(matches!(
                result,
                Err(LightWalletdError::StreamTimeout {
                    timeout_duration: 10
                })
            ));
        }

        #[tokio::test]
        async fn error_stops_processing() {
            let items = vec![
                Ok(make_block(100)),
                Err(Status::internal("")),
                Ok(make_block(102)),
            ];
            let mut s = stream::iter(items);
            let timeout = Duration::from_secs(1);

            assert!(receive_next_block(&mut s, timeout).await.is_ok());
            assert!(matches!(
                receive_next_block(&mut s, timeout).await,
                Err(LightWalletdError::Grpc(_))
            ));
        }
    }
}
