use crate::light_walletd::config::ConfigError;

/// Errors that can occur when interacting with lightwalletd
#[derive(Debug, thiserror::Error)]
pub enum LightWalletdError {
    /// gRPC error from lightwalletd
    #[error("gRPC: {0}")]
    Grpc(#[from] tonic::Status),
    /// Transport error connecting to lightwalletd
    #[error("Transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// Invalid nullifier length
    #[error(
        "Invalid nullifier length: expected 32, got {length} bytes. Block height: {block_height}"
    )]
    InvalidLength {
        /// The block height where the error occurred
        block_height: u64,
        /// The invalid length
        length: usize,
    },
    /// Integer conversion error
    #[error("Integer conversion error: {0}")]
    IntConversion(#[from] std::num::TryFromIntError),
    /// Overflow error
    #[error("Overflow error")]
    OverflowError,
    /// Index error
    #[error("Index error: index {index} out of bounds for length {length}")]
    IndexError {
        /// The invalid index
        index: usize,
        /// The length of the collection
        length: usize,
    },
    /// Stream message timeout
    #[error("Stream message timeout after {timeout_duration} milliseconds")]
    StreamTimeout {
        /// The timeout duration in milliseconds
        timeout_duration: u128,
    },
    /// Missing chain metadata required for position calculation
    #[error("Missing chain metadata at block height {block_height}")]
    MissingChainMetadata {
        /// The block height where metadata was missing
        block_height: u64,
    },
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigError),
    /// Failed to convert commit root to string
    #[error("Failed to convert commit root to string, {0}")]
    CommitRootToString(String),
    /// Scanner error
    #[error("Scanner error: {0}")]
    ScannerError(#[from] crate::scanner::ScannerError),
    /// Channel send error (receiver dropped)
    #[error("Block channel closed unexpectedly")]
    ChannelClosed,
    /// Task join error
    #[error("Task join error: {0}")]
    TaskJoin(String),
    /// Tokio send error
    #[error("Tokio send: {0}")]
    SendError(
        Box<
            tokio::sync::mpsc::error::SendError<
                zcash_client_backend::proto::compact_formats::CompactBlock,
            >,
        >,
    ),
}

impl
    From<
        tokio::sync::mpsc::error::SendError<
            zcash_client_backend::proto::compact_formats::CompactBlock,
        >,
    > for LightWalletdError
{
    fn from(
        e: tokio::sync::mpsc::error::SendError<
            zcash_client_backend::proto::compact_formats::CompactBlock,
        >,
    ) -> Self {
        Self::SendError(Box::new(e))
    }
}

impl LightWalletdError {
    /// Returns `true` if this error is transient and the operation should be retried.
    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "We are interested in specific variants only."
    )]
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        use tonic::Code;

        match self {
            // Retryable GRPC errors:
            // - `Unavailable`: Service temporarily unavailable
            // - `ResourceExhausted`: Rate limiting or quota exceeded
            // - `Aborted`: Operation aborted, typically due to concurrency issues
            // - `DeadlineExceeded`: Request timeout (may succeed on retry)
            // - `Unknown`: Unknown errors that might be transient
            Self::Grpc(status) => matches!(
                status.code(),
                Code::Unavailable |
                    Code::ResourceExhausted |
                    Code::Aborted |
                    Code::DeadlineExceeded |
                    Code::Unknown
            ),
            Self::Transport(_) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use tonic::Status;

    use super::*;

    #[test]
    fn error_is_retriable() {
        // Grpc - retryable codes
        assert!(LightWalletdError::Grpc(Status::unavailable("")).is_retryable());
        assert!(LightWalletdError::Grpc(Status::resource_exhausted("")).is_retryable());
        assert!(LightWalletdError::Grpc(Status::aborted("")).is_retryable());
        assert!(LightWalletdError::Grpc(Status::deadline_exceeded("")).is_retryable());
        assert!(LightWalletdError::Grpc(Status::unknown("")).is_retryable());

        // Grpc - non-retryable codes
        assert!(!LightWalletdError::Grpc(Status::not_found("")).is_retryable());

        // Other variants - not retryable
        assert!(!LightWalletdError::OverflowError.is_retryable());
    }
}
