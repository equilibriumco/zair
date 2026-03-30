use std::time::Duration;

use thiserror::Error;

use crate::light_walletd::{
    BACKOFF_FACTOR, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS,
    INITIAL_RETRY_DELAY_MS, MAX_RETRIES, MAX_RETRY_DELAY_MS, STREAM_MESSAGE_TIMEOUT_SECS,
};

/// Errors specific to `LightWalletd` configuration
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Returned when the initial retry delay is zero.
    #[error("Initial retry delay must be greater than zero.")]
    InitialRetryDelayZero,
    /// Returned when the maximum retry delay is less than the initial retry delay.
    #[error("Max retry delay must be greater than or equal to initial retry delay.")]
    MaxRetryDelayLessThanInitial,
    /// Returned when the stream message timeout is below the minimum of one second.
    #[error("Stream message timeout must be at least 1 second.")]
    StreamMessageTimeoutTooLow,
    /// Returned when the exponential-backoff factor is below the minimum of 2.
    #[error("Backoff factor must be at least 2.")]
    BackoffFactorTooLow,
}

/// Configuration for `LightWalletd` connection and retry behavior
#[derive(Debug, Clone)]
pub struct LightWalletdConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum number of retry attempts for transient errors
    pub max_retry_attempts: u32,
    /// Initial retry delay (Should be greater than zero)
    pub initial_retry_delay: Duration,
    /// Maximum retry delay
    pub max_retry_delay: Duration,
    /// Factor for exponential backoff. (Minimum value: 2)
    pub backoff_factor: u32,
    /// Timeout for receiving stream messages. (Minimum: 1 second)
    pub stream_message_timeout: Duration,
}

/// Validated Configuration for `LightWalletd`
/// This is the only configuration in use, `LightWalletdConfig` is only used to build this after
/// validation.
#[derive(Debug, Clone)]
pub struct ValidatedLightWalletdConfig {
    inner: LightWalletdConfig,
}

impl std::ops::Deref for ValidatedLightWalletdConfig {
    type Target = LightWalletdConfig;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Default for LightWalletdConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_retry_attempts: MAX_RETRIES,
            initial_retry_delay: Duration::from_millis(INITIAL_RETRY_DELAY_MS),
            max_retry_delay: Duration::from_millis(MAX_RETRY_DELAY_MS),
            backoff_factor: BACKOFF_FACTOR,
            stream_message_timeout: Duration::from_secs(STREAM_MESSAGE_TIMEOUT_SECS),
        }
    }
}

impl LightWalletdConfig {
    /// Creates a new `LightWalletdConfig` with custom parameters.
    #[must_use]
    pub const fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        max_retry_attempts: u32,
        initial_retry_delay: Duration,
        max_retry_delay: Duration,
        backoff_factor: u32,
        stream_message_timeout: Duration,
    ) -> Self {
        Self {
            connect_timeout,
            request_timeout,
            max_retry_attempts,
            initial_retry_delay,
            max_retry_delay,
            backoff_factor,
            stream_message_timeout,
        }
    }

    /// Validates the configuration parameters.
    ///
    /// # Errors
    /// If any configuration parameter is invalid.
    /// Invalid parameters include:
    /// - `initial_retry_delay` is zero.
    /// - `max_retry_delay` is less than `initial_retry_delay`.
    /// - `stream_message_timeout` is less than 1 second.
    pub fn validate(self) -> Result<ValidatedLightWalletdConfig, ConfigError> {
        if self.initial_retry_delay == Duration::ZERO {
            return Err(ConfigError::InitialRetryDelayZero);
        }

        if self.max_retry_delay < self.initial_retry_delay {
            return Err(ConfigError::MaxRetryDelayLessThanInitial);
        }

        if self.stream_message_timeout < Duration::from_secs(1) {
            return Err(ConfigError::StreamMessageTimeoutTooLow);
        }

        if self.backoff_factor < 2 {
            return Err(ConfigError::BackoffFactorTooLow);
        }

        Ok(ValidatedLightWalletdConfig { inner: self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = LightWalletdConfig::new(
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            MAX_RETRIES,
            Duration::from_millis(INITIAL_RETRY_DELAY_MS),
            Duration::from_millis(MAX_RETRY_DELAY_MS),
            BACKOFF_FACTOR,
            Duration::from_secs(STREAM_MESSAGE_TIMEOUT_SECS),
        );
        let validated_config = config.validate();
        assert!(validated_config.is_ok());
    }

    #[test]
    fn test_invalid_initial_retry_delay() {
        let config = LightWalletdConfig {
            initial_retry_delay: Duration::ZERO,
            ..LightWalletdConfig::default()
        };
        let validated_config = config.validate();
        assert!(matches!(
            validated_config,
            Err(ConfigError::InitialRetryDelayZero)
        ));
    }

    #[test]
    fn test_invalid_max_retry_delay() {
        let config = LightWalletdConfig {
            initial_retry_delay: Duration::from_secs(5),
            max_retry_delay: Duration::from_secs(3),
            ..LightWalletdConfig::default()
        };
        let validated_config = config.validate();
        assert!(matches!(
            validated_config,
            Err(ConfigError::MaxRetryDelayLessThanInitial)
        ));
    }

    #[test]
    fn test_invalid_stream_message_timeout() {
        let config = LightWalletdConfig {
            stream_message_timeout: Duration::from_millis(500),
            ..LightWalletdConfig::default()
        };
        let validated_config = config.validate();
        assert!(matches!(
            validated_config,
            Err(ConfigError::StreamMessageTimeoutTooLow)
        ));
    }

    #[test]
    fn test_invalid_backoff_factor() {
        let config = LightWalletdConfig {
            backoff_factor: 1,
            ..LightWalletdConfig::default()
        };
        let validated_config = config.validate();
        assert!(matches!(
            validated_config,
            Err(ConfigError::BackoffFactorTooLow)
        ));
    }
}
