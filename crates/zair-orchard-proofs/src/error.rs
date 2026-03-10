use halo2_proofs::plonk;
use thiserror::Error;

/// Errors for Orchard claim proof operations.
#[derive(Debug, Error)]
pub enum ClaimProofError {
    /// A 32-byte value was not a canonical encoding of a Pallas base field element.
    #[error("invalid canonical pallas base encoding")]
    NonCanonicalBase,
    /// A 32-byte value was not a canonical encoding of a Pallas scalar field element.
    #[error("invalid canonical pallas scalar encoding")]
    NonCanonicalScalar,
    /// A 32-byte value was not a valid Pallas point encoding.
    #[error("invalid pallas point encoding")]
    InvalidPoint,
    /// A Pallas point encoding decoded to the identity (disallowed in contexts requiring a
    /// non-identity point).
    #[error("pallas point must be non-identity")]
    IdentityPoint,
    /// A Halo2 error occurred during keygen/proving/verifying.
    #[error("halo2 error: {0}")]
    Halo2(#[from] plonk::Error),
    /// Orchard target id length is invalid.
    #[error("Orchard target_id length must be <= 32 bytes")]
    InvalidTargetIdLength,
    /// Orchard target id bytes are not valid UTF-8.
    #[error("Orchard target_id must be valid UTF-8")]
    InvalidTargetIdUtf8,
    /// Internal key cache lock was poisoned.
    #[error("internal key cache lock poisoned")]
    CachePoisoned,
    /// Missing SHA-256 value commitment randomness in SHA-256 scheme mode.
    #[error("missing rcv_sha256 for sha256 value commitment scheme")]
    MissingRcvSha256,
    /// Unexpected SHA-256 value commitment randomness in native scheme mode.
    #[error("unexpected rcv_sha256 for native value commitment scheme")]
    UnexpectedRcvSha256,
    /// Halo2 params `k` does not match the configured scheme.
    #[error("Orchard params k mismatch: expected {expected}, got {actual}")]
    InvalidParamsK { expected: u32, actual: u32 },
    /// Failed to read params from bytes.
    #[error("Failed to read Orchard params")]
    ReadParams,
    /// Failed decode signature verification key.
    #[error("Invalid rk encoding")]
    InvalidRkEncoding,
    /// Failed to verify spend-auth signature.
    #[error("Invalid Orchard spend-auth signature")]
    InvalidSignature,
    /// Orchard proof length exceeds [`u32::MAX`].
    #[error("Orchard proof length exceeds u32::MAX")]
    ProofLengthExceedsU32,
}
