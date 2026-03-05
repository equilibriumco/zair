//! Sapling claim proving and verification.

mod error;
mod types;

#[cfg(feature = "prove")]
pub mod prover;

#[cfg(feature = "verify")]
pub mod verifier;

#[cfg(feature = "verify")]
pub use verifier::*;
