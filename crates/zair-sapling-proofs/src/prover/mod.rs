//! Proving for the Claim circuit.
//!
//! This module provides functions for proving Groth16 proofs for the Claim circuit.
mod builder;
mod convenience;
mod proving;

pub use builder::{
    ParameterError, generate_parameters, load_parameters, load_parameters_from_bytes,
    save_parameters,
};
pub use convenience::generate_claim_proof;
pub use proving::ClaimParameters;

pub use crate::error::ClaimProofError;
pub use crate::types::{ClaimProofInputs, ValueCommitmentScheme};
