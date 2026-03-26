//! Parameter generation for the Claim circuit.
//!
//! This module provides functionality to generate Groth16 proving and verifying
//! parameters for the Claim circuit.

use std::path::Path;

use bellman::groth16::{Parameters, generate_random_parameters};
use bls12_381::Bls12;
use rand::rngs::OsRng;
use zair_nonmembership::NON_MEMBERSHIP_TREE_DEPTH;
use zair_sapling_circuit::Claim;

use crate::prover::proving::ClaimParameters;
use crate::types::ValueCommitmentScheme;

/// Errors that can occur during parameter operations.
#[derive(Debug, thiserror::Error)]
pub enum ParameterError {
    /// I/O error (file creation/opening)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Parameter generation failed
    #[error("Parameter generation failed")]
    Generation(#[source] bellman::SynthesisError),
    /// Parameter serialization failed
    #[error("Parameter serialization failed")]
    Serialization(#[source] std::io::Error),
    /// Parameter deserialization failed
    #[error("Parameter deserialization failed")]
    Deserialization(#[source] std::io::Error),
}

/// Generate new Groth16 parameters for the Claim circuit.
///
/// This function creates an empty circuit instance and generates random
/// parameters using the BLS12-381 curve. This is a computationally expensive
/// operation that should only be done once.
///
/// # Returns
/// The generated parameters wrapped in `ClaimParameters`.
///
/// # Errors
/// Returns an error if parameter generation fails.
pub fn generate_parameters(
    value_commitment_scheme: ValueCommitmentScheme,
) -> Result<ClaimParameters, ParameterError> {
    let mut rng = OsRng;

    // Create empty circuit for parameter generation
    let empty_circuit = Claim {
        value_commitment_opening: None,
        proof_generation_key: None,
        payment_address: None,
        commitment_randomness: None,
        ar: None,
        auth_path: vec![None; usize::from(sapling::NOTE_COMMITMENT_TREE_DEPTH)],
        anchor: None,
        nm_left_nf: None,
        nm_right_nf: None,
        nm_merkle_path: vec![None; usize::from(NON_MEMBERSHIP_TREE_DEPTH)],
        nm_anchor: None,
        value_commitment_scheme: value_commitment_scheme.into(),
        rcv_sha256: None,
    };

    let params = generate_random_parameters::<Bls12, _, _>(empty_circuit, &mut rng)
        .map_err(ParameterError::Generation)?;

    Ok(ClaimParameters(params))
}

/// Save parameters to files.
///
/// # Arguments
/// * `params` - The parameters to save
/// * `proving_key_path` - Path for the proving key file
/// * `verifying_key_path` - Path for the verifying key file
///
/// # Errors
/// Returns an error if writing fails.
pub fn save_parameters(
    params: &ClaimParameters,
    proving_key_path: &Path,
    verifying_key_path: &Path,
) -> Result<(), ParameterError> {
    // Save proving key (full parameters)
    let mut proving_file = std::fs::File::create(proving_key_path)?;
    params
        .0
        .write(&mut proving_file)
        .map_err(ParameterError::Serialization)?;

    // Save verifying key separately
    let mut verifying_file = std::fs::File::create(verifying_key_path)?;
    params
        .0
        .vk
        .write(&mut verifying_file)
        .map_err(ParameterError::Serialization)?;

    Ok(())
}

/// Load parameters from a proving key file.
///
/// # Arguments
/// * `proving_key_path` - Path to the proving key file
/// * `checked` - If true, verify the parameters (slower but safer)
///
/// # Errors
/// Returns an error if reading or parsing fails.
pub fn load_parameters(
    proving_key_path: &Path,
    checked: bool,
) -> Result<ClaimParameters, ParameterError> {
    let file = std::fs::File::open(proving_key_path)?;
    let reader = std::io::BufReader::new(file);

    let params = Parameters::read(reader, checked).map_err(ParameterError::Deserialization)?;

    Ok(ClaimParameters(params))
}

/// Load parameters from in-memory bytes.
///
/// # Arguments
/// * `bytes` - Proving key bytes
/// * `checked` - If true, verify the parameters (slower but safer)
///
/// # Errors
/// Returns an error if reading or parsing fails.
pub fn load_parameters_from_bytes(
    bytes: &[u8],
    checked: bool,
) -> Result<ClaimParameters, ParameterError> {
    let cursor = std::io::Cursor::new(bytes);
    let reader = std::io::BufReader::new(cursor);

    let params = Parameters::read(reader, checked).map_err(ParameterError::Deserialization)?;

    Ok(ClaimParameters(params))
}
