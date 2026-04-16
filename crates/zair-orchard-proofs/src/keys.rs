use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use halo2_proofs::plonk;
#[cfg(feature = "verify")]
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use zair_orchard_circuit::circuit::airdrop::{
    Circuit, ValueCommitmentScheme as CircuitValueCommitmentScheme,
};

use crate::error::ClaimProofError;
use crate::types::ValueCommitmentScheme;

#[derive(Debug)]
pub struct Keys {
    #[cfg(feature = "verify")]
    pub(crate) vk: VerifyingKey<vesta::Affine>,
    #[cfg(feature = "prove")]
    pub(crate) pk: plonk::ProvingKey<vesta::Affine>,
}

fn dummy_circuit(target_id: [u8; 32], target_id_len: u8) -> Circuit {
    // Keygen doesn't need witnesses; we only need a circuit with the correct configuration.
    Circuit {
        target_id,
        target_id_len,
        ..Circuit::default()
    }
}

fn keygen(
    params: &Params<vesta::Affine>,
    scheme: ValueCommitmentScheme,
    target_id: [u8; 32],
    target_id_len: u8,
) -> Result<Keys, ClaimProofError> {
    let circuit_scheme: CircuitValueCommitmentScheme = scheme.into();
    let mut circuit = dummy_circuit(target_id, target_id_len);
    circuit.value_commitment_scheme = circuit_scheme;

    let vk = plonk::keygen_vk(params, &circuit)?;
    #[cfg(feature = "prove")]
    let pk = plonk::keygen_pk(params, vk.clone(), &circuit)?;

    Ok(Keys {
        #[cfg(feature = "verify")]
        vk,
        #[cfg(feature = "prove")]
        pk,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    scheme: ValueCommitmentScheme,
    target_id: [u8; 32],
    target_id_len: u8,
}

pub fn keys_for(
    params: &Params<vesta::Affine>,
    scheme: ValueCommitmentScheme,
    target_id: [u8; 32],
    target_id_len: u8,
) -> Result<Arc<Keys>, ClaimProofError> {
    let circuit_scheme: CircuitValueCommitmentScheme = scheme.into();
    let expected = circuit_scheme.k();
    let actual = params.k();
    if expected != actual {
        return Err(ClaimProofError::InvalidParamsK { expected, actual });
    }

    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Arc<Keys>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let cache_key = CacheKey {
        scheme,
        target_id,
        target_id_len,
    };

    if let Some(keys) = cache
        .lock()
        .map_err(|_| ClaimProofError::CachePoisoned)?
        .get(&cache_key)
        .cloned()
    {
        return Ok(keys);
    }

    let keys = Arc::new(keygen(params, scheme, target_id, target_id_len)?);
    cache
        .lock()
        .map_err(|_| ClaimProofError::CachePoisoned)?
        .insert(cache_key, Arc::clone(&keys));
    Ok(keys)
}
