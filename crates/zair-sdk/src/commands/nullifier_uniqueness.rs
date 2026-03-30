//! Helpers for enforcing unique airdrop nullifiers in claim collections.

use std::collections::BTreeSet;

use eyre::ensure;
use zair_core::base::Nullifier;

/// Ensure a collection does not contain duplicate airdrop nullifiers.
///
/// # Errors
/// Returns an error when a duplicate nullifier is found.
pub fn ensure_unique_airdrop_nullifiers<I>(nullifiers: I, context: &str) -> eyre::Result<()>
where
    I: IntoIterator<Item = Nullifier>,
{
    let mut seen = BTreeSet::new();
    for (index, nullifier) in nullifiers.into_iter().enumerate() {
        ensure!(
            seen.insert(nullifier),
            "Duplicate {context} entry for airdrop nullifier {nullifier} at index {index}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use zair_core::base::Nullifier;

    use super::ensure_unique_airdrop_nullifiers;

    #[test]
    fn accepts_unique_nullifiers() {
        let nullifiers = vec![
            Nullifier::from([1_u8; 32]),
            Nullifier::from([2_u8; 32]),
            Nullifier::from([3_u8; 32]),
        ];
        let result = ensure_unique_airdrop_nullifiers(nullifiers, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_duplicate_nullifiers() {
        let nullifier = Nullifier::from([7_u8; 32]);
        let result = ensure_unique_airdrop_nullifiers([nullifier, nullifier], "test");
        assert!(result.is_err());
    }
}
