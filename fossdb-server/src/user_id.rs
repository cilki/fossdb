//! Server-side minting of account credentials.
//!
//! The format itself (prefix, alphabet, length, normalisation) is defined in
//! [`fossdb::user_id`], which is dependency-free so the WASM frontend and the
//! CLI can validate input. Only generation lives here, because it needs a
//! CSPRNG.

use anyhow::{Context, Result};
use fossdb::user_id::{ALPHABET, BODY_LEN, PREFIX};

/// Mint a new account credential: [`PREFIX`] followed by [`BODY_LEN`]
/// random Crockford base32 characters (130 bits).
///
/// Errors rather than falling back to a weaker source: a predictable
/// credential is a total account compromise, so failing the registration is
/// strictly better than succeeding insecurely.
pub fn generate() -> Result<String> {
    Ok(format!("{PREFIX}{}", random_base32(BODY_LEN)?))
}

/// Draw `len` characters of Crockford base32 from the OS CSPRNG.
///
/// One byte per character, keeping the low 5 bits. 32 divides 256 exactly,
/// so the mask is uniform and needs no rejection sampling.
pub(crate) fn random_base32(len: usize) -> Result<String> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).context("failed to read from the operating system CSPRNG")?;

    Ok(bytes
        .into_iter()
        .map(|b| ALPHABET[(b & 0b1_1111) as usize] as char)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossdb::user_id::{is_well_formed, normalize, TOTAL_LEN};
    use std::collections::HashSet;

    #[test]
    fn generated_ids_are_well_formed() {
        for _ in 0..256 {
            let id = generate().unwrap();
            assert_eq!(id.len(), TOTAL_LEN, "{id}");
            assert!(is_well_formed(&id), "{id}");
        }
    }

    #[test]
    fn generated_ids_survive_normalization() {
        // A user retyping what we printed must land back on the same id.
        for _ in 0..64 {
            let id = generate().unwrap();
            assert_eq!(normalize(&id), id);
            assert_eq!(normalize(&id.to_uppercase()), id);
        }
    }

    /// Not a statistical test - just a smoke check that we are not emitting a
    /// constant or a low-period sequence.
    #[test]
    fn generated_ids_do_not_repeat() {
        let ids: HashSet<String> = (0..1024).map(|_| generate().unwrap()).collect();
        assert_eq!(ids.len(), 1024);
    }

    /// Every alphabet position must be reachable; an off-by-one in the bit
    /// packing would silently shrink the keyspace.
    #[test]
    fn generation_covers_the_whole_alphabet() {
        let mut seen = HashSet::new();
        for _ in 0..512 {
            for ch in generate().unwrap()[PREFIX.len()..].chars() {
                seen.insert(ch);
            }
        }
        assert_eq!(seen.len(), ALPHABET.len(), "unreachable alphabet symbols");
    }
}
