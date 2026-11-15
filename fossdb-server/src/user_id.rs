//! Server-side minting of account credentials.
//!
//! The format itself (prefix, alphabet, length, normalisation) is defined in
//! [`fossdb::user_id`], which is dependency-free so the WASM frontend and the
//! CLI can validate input. Only generation lives here, because it needs a
//! CSPRNG.

use anyhow::{Context, Result};
use fossdb::user_id::{ALPHABET, BODY_LEN, ENTROPY_BYTES, PREFIX};

/// Mint a new account credential.
///
/// Draws [`ENTROPY_BYTES`] (128 bits) from the operating system CSPRNG and
/// renders it in Crockford base32. Errors rather than falling back to a
/// weaker source: a predictable credential is a total account compromise, so
/// failing the registration is strictly better than succeeding insecurely.
pub fn generate() -> Result<String> {
    let mut entropy = [0u8; ENTROPY_BYTES];
    getrandom::fill(&mut entropy).context(
        "failed to read from the operating system CSPRNG while minting an account id",
    )?;

    let mut out = String::with_capacity(PREFIX.len() + BODY_LEN);
    out.push_str(PREFIX);

    // Big-endian bit cursor over the entropy, emitting one alphabet symbol
    // per 5 bits. 26 symbols x 5 = 130 bits, so the final symbol is padded
    // with two zero bits; that costs nothing because the full 128 bits of
    // entropy are still represented.
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for byte in entropy {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let symbol = ((acc >> bits) & 0b1_1111) as usize;
            out.push(ALPHABET[symbol] as char);
        }
    }
    if bits > 0 {
        let symbol = ((acc << (5 - bits)) & 0b1_1111) as usize;
        out.push(ALPHABET[symbol] as char);
    }

    debug_assert_eq!(out.len(), PREFIX.len() + BODY_LEN);
    Ok(out)
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
