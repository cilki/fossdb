//! Server-side minting and verification of collector/worker API keys.
//!
//! The format is defined in [`fossdb::api_key`]; only the parts needing a
//! CSPRNG and a hash function live here.

use anyhow::{Context, Result};
use fossdb::api_key::{ALPHABET, ID_LEN, PREFIX, SECRET_ENTROPY_BYTES, SECRET_LEN};
use sha2::{Digest, Sha256};

/// A freshly minted key: the full string to hand out, plus what to store.
pub struct MintedKey {
    /// Complete key. Disclosed once and never recoverable.
    pub key: String,
    pub key_id: String,
    pub secret_hash: String,
}

/// Mint a new API key.
///
/// Both halves come from the OS CSPRNG. The id is random rather than
/// sequential so that listing keys does not reveal how many have ever
/// existed, and so two servers cannot mint colliding ids.
pub fn mint() -> Result<MintedKey> {
    // The id needs far less entropy than the secret - it is only a lookup
    // handle - but it must still not be guessable enough to let someone
    // enumerate which keys exist.
    let key_id = random_base32(ID_LEN)?;
    let secret = random_base32(SECRET_LEN)?;

    let secret_hash = hash_secret(&secret);
    let key = format!("{PREFIX}{key_id}_{secret}");

    debug_assert!(fossdb::api_key::is_well_formed(&key));

    Ok(MintedKey {
        key,
        key_id,
        secret_hash,
    })
}

/// Hex SHA-256 of a key's secret component.
pub fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());

    // Lowercase hex, so stored hashes compare byte-for-byte.
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare a presented secret against a stored hash in constant time.
///
/// This runs on every collector and worker request. The comparison is over
/// hashes rather than secrets, and does not short-circuit on the first
/// differing byte.
pub fn verify_secret(presented: &str, stored_hash: &str) -> bool {
    let computed = hash_secret(presented);
    let (a, b) = (computed.as_bytes(), stored_hash.as_bytes());

    if a.len() != b.len() {
        return false;
    }

    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Draw `len` characters of Crockford base32 from the OS CSPRNG.
fn random_base32(len: usize) -> Result<String> {
    // One byte per character, reduced into the alphabet. Rejection sampling
    // avoids the modulo bias that `byte % 32` would introduce... except 256
    // is an exact multiple of 32, so the mask below is already uniform.
    let mut bytes = vec![0u8; len.max(SECRET_ENTROPY_BYTES)];
    getrandom::fill(&mut bytes)
        .context("failed to read from the operating system CSPRNG while minting an API key")?;

    Ok(bytes
        .into_iter()
        .take(len)
        // 32 divides 256 exactly, so masking the low 5 bits is uniform.
        .map(|b| ALPHABET[(b & 0b1_1111) as usize] as char)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn minted_keys_are_well_formed() {
        for _ in 0..256 {
            let minted = mint().unwrap();
            assert!(fossdb::api_key::is_well_formed(&minted.key), "{}", minted.key);
            assert!(fossdb::api_key::is_well_formed_id(&minted.key_id));

            // The stored record must be reconstructible from the key.
            let (id, secret) = fossdb::api_key::split(&minted.key).unwrap();
            assert_eq!(id, minted.key_id);
            assert_eq!(hash_secret(secret), minted.secret_hash);
        }
    }

    #[test]
    fn minted_keys_do_not_repeat() {
        let keys: HashSet<String> = (0..512).map(|_| mint().unwrap().key).collect();
        assert_eq!(keys.len(), 512);

        let ids: HashSet<String> = (0..512).map(|_| mint().unwrap().key_id).collect();
        assert_eq!(ids.len(), 512);
    }

    #[test]
    fn generation_covers_the_whole_alphabet() {
        let mut seen = HashSet::new();
        for _ in 0..512 {
            for ch in mint().unwrap().key_id.chars() {
                seen.insert(ch);
            }
        }
        assert_eq!(seen.len(), ALPHABET.len(), "unreachable alphabet symbols");
    }

    #[test]
    fn hash_is_stable_and_hex() {
        let a = hash_secret("3k9x7m2qdv5r8ptw1ny6az4cbf");
        let b = hash_secret("3k9x7m2qdv5r8ptw1ny6az4cbf");

        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn hash_is_not_the_secret() {
        let secret = "3k9x7m2qdv5r8ptw1ny6az4cbf";
        assert!(!hash_secret(secret).contains(secret));
    }

    #[test]
    fn verify_accepts_the_right_secret_only() {
        let minted = mint().unwrap();
        let (_, secret) = fossdb::api_key::split(&minted.key).unwrap();

        assert!(verify_secret(secret, &minted.secret_hash));
        assert!(!verify_secret("3k9x7m2qdv5r8ptw1ny6az4cbf", &minted.secret_hash));
        assert!(!verify_secret("", &minted.secret_hash));
    }

    #[test]
    fn verify_rejects_a_malformed_stored_hash() {
        // A truncated or corrupted record must fail closed, not match.
        assert!(!verify_secret("anything", ""));
        assert!(!verify_secret("anything", "abc"));
    }

    /// Known-answer test, so a change of hash function is caught rather than
    /// silently invalidating every stored key.
    #[test]
    fn hash_matches_sha256_known_answer() {
        assert_eq!(
            hash_secret("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
