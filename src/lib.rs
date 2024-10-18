//! Optimized SHA256 for use in Ethereum.
//!
//! The initial purpose of this crate was to provide an abstraction over the hash function used in
//! the beacon chain. The hash function changed during the specification process, so defining it
//! once in this crate made it easy to replace.
//!
//! Now this crate serves primarily as a wrapper over the `sha2` crate.

use sha2::{Digest, Sha256};

#[cfg(feature = "zero_hash_cache")]
use std::sync::LazyLock;

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;

/// Returns the digest of `input` using the `sha2` implementation.
pub fn hash(input: &[u8]) -> Vec<u8> {
    Sha2Impl.hash(input)
}

/// Hash function returning a fixed-size array (to save on allocations).
///
/// Uses the `sha2` implementation.
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    Sha2Impl.hash_fixed(input)
}

/// Compute the hash of two slices concatenated.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; HASH_LEN] {
    let mut ctxt = Sha2Context::new();
    ctxt.update(h1);
    ctxt.update(h2);
    ctxt.finalize()
}

/// Context trait for abstracting over implementation contexts.
pub trait Sha256Context {
    fn new() -> Self;

    fn update(&mut self, bytes: &[u8]);

    fn finalize(self) -> [u8; HASH_LEN];
}

/// Implementation of SHA256 using the `sha2` crate.
pub struct Sha2Context {
    hasher: Sha256,
}

impl Sha256Context for Sha2Context {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        let result = self.hasher.finalize();
        let mut output = [0u8; HASH_LEN];
        output.copy_from_slice(&result);
        output
    }
}

/// Top-level trait implemented by the `sha2` implementation.
pub trait Sha256Trait {
    type Context: Sha256Context;

    fn hash(&self, input: &[u8]) -> Vec<u8>;

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN];
}

/// Implementation of the `Sha256Trait` using the `sha2` crate.
pub struct Sha2Impl;

impl Sha256Trait for Sha2Impl {
    type Context = Sha2Context;

    fn hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }

    fn hash_fixed(&self, input: &[u8]) -> [u8; HASH_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        let mut output = [0u8; HASH_LEN];
        output.copy_from_slice(&result);
        output
    }
}

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

#[cfg(feature = "zero_hash_cache")]
/// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
pub static ZERO_HASHES: LazyLock<Vec<[u8; HASH_LEN]>> = LazyLock::new(|| {
    let mut hashes = vec![[0; HASH_LEN]; ZERO_HASHES_MAX_INDEX + 1];

    for i in 0..ZERO_HASHES_MAX_INDEX {
        hashes[i + 1] = hash32_concat(&hashes[i], &hashes[i]);
    }

    hashes
});

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[test]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }

    #[cfg(feature = "zero_hash_cache")]
    mod zero_hash {
        use super::*;

        #[test]
        fn zero_hash_zero() {
            assert_eq!(ZERO_HASHES[0], [0; 32]);
        }
    }
}
