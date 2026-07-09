//! Key stretching using iterated Speck-128/256 encryption.
//!
//! **File:** `hash.rs`
//! **Author:** Kevin Thomas
//! **Date:** 2026
//!
//! MIT License
//!
//! Copyright (c) 2026 Kevin Thomas
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in
//! all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.

// Import crate::crypto::speck
use crate::crypto::speck;

// Import crate::EntropySource
use crate::EntropySource;

/// Initial Davies-Meyer chaining value.
const IV_CONST: [u64; 2] = [0x85AE_67BB_67E6_096A, 0x3AF5_4FA5_72F3_6E3C];
/// Number of hash iterations applied during stretching.
const ITERATIONS: usize = 24_576;

/// Stretches a key using iterated Davies-Meyer hashing.
///
/// # Arguments
///
/// * `entropy_source` - Entropy source used to sample jitter.
/// * `round_keys` - Expanded Speck round keys derived from the input passphrase.
///
/// # Returns
///
/// The 128-bit stretched key material.
pub fn stretch_key<S: EntropySource>(entropy_source: &S, round_keys: &[u64; 34]) -> [u64; 2] {
    let mut hash_buf = IV_CONST;
    for _ in 0..ITERATIONS {
        hash_round(entropy_source, &mut hash_buf, round_keys);
    }
    hash_buf[0] ^= IV_CONST[0];
    hash_buf[1] ^= IV_CONST[1];
    hash_buf
}

/// Executes one Davies-Meyer compression round.
///
/// # Arguments
///
/// * `entropy_source` - Entropy source used to sample jitter.
/// * `hash_buf` - Current chaining value updated in place.
/// * `round_keys` - Expanded Speck round keys.
///
/// # Returns
///
/// This function does not return a value; it mutates `hash_buf` in place.
#[inline]
fn hash_round<S: EntropySource>(
    entropy_source: &S,
    hash_buf: &mut [u64; 2],
    round_keys: &[u64; 34],
) {
    core::hint::black_box(entropy_source.get_jitter());
    speck::encrypt_block(hash_buf, round_keys);
}

#[cfg(test)]
mod tests {
    // Import all parent module items
    use super::*;

    /// A mock entropy source for testing.
    struct MockEntropy;

    /// `EntropySource` implementation for the mock entropy source.
    impl EntropySource for MockEntropy {
        /// Queries the current hardware jitter.
        ///
        /// # Returns
        ///
        /// An 8-bit unsigned integer value.
        fn get_jitter(&self) -> u8 {
            0
        }
    }

    /// Verifies that stretching changes the initial chaining value.
    #[test]
    fn test_stretch_key() {
        let hw = MockEntropy;
        let round_keys = [0u64; 34];
        let out = stretch_key(&hw, &round_keys);
        assert_ne!(out, IV_CONST);
    }
}
