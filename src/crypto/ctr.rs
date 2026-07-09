//! CTR Mode Decryption and MAC Validation
//!
//! **File:** `ctr.rs`
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

// Import dependencies from subtle
use subtle::{Choice, ConstantTimeEq};

/// The expected padding byte value for MAC verification.
const MAC_BYTE: u8 = 0xAA;
/// Size of the encrypted payload in bytes.
const CIPHERTEXT_SIZE: usize = 48;
/// Block size of the Speck cipher in bytes.
const BLOCK_SIZE: usize = 16;
/// Size of the MAC region in bytes.
const MAC_SIZE: usize = 32;

/// Decrypts a 48-byte ciphertext entry using CTR mode and validates the MAC in constant time.
///
/// # Arguments
///
/// * `ciphertext` - One encrypted 48-byte Ouroboros entry.
/// * `hash_buf` - Stretched hash buffer whose low 64 bits supply the CTR nonce.
/// * `keys` - Expanded Speck round-key schedule.
///
/// # Returns
///
/// A tuple containing the decrypted payload buffer and a constant-time validity flag.
///
/// # Panics
/// Will panic if `CIPHERTEXT_SIZE` or `BLOCK_SIZE` constants are changed such that array conversions fail.
#[must_use]
pub fn decrypt_and_verify(
    ciphertext: &[u8; CIPHERTEXT_SIZE],
    hash_buf: &[u64; 2],
    keys: &[u64; 34],
) -> ([u8; CIPHERTEXT_SIZE], Choice) {
    let mut buf = [0u8; CIPHERTEXT_SIZE];
    decrypt_all_blocks(&mut buf, ciphertext, hash_buf[0].to_le_bytes(), keys);
    let valid = verify_mac(&buf);
    mask_buffer(&mut buf, valid);
    (buf, valid)
}

/// Decrypts all blocks in the ciphertext sequentially.
///
/// # Arguments
///
/// * `buf` - Plaintext output buffer.
/// * `cipher` - Ciphertext input buffer.
/// * `nonce` - Eight-byte nonce used to seed each counter block.
/// * `keys` - Expanded Speck round keys.
fn decrypt_all_blocks(
    buf: &mut [u8; CIPHERTEXT_SIZE],
    cipher: &[u8; CIPHERTEXT_SIZE],
    nonce: [u8; 8],
    keys: &[u64; 34],
) {
    for b_idx in 0..(CIPHERTEXT_SIZE / BLOCK_SIZE) {
        decrypt_block(buf, cipher, nonce, b_idx, keys);
    }
}

/// Decrypts a single block at the given index.
///
/// # Arguments
///
/// * `buf` - Plaintext output buffer.
/// * `c` - Ciphertext input buffer.
/// * `nonce` - Eight-byte nonce used to seed the counter block.
/// * `idx` - Zero-based block index within the ciphertext.
/// * `keys` - Expanded Speck round keys.
fn decrypt_block(
    buf: &mut [u8; CIPHERTEXT_SIZE],
    c: &[u8; CIPHERTEXT_SIZE],
    nonce: [u8; 8],
    idx: usize,
    keys: &[u64; 34],
) {
    let mut ctr = build_ctr_block(nonce, idx);
    speck::encrypt_block(&mut ctr, keys);
    xor_stream(buf, c, &get_stream_bytes(&ctr), idx * BLOCK_SIZE);
}

/// XORs the generated keystream into the destination buffer.
///
/// # Arguments
///
/// * `buf` - Destination buffer written in place.
/// * `c` - Source ciphertext buffer.
/// * `stream` - Keystream bytes for one CTR block.
/// * `offset` - Byte offset of the active block.
fn xor_stream(
    buf: &mut [u8; CIPHERTEXT_SIZE],
    c: &[u8; CIPHERTEXT_SIZE],
    stream: &[u8; BLOCK_SIZE],
    offset: usize,
) {
    for i in 0..BLOCK_SIZE {
        buf[offset + i] = c[offset + i] ^ stream[i];
    }
}

/// Constructs the 128-bit counter block for a given nonce and index.
///
/// # Arguments
///
/// * `nonce` - Eight-byte nonce copied into the low half of the block.
/// * `idx` - Block index encoded into the ninth byte.
///
/// # Returns
///
/// The 128-bit counter block expressed as two 64-bit words.
fn build_ctr_block(nonce: [u8; 8], idx: usize) -> [u64; 2] {
    let mut b = [0u8; BLOCK_SIZE];
    b[0..8].copy_from_slice(&nonce);
    b[8] = u8::try_from(idx).unwrap();
    [
        u64::from_le_bytes(b[0..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..16].try_into().unwrap()),
    ]
}

/// Converts a 128-bit counter block back to a byte array.
///
/// # Arguments
///
/// * `ctr_block` - Counter block words after Speck encryption.
///
/// # Returns
///
/// The same block serialized as 16 keystream bytes.
fn get_stream_bytes(ctr_block: &[u64; 2]) -> [u8; BLOCK_SIZE] {
    let mut stream_bytes = [0u8; BLOCK_SIZE];
    stream_bytes[0..8].copy_from_slice(&ctr_block[0].to_le_bytes());
    stream_bytes[8..16].copy_from_slice(&ctr_block[1].to_le_bytes());
    stream_bytes
}

/// Performs a constant-time verification of the decrypted MAC bytes.
///
/// # Arguments
///
/// * `result_buf` - Decrypted payload buffer including the MAC region.
///
/// # Returns
///
/// A `Choice` indicating whether the MAC region matched `MAC_BYTE`.
fn verify_mac(result_buf: &[u8; CIPHERTEXT_SIZE]) -> Choice {
    let mut is_valid = Choice::from(1u8);
    for &byte in result_buf
        .iter()
        .take(CIPHERTEXT_SIZE)
        .skip(CIPHERTEXT_SIZE - MAC_SIZE)
    {
        is_valid &= byte.ct_eq(&MAC_BYTE);
    }
    is_valid
}

/// Masks the result buffer with zeroes if the MAC was invalid.
///
/// # Arguments
///
/// * `result_buf` - Decrypted payload buffer to clear on MAC failure.
/// * `is_valid` - Constant-time validity flag returned by `verify_mac`.
///
/// # Returns
///
/// This function does not return a value; it mutates `result_buf` in place.
fn mask_buffer(result_buf: &mut [u8; CIPHERTEXT_SIZE], is_valid: Choice) {
    let mask = is_valid.unwrap_u8().wrapping_neg();
    for byte in result_buf {
        *byte &= mask;
    }
}

#[cfg(test)]
mod tests {
    // Import all parent module items
    use super::*;

    /// Encrypts a buffer with the same CTR routine used by the decrypt path.
    ///
    /// # Arguments
    ///
    /// * `p` - Plaintext buffer to encrypt for test setup.
    /// * `h` - Hash output whose low word supplies the CTR nonce.
    /// * `k` - Expanded Speck round keys.
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext buffer.
    fn encrypt_ctr(p: &[u8; 48], h: &[u64; 2], k: &[u64; 34]) -> [u8; 48] {
        let mut c = [0u8; 48];
        for i in 0..3 {
            enc_ctr_blk(&mut c, p, h[0].to_le_bytes(), i, k);
        }
        c
    }

    /// Encrypts one CTR block for test-only ciphertext generation.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Output ciphertext buffer.
    /// * `plaintext` - Input plaintext buffer.
    /// * `nonce` - Nonce bytes for the counter block.
    /// * `block_idx` - Block index for the counter.
    /// * `round_keys` - Expanded Speck round keys.
    fn enc_ctr_blk(
        ciphertext: &mut [u8; 48],
        plaintext: &[u8; 48],
        nonce: [u8; 8],
        block_idx: usize,
        round_keys: &[u64; 34],
    ) {
        let mut ctr = build_ctr_block(nonce, block_idx);
        speck::encrypt_block(&mut ctr, round_keys);
        xor_stream(
            ciphertext,
            plaintext,
            &get_stream_bytes(&ctr),
            block_idx * BLOCK_SIZE,
        );
    }

    /// Verifies that a valid MAC preserves the decrypted plaintext.
    #[test]
    fn test_decrypt_and_verify_valid_mac() {
        let mut plain = [MAC_BYTE; 48];
        for b in plain.iter_mut().take(16) {
            *b = 0x55;
        }
        let c = encrypt_ctr(&plain, &[0u64; 2], &[0u64; 34]);
        let (dec, is_valid) = decrypt_and_verify(&c, &[0u64; 2], &[0u64; 34]);
        assert_eq!(is_valid.unwrap_u8(), 1);
        for &byte in dec.iter().take(16) {
            assert_eq!(byte, 0x55);
        }
    }

    /// Verifies that an invalid MAC is detected and reported.
    #[test]
    fn test_decrypt_and_verify_invalid_mac() {
        let mut plain = [MAC_BYTE; 48];
        for b in plain.iter_mut().take(16) {
            *b = 0x55;
        }
        let mut c = encrypt_ctr(&plain, &[0u64; 2], &[0u64; 34]);
        c[20] ^= 0x01;
        let (_dec, valid) = decrypt_and_verify(&c, &[0u64; 2], &[0u64; 34]);
        assert_eq!(valid.unwrap_u8(), 0);
    }
}
