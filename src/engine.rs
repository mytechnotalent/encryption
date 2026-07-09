use crate::crypto;
use crate::EntropySource;
#[cfg(feature = "hardened")]
use argon2::{Algorithm, Argon2, Params, Version};
#[cfg(feature = "hardened")]
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
#[cfg(feature = "hardened")]
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};

/// Size of one Ouroboros ciphertext entry in bytes.
pub const ENTRY_SIZE: usize = 48;

/// Size of the random salt used by hardened Argon2id key derivation.
#[cfg(feature = "hardened")]
pub const HARDENED_SALT_SIZE: usize = 16;

/// Size of the random XChaCha20-Poly1305 nonce used in hardened mode.
#[cfg(feature = "hardened")]
pub const HARDENED_NONCE_SIZE: usize = 24;

/// Size of the XChaCha20-Poly1305 authentication tag.
#[cfg(feature = "hardened")]
pub const HARDENED_TAG_SIZE: usize = 16;

/// Pre-computed encrypted ciphertext entry.
///
/// Encrypted with Speck-128/256 + Davies-Meyer + CTR for passphrase
/// `"hello"` producing output `"world"`. See `scripts/dec.py` in this
/// repository to generate custom entries.
pub const CIPHERTEXT: [u8; ENTRY_SIZE] = [
    0xB3, 0xD9, 0xD9, 0x88, 0x17, 0xB7, 0xEB, 0x9B, 0xB2, 0xEB, 0xE6, 0xB0, 0xD0, 0x87, 0x6E, 0xF9,
    0x09, 0x23, 0xE5, 0xA5, 0x69, 0x9F, 0x34, 0x4B, 0xDD, 0x24, 0xD3, 0x4A, 0x35, 0x96, 0x47, 0x7F,
    0xB3, 0x13, 0xFC, 0x6C, 0x7B, 0x95, 0xAE, 0x25, 0xD1, 0x1C, 0xA5, 0x0A, 0xD7, 0xE1, 0x65, 0x3A,
];

/// Errors returned by the Ouroboros library API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    /// The supplied passphrase was empty.
    EmptyPassphrase,

    /// The supplied passphrase exceeded the 32-byte key buffer.
    PassphraseTooLong,

    /// The ciphertext decrypted but failed the constant-time MAC check.
    AuthenticationFailed,

    /// Hardened KDF parameters were invalid.
    #[cfg(feature = "hardened")]
    InvalidHardenedParams,

    /// Hardened passphrase failed the strict 12-lowercase-word policy.
    #[cfg(feature = "hardened")]
    PassphrasePolicyViolation,

    /// Hardened Argon2id derivation failed.
    #[cfg(feature = "hardened")]
    HardenedKdfFailed,
}

/// Tunable Argon2id work factors for hardened decryption mode.
#[cfg(feature = "hardened")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenedKdfParams {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,

    /// Argon2 time cost (number of passes).
    pub iterations: u32,

    /// Argon2 parallelism lanes.
    pub parallelism: u32,
}

#[cfg(feature = "hardened")]
impl Default for HardenedKdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

/// Decoded payload operation emitted by the decrypted Ouroboros program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadOp<'a> {
    /// Set LED state from byte 0 (`true` when non-zero).
    LedState(bool),

    /// Transmit payload bytes from indices `1..8`.
    TxBytes(&'a [u8]),
}

/// Iterator over decoded payload operations.
pub struct PayloadIter<'a> {
    /// Raw decrypted payload bytes being decoded.
    bytes: &'a [u8; ENTRY_SIZE],

    /// Current decode stage.
    stage: u8,
}

impl<'a> Iterator for PayloadIter<'a> {
    type Item = PayloadOp<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let op = match self.stage {
            0 => Some(PayloadOp::LedState(self.bytes[0] != 0)),
            1 => Some(PayloadOp::TxBytes(&self.bytes[1..8])),
            _ => None,
        };
        if self.stage < 2 {
            self.stage += 1;
        }
        op
    }
}

/// The core Ouroboros engine that derives keys and decrypts Ouroboros entries.
///
/// # Example
///
/// ```rust
/// use encryption::{EntropySource, OuroborosEngine, PayloadOp};
///
/// struct MockEntropy;
/// impl EntropySource for MockEntropy {
///     fn get_jitter(&self) -> u8 { 0 }
/// }
///
/// let mut engine = OuroborosEngine::new(MockEntropy);
/// let payload = *engine.decrypt(b"hello").unwrap();
/// assert_eq!(payload.len(), encryption::ENTRY_SIZE);
/// let ops: Vec<_> = engine.payload_ops().collect();
/// assert_eq!(ops[0], PayloadOp::LedState(payload[0] != 0));
/// assert_eq!(ops[1], PayloadOp::TxBytes(&payload[1..8]));
/// ```
pub struct OuroborosEngine<S: EntropySource> {
    /// Entropy provider used during key stretching.
    entropy_source: S,

    /// Current 128-bit Davies-Meyer output.
    hash_buf: [u64; 2],

    /// Expanded Speck-128/256 round keys derived from the passphrase.
    round_keys: [u64; 34],

    /// Most recently decrypted payload buffer.
    result_buf: [u8; ENTRY_SIZE],
}

impl<S: EntropySource> OuroborosEngine<S> {
    /// Creates a new Ouroboros engine instance.
    ///
    /// # Arguments
    ///
    /// * `entropy_source` - Entropy provider used during key stretching.
    #[must_use]
    pub const fn new(entropy_source: S) -> Self {
        Self {
            entropy_source,
            hash_buf: [0; 2],
            round_keys: [0; 34],
            result_buf: [0; ENTRY_SIZE],
        }
    }

    /// Decrypts the default bundled ciphertext with the supplied passphrase.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Passphrase bytes, up to 32 bytes long.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 32 bytes.
    /// Returns [`EngineError::AuthenticationFailed`] when the decrypted entry fails MAC validation.
    pub fn decrypt(&mut self, passphrase: &[u8]) -> Result<&[u8; ENTRY_SIZE], EngineError> {
        self.decrypt_with_ciphertext(passphrase, &CIPHERTEXT)
    }

    /// Decrypts a caller-supplied ciphertext entry with the supplied passphrase.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Passphrase bytes, up to 32 bytes long.
    /// * `ciphertext` - One 48-byte Ouroboros ciphertext entry.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 32 bytes.
    /// Returns [`EngineError::AuthenticationFailed`] when the decrypted entry fails MAC validation.
    pub fn decrypt_with_ciphertext(
        &mut self,
        passphrase: &[u8],
        ciphertext: &[u8; ENTRY_SIZE],
    ) -> Result<&[u8; ENTRY_SIZE], EngineError> {
        Self::validate_passphrase_32(passphrase)?;
        let key_words = Self::key_words(passphrase)?;
        self.round_keys = crypto::speck::expand_key(&key_words);
        self.hash_buf = crypto::hash::stretch_key(&self.entropy_source, &self.round_keys);
        let (result_buf, is_valid) =
            crypto::ctr::decrypt_and_verify(ciphertext, &self.hash_buf, &self.round_keys);
        if is_valid.unwrap_u8() == 0 {
            self.result_buf.fill(0);
            return Err(EngineError::AuthenticationFailed);
        }
        self.result_buf = result_buf;
        Ok(&self.result_buf)
    }

    /// Decrypts a hardened ciphertext entry using Argon2id and XChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Human-entered passphrase bytes.
    /// * `kdf_params` - Argon2id work-factor configuration.
    /// * `salt` - Per-ciphertext random salt.
    /// * `nonce` - Per-ciphertext random `XChaCha20` nonce.
    /// * `ciphertext_and_tag` - 48-byte ciphertext followed by 16-byte tag.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 512 bytes.
    /// Returns [`EngineError::PassphrasePolicyViolation`] when `passphrase` is not exactly 12 lowercase words.
    /// Returns [`EngineError::InvalidHardenedParams`] when Argon2 parameters are invalid.
    /// Returns [`EngineError::HardenedKdfFailed`] when Argon2 derivation fails.
    /// Returns [`EngineError::AuthenticationFailed`] when AEAD authentication fails.
    #[cfg(feature = "hardened")]
    pub fn decrypt_hardened(
        &mut self,
        passphrase: &[u8],
        kdf_params: HardenedKdfParams,
        salt: &[u8; HARDENED_SALT_SIZE],
        nonce: &[u8; HARDENED_NONCE_SIZE],
        ciphertext_and_tag: &[u8; ENTRY_SIZE + HARDENED_TAG_SIZE],
    ) -> Result<&[u8; ENTRY_SIZE], EngineError> {
        Self::validate_hardened_passphrase(passphrase)?;
        let key = Self::derive_hardened_key(passphrase, kdf_params, salt)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce_ref = XNonce::from_slice(nonce);
        let mut buf = [0u8; ENTRY_SIZE];
        buf.copy_from_slice(&ciphertext_and_tag[..ENTRY_SIZE]);
        let mut tag_buf = [0u8; HARDENED_TAG_SIZE];
        tag_buf.copy_from_slice(&ciphertext_and_tag[ENTRY_SIZE..]);
        let tag_ref = Tag::from_slice(&tag_buf);
        if cipher
            .decrypt_in_place_detached(nonce_ref, b"", &mut buf, tag_ref)
            .is_err()
        {
            self.result_buf.fill(0);
            return Err(EngineError::AuthenticationFailed);
        }
        self.result_buf = buf;
        Ok(&self.result_buf)
    }

    /// Encrypts one 48-byte payload into hardened ciphertext using Argon2id and XChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Human-entered passphrase bytes.
    /// * `kdf_params` - Argon2id work-factor configuration.
    /// * `salt` - Per-ciphertext random salt.
    /// * `nonce` - Per-ciphertext random `XChaCha20` nonce.
    /// * `payload` - Plaintext 48-byte payload.
    ///
    /// # Returns
    ///
    /// A 64-byte buffer containing ciphertext then authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 512 bytes.
    /// Returns [`EngineError::PassphrasePolicyViolation`] when `passphrase` is not exactly 12 lowercase words.
    /// Returns [`EngineError::InvalidHardenedParams`] when Argon2 parameters are invalid.
    /// Returns [`EngineError::HardenedKdfFailed`] when Argon2 derivation fails.
    #[cfg(feature = "hardened")]
    pub fn encrypt_hardened(
        &mut self,
        passphrase: &[u8],
        kdf_params: HardenedKdfParams,
        salt: &[u8; HARDENED_SALT_SIZE],
        nonce: &[u8; HARDENED_NONCE_SIZE],
        payload: &[u8; ENTRY_SIZE],
    ) -> Result<[u8; ENTRY_SIZE + HARDENED_TAG_SIZE], EngineError> {
        Self::validate_hardened_passphrase(passphrase)?;
        let key = Self::derive_hardened_key(passphrase, kdf_params, salt)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce_ref = XNonce::from_slice(nonce);
        let mut buf = *payload;
        let tag = cipher
            .encrypt_in_place_detached(nonce_ref, b"", &mut buf)
            .map_err(|_| EngineError::AuthenticationFailed)?;
        let mut out = [0u8; ENTRY_SIZE + HARDENED_TAG_SIZE];
        out[..ENTRY_SIZE].copy_from_slice(&buf);
        out[ENTRY_SIZE..].copy_from_slice(&tag);
        Ok(out)
    }

    /// Returns the most recently decrypted payload buffer.
    ///
    /// # Returns
    ///
    /// A reference to the internal 48-byte payload buffer.
    #[must_use]
    pub const fn payload(&self) -> &[u8; ENTRY_SIZE] {
        &self.result_buf
    }

    /// Returns an iterator over decoded operations in the current payload.
    ///
    /// # Returns
    ///
    /// A `PayloadIter` that yields LED state first, followed by TX bytes.
    #[must_use]
    pub const fn payload_ops(&self) -> PayloadIter<'_> {
        PayloadIter {
            bytes: &self.result_buf,
            stage: 0,
        }
    }

    /// Converts passphrase bytes into the four 64-bit words expected by Speck.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Raw passphrase bytes to validate and pack.
    ///
    /// # Returns
    ///
    /// Four little-endian `u64` words for Speck key expansion.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 32 bytes.
    fn key_words(passphrase: &[u8]) -> Result<[u64; 4], EngineError> {
        Self::validate_passphrase_32(passphrase)?;

        let mut buf = [0u8; 32];
        buf[..passphrase.len()].copy_from_slice(passphrase);
        let mut key_words = [0u64; 4];
        for (slot, chunk) in key_words.iter_mut().zip(buf.chunks(8)) {
            *slot = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Ok(key_words)
    }

    /// Validates basic passphrase constraints.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Raw passphrase bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` when constraints are satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 32 bytes.
    fn validate_passphrase_32(passphrase: &[u8]) -> Result<(), EngineError> {
        if passphrase.is_empty() {
            return Err(EngineError::EmptyPassphrase);
        }
        if passphrase.len() > 32 {
            return Err(EngineError::PassphraseTooLong);
        }
        Ok(())
    }

    /// Validates hardened passphrase constraints used by terminal-entry workflows.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Raw passphrase bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` when constraints are satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyPassphrase`] when `passphrase` has zero length.
    /// Returns [`EngineError::PassphraseTooLong`] when `passphrase` exceeds 512 bytes.
    /// Returns [`EngineError::PassphrasePolicyViolation`] when `passphrase` is not exactly 12 lowercase words.
    #[cfg(feature = "hardened")]
    fn validate_hardened_passphrase(passphrase: &[u8]) -> Result<(), EngineError> {
        if passphrase.is_empty() {
            return Err(EngineError::EmptyPassphrase);
        }
        if passphrase.len() > 512 {
            return Err(EngineError::PassphraseTooLong);
        }
        let text =
            core::str::from_utf8(passphrase).map_err(|_| EngineError::PassphrasePolicyViolation)?;
        let mut count = 0usize;
        for word in text.split_whitespace() {
            if word.is_empty() || !word.chars().all(|ch| ch.is_ascii_lowercase()) {
                return Err(EngineError::PassphrasePolicyViolation);
            }
            count += 1;
        }
        if count != 12 {
            return Err(EngineError::PassphrasePolicyViolation);
        }
        Ok(())
    }

    /// Derives a 256-bit hardened key from passphrase material using Argon2id.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - Raw passphrase bytes.
    /// * `kdf_params` - Argon2id work-factor configuration.
    /// * `salt` - Per-ciphertext random salt.
    ///
    /// # Returns
    ///
    /// A 32-byte key for AEAD operations.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidHardenedParams`] when Argon2 parameters are invalid.
    /// Returns [`EngineError::HardenedKdfFailed`] when Argon2 derivation fails.
    #[cfg(feature = "hardened")]
    fn derive_hardened_key(
        passphrase: &[u8],
        kdf_params: HardenedKdfParams,
        salt: &[u8; HARDENED_SALT_SIZE],
    ) -> Result<[u8; 32], EngineError> {
        let params = Params::new(
            kdf_params.memory_kib,
            kdf_params.iterations,
            kdf_params.parallelism,
            Some(32),
        )
        .map_err(|_| EngineError::InvalidHardenedParams)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|_| EngineError::HardenedKdfFailed)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic entropy source used by unit tests.
    struct MockEntropy;

    /// `EntropySource` implementation for deterministic test behavior.
    impl EntropySource for MockEntropy {
        /// Returns a fixed jitter sample for deterministic tests.
        ///
        /// # Returns
        ///
        /// Always returns `0`.
        fn get_jitter(&self) -> u8 {
            0
        }
    }

    /// Verifies that caller-supplied default ciphertext matches bundled decryption behavior.
    #[test]
    fn test_decrypt_with_ciphertext_matches_default_entry() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let default_payload = *engine.decrypt(b"hello").unwrap();
        let external_payload = *engine
            .decrypt_with_ciphertext(b"hello", &CIPHERTEXT)
            .unwrap();
        assert_eq!(external_payload, default_payload);
    }

    /// Verifies that an incorrect passphrase fails authentication.
    #[test]
    fn test_decrypt_rejects_invalid_passphrase() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let result = engine.decrypt(b"nope");
        assert_eq!(result, Err(EngineError::AuthenticationFailed));
    }

    /// Verifies that an empty passphrase is rejected before decryption.
    #[test]
    fn test_decrypt_rejects_empty_passphrase() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let result = engine.decrypt(b"");
        assert_eq!(result, Err(EngineError::EmptyPassphrase));
    }

    /// Verifies that payload operation decoding yields LED state then TX bytes.
    #[test]
    fn test_payload_ops_match_rp2350_dispatch_shape() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let payload = *engine.decrypt(b"hello").unwrap();
        let mut ops = engine.payload_ops();
        assert_eq!(ops.next(), Some(PayloadOp::LedState(payload[0] != 0)));
        assert_eq!(ops.next(), Some(PayloadOp::TxBytes(&payload[1..8])));
        assert_eq!(ops.next(), None);
    }

    /// Verifies the bundled ciphertext decodes to the expected world-plus-CRLF bytes.
    #[test]
    fn test_default_vector_yields_world_crlf() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let payload = *engine.decrypt(b"hello").unwrap();
        assert_ne!(payload[0], 0);
        assert_eq!(&payload[1..8], b"world\r\n");
    }

    /// Verifies hardened mode round-trips when passphrase and parameters match.
    #[cfg(feature = "hardened")]
    #[test]
    fn test_hardened_round_trip() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let params = HardenedKdfParams {
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [0x55u8; HARDENED_SALT_SIZE];
        let nonce = [0x33u8; HARDENED_NONCE_SIZE];
        let mut payload = [0u8; ENTRY_SIZE];
        payload[0] = 1;
        payload[1..8].copy_from_slice(b"world\r\n");
        let passphrase =
            b"orbit olive ladder marble quartz canyon ripple saddle violet ember walnut falcon";
        let encrypted = engine
            .encrypt_hardened(passphrase, params, &salt, &nonce, &payload)
            .unwrap();
        let decrypted = engine
            .decrypt_hardened(passphrase, params, &salt, &nonce, &encrypted)
            .unwrap();
        assert_eq!(decrypted, &payload);
    }

    /// Verifies hardened mode rejects incorrect passphrases.
    #[cfg(feature = "hardened")]
    #[test]
    fn test_hardened_rejects_wrong_passphrase() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let params = HardenedKdfParams {
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [0x22u8; HARDENED_SALT_SIZE];
        let nonce = [0x11u8; HARDENED_NONCE_SIZE];
        let payload = [0xAAu8; ENTRY_SIZE];
        let good =
            b"orbit olive ladder marble quartz canyon ripple saddle violet ember walnut falcon";
        let bad = b"amber basil cedar drift ember frost garnet harbor ivory juniper kelp lilac";
        let encrypted = engine
            .encrypt_hardened(good, params, &salt, &nonce, &payload)
            .unwrap();
        let result = engine.decrypt_hardened(bad, params, &salt, &nonce, &encrypted);
        assert_eq!(result, Err(EngineError::AuthenticationFailed));
    }

    /// Verifies hardened mode rejects passphrases that violate the strict word policy.
    #[cfg(feature = "hardened")]
    #[test]
    fn test_hardened_rejects_non_policy_passphrase() {
        let mut engine = OuroborosEngine::new(MockEntropy);
        let params = HardenedKdfParams {
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [0x22u8; HARDENED_SALT_SIZE];
        let nonce = [0x11u8; HARDENED_NONCE_SIZE];
        let payload = [0xAAu8; ENTRY_SIZE];
        let result = engine.encrypt_hardened(
            b"correct horse battery staple",
            params,
            &salt,
            &nonce,
            &payload,
        );
        assert_eq!(result, Err(EngineError::PassphrasePolicyViolation));
    }
}
