/// Entropy source used during Ouroboros key stretching.
///
/// # Example
///
/// ```rust
/// use encryption::EntropySource;
///
/// struct MyEntropy;
///
/// impl EntropySource for MyEntropy {
///     fn get_jitter(&self) -> u8 { 0 }
/// }
/// ```
pub trait EntropySource {
    /// Retrieves the current jitter sample used as entropy input.
    ///
    /// # Returns
    ///
    /// An 8-bit jitter sample used to perturb timing behavior.
    fn get_jitter(&self) -> u8;
}
