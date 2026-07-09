//! Interactive Host Demo for Ouroboros Engine
//!
//! **File:** `demo.rs`
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

// Import dependencies from std
use std::{fs, io::Write};

// Import dependencies from encryption
use encryption::{
    EntropySource, HardenedKdfParams, OuroborosEngine, PayloadOp, ENTRY_SIZE, HARDENED_NONCE_SIZE,
    HARDENED_SALT_SIZE, HARDENED_TAG_SIZE,
};

// Import dependencies from serde
use serde::Deserialize;

// Import dependencies from crossterm
use crossterm::event::{read, Event, KeyCode, KeyEventKind};

/// Host-side entropy source used by the demo.
struct HostEntropy;

/// The required number of words for terminal-entered passphrases.
const REQUIRED_WORDS: usize = 12;

/// Default JSON path produced by scripts/dec.py.
const DEMO_ARTIFACT_PATH: &str = "scripts/demo_artifact.json";

/// Serializable on-disk schema for hardened demo artifacts.
#[derive(Deserialize)]
struct DemoArtifactJson {
    format: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_and_tag_hex: String,
}

/// Parsed hardened artifact used for decryption.
struct DemoArtifact {
    kdf_params: HardenedKdfParams,
    salt: [u8; HARDENED_SALT_SIZE],
    nonce: [u8; HARDENED_NONCE_SIZE],
    ciphertext_and_tag: [u8; ENTRY_SIZE + HARDENED_TAG_SIZE],
}

/// `EntropySource` implementation for the host demo.
impl EntropySource for HostEntropy {
    /// Queries the current host jitter sample.
    ///
    /// # Returns
    ///
    /// An 8-bit jitter sample value.
    fn get_jitter(&self) -> u8 {
        0
    }
}

/// Writes the REPL prompt to stdout.
///
/// # Returns
///
/// This function does not return a value.
fn write_prompt() {
    let _ = std::io::stdout().write_all(b"> ");
    let _ = std::io::stdout().flush();
}

/// Writes a byte slice to stdout.
///
/// # Arguments
///
/// * `bytes` - Bytes to write.
///
/// # Returns
///
/// This function does not return a value.
fn write_bytes(bytes: &[u8]) {
    let _ = std::io::stdout().write_all(bytes);
    let _ = std::io::stdout().flush();
}

/// Returns true when input matches the strict terminal passphrase policy.
///
/// # Arguments
///
/// * `input` - Candidate passphrase entered by the user.
///
/// # Returns
///
/// `true` only when input has exactly 12 lowercase alphabetic words.
fn is_policy_compliant_passphrase(input: &str) -> bool {
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() != REQUIRED_WORDS {
        return false;
    }
    words
        .iter()
        .all(|word| !word.is_empty() && word.chars().all(|ch| ch.is_ascii_lowercase()))
}

/// Writes policy help text to guide terminal entry.
///
/// # Returns
///
/// This function does not return a value.
fn write_policy_hint() {
    write_bytes(b"Enter exactly 12 lowercase words separated by spaces.\r\n");
}

/// Parses fixed-length bytes from a lower/upper-hex string.
///
/// # Arguments
///
/// * `label` - Field name for diagnostics.
/// * `value` - Hex-encoded bytes.
///
/// # Returns
///
/// Parsed fixed-size byte array.
fn decode_hex_fixed<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!(
            "{} must be exactly {} hex chars ({} bytes).",
            label,
            N * 2,
            N
        ));
    }
    let mut out = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair_str = core::str::from_utf8(pair)
            .map_err(|_| format!("{} contains non-UTF8 characters.", label))?;
        out[index] = u8::from_str_radix(pair_str, 16)
            .map_err(|_| format!("{} contains invalid hex at byte index {}.", label, index))?;
    }
    Ok(out)
}

/// Loads and validates hardened artifact data from JSON.
///
/// # Arguments
///
/// * `path` - JSON file path.
///
/// # Returns
///
/// Parsed artifact ready for hardened decryption.
fn load_demo_artifact(path: &str) -> Result<DemoArtifact, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read demo artifact '{}': {}", path, err))?;
    let parsed: DemoArtifactJson = serde_json::from_str(&raw)
        .map_err(|err| format!("Failed to parse demo artifact JSON '{}': {}", path, err))?;

    if parsed.format != "ouroboros-hardened-demo-v1" {
        return Err(format!(
            "Unsupported demo artifact format '{}'. Expected 'ouroboros-hardened-demo-v1'.",
            parsed.format
        ));
    }
    let salt = decode_hex_fixed::<HARDENED_SALT_SIZE>("salt_hex", &parsed.salt_hex)?;
    let nonce = decode_hex_fixed::<HARDENED_NONCE_SIZE>("nonce_hex", &parsed.nonce_hex)?;
    let ciphertext_and_tag = decode_hex_fixed::<{ ENTRY_SIZE + HARDENED_TAG_SIZE }>(
        "ciphertext_and_tag_hex",
        &parsed.ciphertext_and_tag_hex,
    )?;
    Ok(DemoArtifact {
        kdf_params: HardenedKdfParams {
            memory_kib: parsed.memory_kib,
            iterations: parsed.iterations,
            parallelism: parsed.parallelism,
        },
        salt,
        nonce,
        ciphertext_and_tag,
    })
}

/// Handles a submitted passphrase line.
///
/// # Arguments
///
/// * `engine` - Demo engine instance.
/// * `line_buf` - Current input line buffer.
///
/// # Returns
///
/// This function does not return a value.
fn handle_submit(
    engine: &mut OuroborosEngine<HostEntropy>,
    artifact: &DemoArtifact,
    line_buf: &mut Vec<u8>,
) {
    write_bytes(b"\r\n");
    let input = core::str::from_utf8(line_buf).unwrap_or("");
    if !is_policy_compliant_passphrase(input) {
        write_policy_hint();
        write_bytes(b"\r\n");
        line_buf.clear();
        write_prompt();
        return;
    }
    if let Ok(_payload) = engine.decrypt_hardened(
        line_buf,
        artifact.kdf_params,
        &artifact.salt,
        &artifact.nonce,
        &artifact.ciphertext_and_tag,
    ) {
        for op in engine.payload_ops() {
            match op {
                PayloadOp::LedState(_on) => {}
                PayloadOp::TxBytes(bytes) => write_bytes(bytes),
            }
        }
    } else {
        write_bytes(b"Authentication failed.\r\n");
    }
    write_bytes(b"\r\n");
    line_buf.clear();
    write_prompt();
}

/// Handles a backspace keypress.
///
/// # Arguments
///
/// * `line_buf` - Current input line buffer.
///
/// # Returns
///
/// This function does not return a value.
fn handle_backspace(line_buf: &mut Vec<u8>) {
    if line_buf.pop().is_some() {
        write_bytes(&[0x08, b' ', 0x08]);
    }
}

/// Handles a printable character.
///
/// # Arguments
///
/// * `line_buf` - Current input line buffer.
/// * `ch` - Character to append and echo.
///
/// # Returns
///
/// This function does not return a value.
fn handle_char(line_buf: &mut Vec<u8>, ch: char) {
    if line_buf.len() < 512 && ch.is_ascii() {
        line_buf.push(ch as u8);
        write_bytes(&[ch as u8]);
    }
}

/// A guard that automatically disables raw mode upon dropping.
struct RawModeGuard;

/// Drop implementation for the raw mode guard.
impl Drop for RawModeGuard {
    /// Executes the drop logic to disable raw mode.
    ///
    /// # Returns
    ///
    /// This function does not return a value.
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Executes the host demo in raw terminal mode.
///
/// # Panics
///
/// Panics if raw terminal mode cannot be enabled.
fn main() {
    let artifact = match load_demo_artifact(DEMO_ARTIFACT_PATH) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{}", err);
            eprintln!("Generate it with: python3 scripts/dec.py --key \"<12 lowercase words>\" --text \"hello\"");
            return;
        }
    };

    crossterm::terminal::enable_raw_mode().expect("failed to enable raw mode");
    let _guard = RawModeGuard;
    let mut engine = OuroborosEngine::new(HostEntropy);
    let mut line_buf = Vec::new();
    write_policy_hint();
    write_prompt();
    loop {
        if let Ok(Event::Key(key_event)) = read() {
            if key_event.kind == KeyEventKind::Press {
                match key_event.code {
                    KeyCode::Char(ch) => handle_char(&mut line_buf, ch),
                    KeyCode::Enter => handle_submit(&mut engine, &artifact, &mut line_buf),
                    KeyCode::Backspace => handle_backspace(&mut line_buf),
                    _ => {}
                }
            }
        }
    }
}
