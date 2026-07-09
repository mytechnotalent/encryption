# encryption

`encryption` is a no_std Ouroboros authentication engine with Speck-128/256, Davies-Meyer key stretching, and CTR-mode payload execution.

## Highlights

- `#![no_std]` crate API suitable for microcontroller targets
- Constant-time MAC verification via `subtle`
- Entropy abstraction limited to jitter sampling during key stretching
- Included host demo for local verification and debugging

## 30-Second Quick Test

Run this from a clean checkout to verify the crate works end-to-end:

```bash
cargo test --all-features && cargo run --features demo --bin demo
```

At the prompt, enter:

```text
orbit olive ladder marble quartz canyon ripple saddle violet ember walnut falcon
```

Expected result:

```text
hello
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
encryption = { git = "https://github.com/mytechnotalent/encryption" }
```

## Compatibility Matrix

| Area | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Rust crate build (`cargo test --all-features`) | Tested | Toolchain-supported; verify in your environment | Toolchain-supported; verify in your environment |
| Demo binary (`cargo run --features demo --bin demo`) | Tested | Supported (`crossterm`) | Supported (`crossterm`) |
| `scripts/dec.py` (`argon2-cffi`, `pynacl`) | Tested | Supported with Python 3 + native deps | Supported with Python 3 + native deps |

Toolchain used for latest validation:

- Rust stable (`cargo`)
- Python 3.12+ with `argon2-cffi` and `pynacl`

## Quick Start

Implement `EntropySource` for your platform, then decrypt a passphrase and consume the decoded payload operations:

```rust
# use encryption::{EntropySource, OuroborosEngine, PayloadOp};
# struct MockEntropy;
# impl EntropySource for MockEntropy {
#     fn get_jitter(&self) -> u8 { 0 }
# }
let mut engine = OuroborosEngine::new(MockEntropy);
let _payload = engine.decrypt_with_ciphertext(b"hello", &encryption::CIPHERTEXT).unwrap();
for op in engine.payload_ops() {
	match op {
		PayloadOp::LedState(on) => {
			let _ = on;
		}
		PayloadOp::TxBytes(bytes) => {
			let _ = bytes;
		}
	}
}
```

The library no longer owns UART, LED, or delay behavior. Callers are responsible for mapping `PayloadOp` values onto their own platform I/O.

Payload decoding uses a fixed dispatch shape: one LED state from byte `0` and transmitted bytes from `1..8`.

Authentication failure is reported as `EngineError::AuthenticationFailed` rather than a successful decrypt of a zeroed buffer.

## Why This vs Alternatives

Use this project when you want:

- A small, auditable `no_std` Rust authentication/decryption engine for embedded-oriented flows.
- Explicit payload operation decoding (`LedState`, `TxBytes`) without hardwiring platform I/O.
- A paired host artifact generator (`scripts/dec.py`) and firmware-friendly payload contract.

Prefer mainstream higher-level crypto libraries when you need:

- A general-purpose application crypto toolkit with broad algorithm agility.
- Drop-in network/application protocol primitives rather than fixed demo payload dispatch.
- Third-party audited compliance profiles for production certification targets.

## Running the Demo

A host-side demo with raw terminal input is included. It is intentionally kept out of the default library build so the crate stays clean for embedded consumers.

```bash
cargo run --features demo --bin demo
```

The demo enforces a strict passphrase policy: Enter exactly 12 lowercase words separated by ASCII whitespace (spaces/tabs/newlines are normalized by parsing). Inputs like `hello`, empty lines, or non-policy strings are rejected with a policy hint.

Successful decrypt also requires that your input exactly matches the passphrase used to generate `scripts/demo_artifact.json`.

If you generated the artifact with the default README command, enter this exact 12-word phrase:

```text
orbit olive ladder marble quartz canyon ripple saddle violet ember walnut falcon
```

On success, the demo prints `hello` (plus CRLF by default).

If your artifact was generated with a different passphrase, this phrase will return `Authentication failed.`

Expected behavior summary:

```text
correct phrase for current artifact -> hello
wrong phrase for current artifact   -> Authentication failed.
```

The demo uses `crossterm`, so it should work on the major macOS, Linux, and Windows terminals supported by that crate. It is not a guarantee for every pseudo-terminal, IDE-integrated terminal, or unusual serial console environment.

## Hardened Mode (Argon2id + XChaCha20-Poly1305)

For terminal-entered secrets that need higher modeled offline guessing cost, enable the `hardened` feature:

```bash
cargo test --features hardened
```

Hardened APIs are available on `OuroborosEngine`:

- `encrypt_hardened(passphrase, kdf_params, salt, nonce, payload)`
- `decrypt_hardened(passphrase, kdf_params, salt, nonce, ciphertext_and_tag)`

Use per-ciphertext random values:

- `HARDENED_SALT_SIZE = 16`
- `HARDENED_NONCE_SIZE = 24`

For host/desktop systems where you want a higher per-guess verification cost, the recommended KDF policy for terminal-entered secrets is Argon2id with calibrated runtime near 10 seconds on your baseline hardware. A practical starting point is:

- `memory_kib: 1_048_576` (1 GiB)
- `iterations: 3`
- `parallelism: 1`

Important: passphrase expansion to 32 bytes does not create entropy. Security still depends on the entropy of what the human enters.

## Generating Hardened Demo Artifacts

The `scripts/dec.py` script is hardened-only and writes a JSON artifact consumed by the demo at runtime.

Run it with a strict 12-word lowercase passphrase:

```bash
python3 scripts/dec.py --key "orbit olive ladder marble quartz canyon ripple saddle violet ember walnut falcon" --text "hello"
```

By default this updates `scripts/demo_artifact.json` directly (no Rust copy/paste needed).

`dec.py` enforces the same passphrase policy as the engine and demo: exactly 12 lowercase words under ASCII-whitespace normalization.

If your local `.venv` has native-extension architecture mismatch errors (for example, `_cffi_backend` incompatible architecture), rebuild it first:

```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip setuptools wheel
python3 -m pip install argon2-cffi pynacl
```

Otherwise, install required Python packages first:

```bash
python3 -m pip install argon2-cffi pynacl
```

You can override the output path if needed:

```bash
python3 scripts/dec.py --key "<12 lowercase words>" --text "hello" --out scripts/demo_artifact.json
```

Then rebuild and run:

```bash
cargo test --all-features
cargo run --features demo --bin demo
```

Payload layout is fixed:

- byte `0`: LED state (`1` on, `0` off)
- bytes `1..7`: UART output bytes

By default, `dec.py` appends CRLF (`\r\n`) to `--text`, so output must fit within 7 bytes after that append. Use `--no-crlf` to keep full 7-byte capacity for raw text.

You can also keep your own ciphertext outside the crate and pass it directly to `decrypt_with_ciphertext()`.

## Crate Layout

- `src/lib.rs`: crate root and public re-exports
- `src/entropy.rs`: jitter sampling abstraction
- `src/engine.rs`: passphrase decryption and payload decoding
- `src/crypto/speck.rs`: Speck-128/256 block cipher primitives
- `src/crypto/hash.rs`: Davies-Meyer stretching
- `src/crypto/ctr.rs`: CTR decryption and MAC masking

## Security Notes

The Ouroboros engine uses:
- **Speck-128/256** block cipher with 34 rounds
- **Davies-Meyer** key stretching with 24,576 iterations
- **CTR mode** decryption using a nonce derived from the stretched hash
- **Constant-time** MAC verification over the trailing payload bytes

### Cryptographic Equations

Speck-128/256 round function:

```text
x' = (ROR64(x, 8) + y) xor k_i
y' = (ROL64(y, 3) xor x')
```

Key schedule for `(k_0, l_0, l_1, l_2)`:

```text
l_{i mod 3} = (ROR64(l_{i mod 3}, 8) + k_i) xor i
k_{i+1}     = (ROL64(k_i, 3) xor l_{i mod 3})
```

Davies-Meyer stretching (24,576 iterations):

```text
H_0  = IV
H_j  = E_K(H_{j-1}), j = 1..24576
hash = H_24576 xor IV
```

CTR decryption for 48-byte entries (three blocks):

```text
CTR_b = hash[0:8] || b || 0^7
KS_b  = E_K(CTR_b)
P_b   = C_b xor KS_b
```

Branchless MAC verification over bytes `16..47` against `0xAA`:

```text
diff = OR_i (P[i] xor 0xAA)
valid = (diff == 0)
```

### Why There Is No Known Passphrase Bypass

Short version: there is no known cryptographic shortcut that bypasses the passphrase and directly reveals the message. Under the standard assumption that full-round Speck-128/256 resists key recovery, recovering the plaintext without the passphrase still reduces to a practical key-recovery problem.

- Wrong key gives wrong keystream: `P = C xor KS(K)` only yields the correct plaintext with the correct `K`.
- MAC gating is not the core protection: even if a fault bypassed MAC handling, a wrong key still decrypts to wrong bytes.
- The stretching loop is sequential: `H_j` depends on `H_{j-1}` for all 24,576 iterations.

Known-keystream observation:

```text
KS[16:48] = C[16:48] xor 0xAA
```

This leakage is real (because the MAC plaintext is fixed), but converting those known keystream blocks into the 256-bit key still requires a practical key-recovery attack on full-round Speck-128/256. No such practical attack is known for the full configured variant used here.

This is not a formal proof. It is an implementation claim under current public cryptanalysis assumptions.

Scope boundary: claims here are limited to intended execution with unmodified firmware; firmware patching, instruction-level control, and active fault injection are out of scope.

### Is This Quantum-Safe?

Short answer: **not in the strict post-quantum-cryptography (PQC) sense**.

- This crate does not implement a NIST PQC KEM or signature scheme.
- Security here is symmetric-key + password-guessing cost.
- Against Grover-style brute force, symmetric search exponents are roughly halved.

So the right claim is: **high modeled brute-force cost under stated entropy and KDF assumptions**, not "quantum-proof."

### Crack-Time Math (Actual Numbers)

Assume offline guessing, where each guess runs the full verifier.

- Let `H` be effective passphrase entropy (bits).
- Let `r` be classical guesses/second.
- Let `r_q` be quantum oracle evaluations/second.

Average classical crack time:

```text
T_avg_classical_years = 2^(H-1) / (r * 31,557,600)
```

Optimistic Grover-style estimate (very favorable to attacker):

```text
T_avg_quantum_years = 2^(H/2 - 1) / (r_q * 31,557,600)
```

The quantum formula above is only a coarse upper-bound model. It assumes a scalable fault-tolerant quantum machine can evaluate the full password oracle repeatedly, which is far from current reality.

#### Numeric Scenarios

All values below are average time to crack.

| Scenario | Assumptions | Classical | Quantum (optimistic Grover model) |
| --- | --- | --- | --- |
| Weak human secret | `H = 40`, `r = 10^9/s` | `1.74e-5 years` (~9.2 minutes) | `1.66e-11 years` (~0.52 ms) |
| Better but still human | `H = 60`, `r = 10^9/s` | `18.27 years` | `1.70e-8 years` (~0.54 s) |
| Strong random secret | `H = 80`, `r = 10^9/s` | `1.92e7 years` | `1.74e-5 years` (~9.2 minutes) |
| Very strong random secret | `H = 100`, `r = 10^9/s` | `2.01e13 years` | `0.0178 years` (~6.5 days) |
| Hardened policy target (12 Diceware words) | `H ≈ 155.1`, `r = 0.1/s` (10 s/guess Argon2id calibration) | `~7.76e39 years` | `~3.51e16 years` |

Age-of-universe comparison for the hardened policy row (age of universe `≈ 1.38e10 years`):

```text
Classical ratio = 7.76e39 / 1.38e10 ≈ 5.6e29
Quantum ratio   = 3.51e16 / 1.38e10 ≈ 2.5e6
```

That is approximately:

- Classical: about `5.6e29` times the age of the universe (~560 octillionx).
- Quantum (optimistic Grover model): about `2.5e6` times the age of the universe (~2.5 millionx).

#### Interpreting The Table

- The dominant variable is **entropy**. Low-entropy human secrets are breakable regardless of algorithm branding.
- Hardened mode only helps if operators enforce high-entropy secrets and keep Argon2id calibration expensive.
- Non-memory-hard constructions should not be positioned as high-security password verifiers.

#### Reproducibility Snippet

```python
SECONDS_PER_YEAR = 365.25 * 24 * 3600

def avg_years_classical(H, r):
	return 2 ** (H - 1) / (r * SECONDS_PER_YEAR)

def avg_years_quantum(H, r_q):
	return 2 ** (H / 2 - 1) / (r_q * SECONDS_PER_YEAR)

print(avg_years_classical(155.1, 0.1))
print(avg_years_quantum(155.1, 0.1))
```

### Parity Coverage

Behavioral parity is continuously tested in Rust for:

- passphrase length handling (`1..=32` valid, `0` and `>32` rejected)
- ciphertext-entry size (`48` bytes)
- authentication failure behavior (`AuthenticationFailed`)
- payload dispatch shape: LED state from byte `0`, UART bytes from `1..8`
- default bundled ciphertext vs caller-supplied ciphertext equivalence

This crate is an implementation project, not a third-party audited cryptography library. Review the design, assumptions, and target-specific integration before using it in production.

This crate is suitable as a microcontroller integration component because the library itself is `#![no_std]` and does not require the host demo stack. Target-specific correctness still depends on the caller providing an appropriate `EntropySource` and mapping decoded `PayloadOp` values onto local I/O.

## License

MIT &mdash; see [LICENSE](LICENSE).
