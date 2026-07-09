"""Generate hardened demo JSON artifacts for the Ouroboros Rust demo.

This tool is hardened-only and writes a JSON blob consumed by `src/bin/demo.rs`.
"""

import argparse
import json
from pathlib import Path
import secrets
import sys
import platform
from typing import Optional


DEFAULT_PASSPHRASE = (
    "orbit olive ladder marble quartz canyon "
    "ripple saddle violet ember walnut falcon"
)
DEFAULT_TEXT = "world"
DEFAULT_OUTPUT_JSON = "scripts/demo_artifact.json"


def _raise_dependency_error(package_name, install_hint, exc):
    """Raise a RuntimeError with environment-aware dependency diagnostics.

    Parameters
    ----------
    package_name : str
        Human-readable package name.
    install_hint : str
        Pip command to install the package.
    exc : Exception
        Original import exception.

    Raises
    ------
    RuntimeError
        Always raised with contextual troubleshooting guidance.
    """
    message = (
        f"Hardened mode requires {package_name}. Install with: {install_hint}"
    )
    detail = str(exc)
    mismatch = (
        "incompatible architecture" in detail
        or "_cffi_backend" in detail
        or "mach-o file, but is an incompatible architecture" in detail
    )
    if mismatch:
        machine = platform.machine()
        message += (
            "\nDetected a Python native-extension architecture mismatch. "
            f"Current interpreter reports machine={machine}, executable={sys.executable}."
            "\nRecreate this virtual environment with an arm64 Python and reinstall deps:"
            "\n  rm -rf .venv"
            "\n  python3 -m venv .venv"
            "\n  source .venv/bin/activate"
            "\n  python3 -m pip install -U pip setuptools wheel"
            "\n  python3 -m pip install argon2-cffi pynacl"
        )
    raise RuntimeError(message) from exc


def _build_payload(text_str, led_on=True, append_crlf=True):
    """Build the fixed 48-byte Ouroboros payload before encryption.

    Parameters
    ----------
    text_str : str
        Text to emit over payload bytes 1..7.
    led_on : bool
        LED state encoded at payload byte 0.
    append_crlf : bool
        If True, append CRLF (\r\n) before fitting into bytes 1..7.

    Returns
    -------
    bytes
        48-byte payload (16-byte dispatch header + 32-byte 0xAA MAC region).

    Raises
    ------
    ValueError
        If output text exceeds 7 bytes after CRLF handling.
    """
    tx_bytes = text_str.encode() + (b'\r\n' if append_crlf else b'')
    if len(tx_bytes) > 7:
        raise ValueError(
            "Output text is too long for fixed dispatch (max 7 bytes after CRLF handling)."
        )
    prog = bytearray(16)
    prog[0] = 1 if led_on else 0
    prog[1:1 + len(tx_bytes)] = tx_bytes
    mac = b'\xAA' * 32
    return bytes(prog) + mac


def _derive_hardened_key(passphrase, salt, memory_kib, iterations, parallelism):
    """Derive a 32-byte key with Argon2id for hardened mode.

    Parameters
    ----------
    passphrase : str
        Human-entered passphrase.
    salt : bytes
        16-byte random salt.
    memory_kib : int
        Argon2 memory cost in KiB.
    iterations : int
        Argon2 iteration count.
    parallelism : int
        Argon2 parallel lanes.

    Returns
    -------
    bytes
        32-byte derived key.

    Raises
    ------
    RuntimeError
        If argon2-cffi is not installed.
    """
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        _raise_dependency_error(
            "argon2-cffi",
            "python3 -m pip install argon2-cffi",
            exc,
        )

    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )


def _is_policy_compliant_hardened_passphrase(passphrase):
    """Return True when passphrase is exactly 12 lowercase ASCII words.

    Parameters
    ----------
    passphrase : str
        Candidate passphrase string.

    Returns
    -------
    bool
        True only for strict 12-word lowercase policy.
    """
    words = passphrase.split()
    if len(words) != 12:
        return False
    return all(word and all(ch.isascii() and ch.islower() for ch in word) for word in words)


def build_hardened_entry(
    key_str,
    text_str,
    led_on=True,
    append_crlf=True,
    salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    memory_kib=1_048_576,
    iterations=3,
    parallelism=1,
):
    """Build a hardened encrypted entry with Argon2id + XChaCha20-Poly1305.

    Parameters
    ----------
    key_str : str
        Passphrase string.
    text_str : str
        Text to emit over bytes 1..7.
    led_on : bool
        LED state encoded at payload byte 0.
    append_crlf : bool
        If True, append CRLF before packing bytes 1..7.
    salt : Optional[bytes]
        Optional 16-byte salt. Randomly generated when omitted.
    nonce : Optional[bytes]
        Optional 24-byte nonce. Randomly generated when omitted.
    memory_kib : int
        Argon2 memory cost in KiB.
    iterations : int
        Argon2 time cost.
    parallelism : int
        Argon2 parallel lanes.

    Returns
    -------
    tuple[bytes, bytes, bytes]
        (salt, nonce, ciphertext_and_tag[64 bytes]).

    Raises
    ------
    RuntimeError
        If PyNaCl is not installed.
    ValueError
        If salt or nonce sizes are invalid.
    """
    if not _is_policy_compliant_hardened_passphrase(key_str):
        raise ValueError(
            "Hardened mode requires exactly 12 lowercase ASCII words in --key."
        )

    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    except ImportError as exc:
        _raise_dependency_error(
            "PyNaCl",
            "python3 -m pip install pynacl",
            exc,
        )

    payload = _build_payload(text_str, led_on=led_on, append_crlf=append_crlf)
    salt = secrets.token_bytes(16) if salt is None else salt
    nonce = secrets.token_bytes(24) if nonce is None else nonce

    if len(salt) != 16:
        raise ValueError("Hardened salt must be exactly 16 bytes.")
    if len(nonce) != 24:
        raise ValueError("Hardened nonce must be exactly 24 bytes.")

    key = _derive_hardened_key(
        passphrase=key_str,
        salt=salt,
        memory_kib=memory_kib,
        iterations=iterations,
        parallelism=parallelism,
    )
    ciphertext_and_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(payload, b"", nonce, key)
    return salt, nonce, ciphertext_and_tag


def _write_demo_json(path, memory_kib, iterations, parallelism, salt, nonce, ciphertext_and_tag):
    """Write a hardened demo artifact JSON file.

    Parameters
    ----------
    path : str
        Output JSON file path.
    memory_kib : int
        Argon2 memory cost in KiB.
    iterations : int
        Argon2 time cost.
    parallelism : int
        Argon2 parallel lanes.
    salt : bytes
        16-byte hardened salt.
    nonce : bytes
        24-byte hardened nonce.
    ciphertext_and_tag : bytes
        64-byte XChaCha20-Poly1305 ciphertext+tag.

    Returns
    -------
    Path
        Resolved output file path.
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "format": "ouroboros-hardened-demo-v1",
        "memory_kib": memory_kib,
        "iterations": iterations,
        "parallelism": parallelism,
        "salt_hex": salt.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_and_tag_hex": ciphertext_and_tag.hex(),
    }

    output_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    return output_path.resolve()


def _hex_decode(value, expected_len, label):
    """Decode a hex string and validate expected byte length.

    Parameters
    ----------
    value : str
        Hex-encoded string.
    expected_len : int
        Required byte length.
    label : str
        Human-readable field name for error messages.

    Returns
    -------
    bytes
        Decoded bytes.

    Raises
    ------
    ValueError
        If string is not valid hex or decoded length is incorrect.
    """
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be valid hex.") from exc
    if len(decoded) != expected_len:
        raise ValueError(f"{label} must decode to exactly {expected_len} bytes.")
    return decoded


def _parse_args():
    """Parse command-line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed command-line options.
    """
    parser = argparse.ArgumentParser(
        description="Generate hardened demo JSON artifact for src/bin/demo.rs."
    )
    parser.add_argument("--key", default=DEFAULT_PASSPHRASE, help="12-word lowercase passphrase.")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="Output text to embed (default: world).")
    parser.add_argument(
        "--led",
        type=int,
        choices=[0, 1],
        default=1,
        help="LED state at payload byte 0 (default: 1).",
    )
    parser.add_argument(
        "--no-crlf",
        action="store_true",
        help="Do not append CRLF to output text before packing bytes 1..7.",
    )
    parser.add_argument(
        "--salt-hex",
        default=None,
        help="Optional hardened salt as 32 hex chars (16 bytes). Random when omitted.",
    )
    parser.add_argument(
        "--nonce-hex",
        default=None,
        help="Optional hardened nonce as 48 hex chars (24 bytes). Random when omitted.",
    )
    parser.add_argument(
        "--memory-kib",
        type=int,
        default=1_048_576,
        help="Argon2 memory cost in KiB for hardened mode (default: 1048576).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Argon2 iteration count for hardened mode (default: 3).",
    )
    parser.add_argument(
        "--parallelism",
        type=int,
        default=1,
        help="Argon2 parallelism lanes for hardened mode (default: 1).",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUTPUT_JSON,
        help="Output artifact JSON path (default: scripts/demo_artifact.json).",
    )
    return parser.parse_args()


# ==============================================================================
# EXECUTION
# ==============================================================================

if __name__ == "__main__":
    args = _parse_args()
    salt = _hex_decode(args.salt_hex, 16, "--salt-hex") if args.salt_hex else None
    nonce = _hex_decode(args.nonce_hex, 24, "--nonce-hex") if args.nonce_hex else None
    hardened_salt, hardened_nonce, ciphertext_and_tag = build_hardened_entry(
        key_str=args.key,
        text_str=args.text,
        led_on=bool(args.led),
        append_crlf=not args.no_crlf,
        salt=salt,
        nonce=nonce,
        memory_kib=args.memory_kib,
        iterations=args.iterations,
        parallelism=args.parallelism,
    )

    output_path = _write_demo_json(
        path=args.out,
        memory_kib=args.memory_kib,
        iterations=args.iterations,
        parallelism=args.parallelism,
        salt=hardened_salt,
        nonce=hardened_nonce,
        ciphertext_and_tag=ciphertext_and_tag,
    )

    print(f"Wrote hardened demo artifact: {output_path}")
