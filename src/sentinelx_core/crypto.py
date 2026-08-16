"""SentinelX command/response field encryption.

The transport and SentinelX message schema remain unchanged. Only textual
command/response fields are encrypted. Keys are read locally from the agent
host; they are never fetched from GitHub.

Wire format for an encrypted text field:
    sx1:<base64url(ephemeral_X25519_public_key)>:<base64url(nonce)>:<base64url(ciphertext+tag)>

X25519 derives a shared secret and ChaCha20-Poly1305 provides authenticated
confidentiality. The recipient's long-term private key stays local.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from sentinelx_core.crypto_audit import record_plain, record_wire

PREFIX = "sx1"
KEY_DIR = Path("/etc/sentinelx/keys")
COMMAND_PRIVATE = KEY_DIR / "command-private.pem"
RESPONSE_PRIVATE = KEY_DIR / "response-private.pem"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_private(path: Path) -> X25519PrivateKey:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read encryption key {path}: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except Exception as exc:
        raise RuntimeError(f"invalid X25519 private key {path}") from exc
    if not isinstance(key, X25519PrivateKey):
        raise RuntimeError(f"key {path} is not an X25519 private key")
    return key


def _derive(shared: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"sentinelx-field-encryption-v1",
    ).derive(shared)


def encrypt_text(text: str, recipient_public_key: X25519PublicKey) -> str:
    record_plain("response", text)
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(recipient_public_key)
    key = _derive(shared)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, text.encode("utf-8"), PREFIX.encode())
    wire = f"{PREFIX}:{_b64(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}:{_b64(nonce)}:{_b64(ciphertext)}"
    record_wire("response", wire)
    return wire


def decrypt_text(value: str, private_key_path: Path) -> str:
    record_wire("command", value)
    parts = value.split(":")
    if len(parts) != 4 or parts[0] != PREFIX:
        raise ValueError("invalid SentinelX encrypted text")
    ephemeral = X25519PublicKey.from_public_bytes(_unb64(parts[1]))
    nonce = _unb64(parts[2])
    ciphertext = _unb64(parts[3])
    key = _derive(_load_private(private_key_path).exchange(ephemeral))
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, PREFIX.encode())
    except Exception as exc:
        raise ValueError("encrypted SentinelX text authentication failed") from exc
    plaintext = plaintext.decode("utf-8")
    record_plain("command", plaintext)
    return plaintext


def load_public_key(path: Path) -> X25519PublicKey:
    try:
        data = path.read_bytes()
        key = serialization.load_pem_public_key(data)
    except OSError as exc:
        raise RuntimeError(f"cannot read encryption public key {path}: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"invalid X25519 public key {path}") from exc
    if not isinstance(key, X25519PublicKey):
        raise RuntimeError(f"key {path} is not an X25519 public key")
    return key


def decrypt_command(value: str, private_key_path: Path = COMMAND_PRIVATE) -> str:
    return decrypt_text(value, private_key_path)


def encrypt_response(text: str, recipient_public_key: X25519PublicKey) -> str:
    return encrypt_text(text, recipient_public_key)
