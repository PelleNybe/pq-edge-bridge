"""Atomic key file serialization with strict POSIX permissions (chmod 600)."""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import TYPE_CHECKING

from pq_edge_bridge.crypto.kem import (
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ML_KEM_768_SECRET_KEY_BYTES,
    generate_kem_keypair,
)
from pq_edge_bridge.crypto.signer import (
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    generate_signing_keypair,
)
from pq_edge_bridge.exceptions import KeyFormatError

if TYPE_CHECKING:
    from pathlib import Path


def write_secret_key_atomic(path: Path, key_bytes: bytes, *, overwrite: bool = False) -> None:
    """Write secret key bytes atomically with strict 0o600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise KeyFormatError(f"Secret key already exists (use --force to overwrite): {path}")

    tmp_path = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(key_bytes)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    except Exception:
        os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise
    os.close(fd)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def write_public_key_atomic(path: Path, key_bytes: bytes, *, overwrite: bool = False) -> None:
    """Write public key bytes atomically with 0o644 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise KeyFormatError(f"Public key already exists (use --force to overwrite): {path}")

    tmp_path = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o644)
    try:
        view = memoryview(key_bytes)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    except Exception:
        os.close(fd)
        tmp_path.unlink(missing_ok=True)
        raise
    os.close(fd)
    os.replace(tmp_path, path)


def load_key_bytes(path: Path, *, expected_length: int | None = None) -> bytes:
    """Read raw key bytes from ``path`` and optionally validate exact byte length."""
    if not path.is_file():
        raise KeyFormatError(f"Key file not found: {path}")
    data = path.read_bytes()
    if expected_length is not None and len(data) != expected_length:
        raise KeyFormatError(
            f"Invalid key length in {path}: expected {expected_length} bytes, got {len(data)}"
        )
    return data


def generate_node_keypairs(
    output_dir: Path,
    *,
    prefix: str = "node",
    overwrite: bool = False,
) -> dict[str, Path]:
    """Generate ML-KEM-768 and ML-DSA-65 keypairs for a node in ``output_dir``."""
    kem_kp = generate_kem_keypair()
    sig_kp = generate_signing_keypair()

    paths = {
        "kem_public": output_dir / f"{prefix}.kem.pub",
        "kem_secret": output_dir / f"{prefix}.kem.key",
        "sig_public": output_dir / f"{prefix}.sig.pub",
        "sig_secret": output_dir / f"{prefix}.sig.key",
    }

    write_public_key_atomic(paths["kem_public"], kem_kp.public_key, overwrite=overwrite)
    write_secret_key_atomic(paths["kem_secret"], kem_kp.secret_key, overwrite=overwrite)
    write_public_key_atomic(paths["sig_public"], sig_kp.public_key, overwrite=overwrite)
    write_secret_key_atomic(paths["sig_secret"], sig_kp.secret_key, overwrite=overwrite)

    # Sanity-check sizes
    assert len(kem_kp.public_key) == ML_KEM_768_PUBLIC_KEY_BYTES
    assert len(kem_kp.secret_key) == ML_KEM_768_SECRET_KEY_BYTES
    assert len(sig_kp.public_key) == ML_DSA_65_PUBLIC_KEY_BYTES
    assert len(sig_kp.secret_key) == ML_DSA_65_SECRET_KEY_BYTES
    return paths


def public_key_fingerprint(public_key: bytes) -> str:
    """Compute a human-readable SHA-256 fingerprint for out-of-band key verification."""
    digest = hashlib.sha256(public_key).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 32, 4))
