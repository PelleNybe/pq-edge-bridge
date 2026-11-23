# Changelog

All notable changes to `pq-edge-bridge` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-23

### Added
- **Cryptographic Core:**
  - `ML-KEM-768` (NIST FIPS 203) key encapsulation and `HKDF-SHA256` key derivation (`crypto/kem.py`).
  - `ML-DSA-65` (NIST FIPS 204) digital signing and verification (`crypto/signer.py`).
  - Versioned `PQEB` v1 hybrid PQC wire envelope with `AES-256-GCM` AEAD, `Verify-then-Decrypt`, and sliding-window replay protection (`crypto/envelope.py`).
  - Session key caching and automatic rotation by message count or elapsed time (`crypto/session.py`).
  - Atomic keypair generation with strict `chmod 600` private key permissions (`crypto/keys.py`).
- **Transports & Offline Resilience:**
  - SQLite WAL-mode FIFO store-and-forward buffer with atomic dequeue-on-ack and disk quotas (`storage/buffer.py`).
  - Production `paho-mqtt` v2 async bridge adapter (`transport/mqtt_adapter.py`).
  - Optional ROS 2 / DDS bridge adapter via `rclpy` (`transport/ros2_adapter.py`).
- **CLI, Benchmarks & Packaging:**
  - Typer + Rich CLI (`keygen`, `encrypt`, `decrypt`, `verify`, `inspect`, `run`).
  - Real benchmark suite (`benchmarks/run_benchmarks.py`) for latency, throughput, wire overhead, CPU, and RSS memory.
  - Reproducible `liboqs` build script (`deploy/scripts/install_liboqs.sh`), hardened `systemd` unit, multi-arch `Dockerfile` (`linux/amd64`, `linux/arm64`), and GitHub Actions CI workflow.
  - Complete architecture, protocol specification, operator manual, and benchmark documentation.
