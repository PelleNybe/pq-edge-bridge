# `pq-edge-bridge` — Architecture & Implementation Plan

**Organization:** Corax CoLAB  
**Author / Lead Architect:** Pelle Nyberg (`@PelleNybe`)  
**License:** Apache-2.0  
**Target Python:** 3.11+ (`asyncio`, strict `mypy` typing)

---

## 1. Executive Summary

`pq-edge-bridge` is a lightweight, production-grade Post-Quantum Cryptography (PQC) telemetry bridge for Edge, IIoT, and Robotics systems. It protects telemetry and command-and-control (C2) channels against *"Harvest Now, Decrypt Later"* (HNDL) adversaries by wrapping plaintext local bus traffic (MQTT, ROS 2 / DDS) in authenticated, forward-secret hybrid PQC envelopes using NIST-standardized algorithms:

- **Key Encapsulation:** ML-KEM-768 (NIST FIPS 203) via `liboqs` (`liboqs-python`)
- **Digital Signatures:** ML-DSA-65 (NIST FIPS 204) via `liboqs` (`liboqs-python`)
- **Key Derivation:** HKDF-SHA256 (RFC 5869)
- **Symmetric AEAD:** AES-256-GCM (NIST SP 800-38D) via `cryptography`

---

## 2. Cryptographic Protocol Specification

### 2.1 Algorithm Suite

| Primitive | Standard | Parameters | Wire Size |
| :--- | :--- | :--- | :--- |
| KEM | NIST FIPS 203 (`ML-KEM-768`) | Security Category 3 (192-bit) | Public Key: 1,184 B / Ciphertext: 1,088 B / Shared Secret: 32 B |
| Signature | NIST FIPS 204 (`ML-DSA-65`) | Security Category 3 (192-bit) | Public Key: 1,952 B / Signature: 3,309 B |
| KDF | RFC 5869 (`HKDF-SHA256`) | Salt: `session_id \|\| seq_be64`, Info: domain-separated | Output: 32 B (256-bit AES key) |
| AEAD | NIST SP 800-38D (`AES-256-GCM`) | 256-bit key, 96-bit nonce, 128-bit tag | Tag: 16 B |

### 2.2 Envelope Wire Format (Version `0x01`)

All multi-byte integers are encoded in **big-endian (network) byte order**.

```text
+--------+---------+-------+---------------+-----------+-----------+-----------+
| Magic  | Version | Flags | SenderID Len  | SenderID  | Topic Len | Topic     |
| 4 B    | 1 B     | 1 B   | 1 B (1..64)   | N B       | 2 B       | M B       |
+--------+---------+-------+---------------+-----------+-----------+-----------+
| Timestamp (ns) | Sequence | Session ID | KEM CT Len | KEM Ciphertext (opt)  |
| 8 B (uint64)   | 8 B      | 16 B       | 2 B        | 0 or 1,088 B          |
+----------------+----------+------------+------------+-----------------------+
| Nonce (GCM) | Ciphertext Len | Ciphertext + 16 B GCM Tag | Sig Len | ML-DSA-65 Sig |
| 12 B        | 4 B (uint32)   | L B                       | 2 B     | 3,309 B       |
+-------------+----------------+---------------------------+---------+---------------+
```

- **Magic:** `0x50 0x51 0x45 0x42` (`b"PQEB"`).
- **Version:** `0x01`.
- **Flags:**
  - `0x00` (`MODE_FULL_KEM`): Every envelope carries a fresh ML-KEM-768 encapsulation (`kem_ct_len = 1088`, `session_id = 0x00 * 16`).
  - `0x01` (`MODE_SESSION`): Session-reuse mode. The first message of a session (and each rotation boundary) carries `kem_ct_len = 1088` and a fresh 16-byte `session_id`. Subsequent messages in the same session carry `kem_ct_len = 0` and the active `session_id`.
- **Associated Authenticated Data (AAD):** All header bytes from `Magic` through `Nonce` inclusive.
- **Signature Coverage (Encrypt-then-Sign):** ML-DSA-65 signs the complete byte slice from `Magic` through `Ciphertext + GCM Tag` inclusive. Receivers **must** verify the ML-DSA-65 signature **before** performing KEM decapsulation or AES-GCM decryption (Verify-then-Decrypt).

### 2.3 Key Derivation (HKDF-SHA256)

1. **Per-Message Full KEM Mode (`flags == 0x00`):**
   - `ikm = ml_kem_shared_secret` (32 B)
   - `salt = sender_id_bytes + seq_be64`
   - `info = b"pq-edge-bridge-v1-full-kem-aes256gcm"`
   - `aes_key = HKDF-SHA256(ikm, salt, info, length=32)`
   - `nonce = os.urandom(12)`

2. **Session Reuse Mode (`flags == 0x01`):**
   - On session establishment: `session_root_key = HKDF-SHA256(ikm=ml_kem_shared_secret, salt=session_id, info=b"pq-edge-bridge-v1-session-root", length=32)`.
   - Per message: `msg_key = HKDF-SHA256(ikm=session_root_key, salt=session_id + seq_be64, info=b"pq-edge-bridge-v1-session-msg", length=32)`.
   - `nonce = session_nonce_prefix (4 B random) + seq_be64 (8 B)`, guaranteeing strict nonce uniqueness across up to $2^{64}$ messages per session.

### 2.4 Session Key Rotation State Machine

```text
[UNINITIALIZED] --(first message)--> [ACTIVE (seq=0, created_at=t0)]
      ^                                      |
      |                          (msg_count >= max_messages
      |                           OR now - created_at >= max_age_sec)
      |                                      v
      +----------(rotate: zeroize old key, new session_id + new ML-KEM-768)---+
```

- Configurable thresholds: `max_messages` (default `1000`), `max_age_seconds` (default `600.0`).
- Receiver caches up to `max_cached_sessions` (LRU) keyed by `(sender_id, session_id)` with expiration TTL so out-of-order packets near a rotation boundary still decrypt cleanly.

### 2.5 Replay & Freshness Protection

- **Timestamp Window:** Reject envelopes whose `timestamp_ns` deviates from local UTC wall-clock by more than `max_clock_skew_seconds` (default `300` s).
- **Sliding-Window Sequence Check:** Per `sender_id`, maintain `(highest_seq, window_bitmap)` (64-bit or 1024-bit sliding window). Reject duplicates (`seq` already seen) and packets older than `highest_seq - window_size`.

---

## 3. Concurrency Architecture

- **Primary Runtime:** Single `asyncio` event loop in the bridge daemon.
- **MQTT (`paho-mqtt` v2):** Uses `paho-mqtt`'s threaded network loop (`loop_start()`) bridged safely into `asyncio` via `loop.call_soon_threadsafe(inbound_queue.put_nowait, msg)`. Outbound publishes run in an executor or non-blocking client call with publish-ack tracking (`wait_for_publish` / `on_publish` Future).
- **ROS 2 (`rclpy`):** Optional extra (`[ros2]`). Spins `rclpy.executors.SingleThreadedExecutor` in a dedicated daemon thread, marshalling incoming ROS 2 messages into the `asyncio` queue via `call_soon_threadsafe` and dispatching decrypted inbound commands back to ROS 2 publishers.
- **SQLite WAL Store-and-Forward (`storage/buffer.py`):**
  - Uses `sqlite3` with `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;`.
  - Protected by an internal `threading.RLock` and executed off the `asyncio` event loop via `asyncio.to_thread(...)` so disk I/O never stalls heartbeats or network callbacks.

---

## 4. Failure Modes, Recovery Guarantees & Threat Model

- **Offline / Broker Disconnect:** Inbound local telemetry is persisted to the SQLite WAL FIFO buffer *before* upstream publish is attempted (or immediately on publish failure), ensuring **zero message loss** across disconnects, process restarts, or power loss.
- **Atomic Dequeue-on-Ack:** Rows are only deleted from SQLite (`DELETE FROM outbound_buffer WHERE id = ?`) after the upstream transport confirms delivery (`on_publish` / QoS 1 PUBACK).
- **Disk Quota Enforcement:** Configurable `max_bytes` and `max_messages` caps; when exceeded, configurable overflow policy (`drop_oldest` or `reject_new`) prevents edge SD-card exhaustion.
- **Threat Model:**
  - *Harvest Now, Decrypt Later (HNDL):* Mitigated by ML-KEM-768 key encapsulation.
  - *Spoofing / Tampering / MitM:* Mitigated by ML-DSA-65 signatures over full frame + AES-256-GCM AEAD.
  - *Replay / Reordering:* Mitigated by timestamp freshness + per-sender sliding-window sequence tracker.
  - *Private Key Compromise on Disk:* Private keys are written atomically (`O_WRONLY | O_CREAT | O_EXCL`, `0o600`), with systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges=yes`).

---

## 5. Milestone Breakdown & Verification Plan

### Phase 1 — Cryptographic Core (MVP)
- **Deliverables:** `pyproject.toml`, `LICENSE` (Apache-2.0), `deploy/scripts/install_liboqs.sh`, `src/pq_edge_bridge/config.py`, `crypto/kem.py`, `crypto/signer.py`, `crypto/envelope.py`, `cli.py` (`keygen`, `encrypt`, `decrypt`, `verify`, `inspect`).
- **Acceptance Criteria:**
  - `liboqs` + `liboqs-python` compiled and importable.
  - `keygen` creates private keys atomically with `0o600` permissions.
  - Round-trip encrypt/sign/verify/decrypt passes; tampering any byte, wrong key, or replayed sequence raises explicit typed exceptions.
- **Verification:** `pytest tests/test_crypto_*.py`, `ruff check`, `mypy src`.

### Phase 2 — Transport & Offline Buffer
- **Deliverables:** `storage/buffer.py` (SQLite WAL FIFO), `transport/base.py`, `transport/mqtt_adapter.py`, `cli.py run` daemon loop.
- **Acceptance Criteria:**
  - Strict FIFO ordering, atomic dequeue-on-ack, disk quota enforcement, persistence across buffer close/reopen.
  - MQTT adapter bridges local plaintext topics to upstream PQC topics and unwraps inbound PQC control commands.
  - Disconnect/reconnect integration tests prove zero message loss and strict ordering.
- **Verification:** `pytest tests/test_buffer.py tests/test_mqtt_bridge.py`.

### Phase 3 — Edge Optimization & ROS 2
- **Deliverables:** `crypto/session.py` (session caching & time/count rotation), `transport/ros2_adapter.py` (optional `rclpy` bridge), `benchmarks/` suite.
- **Acceptance Criteria:**
  - Session key rotation triggers deterministically on `max_messages` and `max_age_seconds`.
  - `ros2_adapter.py` imports cleanly when `rclpy` is absent and bridges real topics when ROS 2 is present.
  - Real benchmarks measure p50/p95/p99 latency, CPU, RSS memory, and wire overhead for both Full-KEM and Session-Reuse modes.
- **Verification:** `pytest tests/test_session.py tests/test_ros2_adapter.py`, `python -m benchmarks.run_benchmarks`.

### Phase 4 — Release, Packaging & Documentation
- **Deliverables:** `deploy/systemd/pq-edge-bridge.service`, `deploy/docker/Dockerfile`, `.github/workflows/ci.yml`, `docs/{ARCHITECTURE,PROTOCOL_SPEC,OPERATOR_MANUAL,BENCHMARKS}.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, marketing-grade `README.md`.
- **Acceptance Criteria:**
  - Full `ruff`, `mypy`, and `pytest` suite passes 100%.
  - Docker build / systemd unit / CI workflow validated.
- **Verification:** `ruff check . && mypy src tests && pytest -v`.
