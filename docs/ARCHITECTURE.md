# System Architecture — `pq-edge-bridge`

**Organization:** Corax CoLAB  
**Author:** Pelle Nyberg (`@PelleNybe`)

---

## 1. Design Philosophy

Edge, IIoT, and autonomous robotics platforms face a unique cryptographic threat: **Harvest Now, Decrypt Later (HNDL)**. Telemetry captured today over cellular, satellite, or untrusted WAN links can be archived by an adversary and decrypted once fault-tolerant quantum computers arrive.

At the same time, edge hardware (e.g., Raspberry Pi 5, NVIDIA Jetson Orin, industrial ARM64 gateways) operates under strict constraints:
- Intermittent WAN connectivity and packet loss.
- Limited CPU and power budgets.
- Legacy local buses (plaintext MQTT, ROS 2 / DDS) that cannot easily be retrofitted with post-quantum TLS.

`pq-edge-bridge` solves this as a **transparent, zero-trust edge sidecar**: it ingests plaintext local telemetry, wraps it in a NIST-standardized Post-Quantum Cryptography (PQC) envelope, persists it in a crash-safe SQLite WAL buffer, and forwards it over untrusted networks with strict FIFO guarantees.

---

## 2. Component Architecture

```text
+-------------------------------------------------------------------------+
|                           Edge Device / Gateway                         |
|                                                                         |
|  +---------------+        +------------------------------------------+  |
|  | Local Sensors |        |            pq-edge-bridge                |  |
|  |  / ROS 2 Bus  |--MQTT->|  1. MqttBridgeTransport / Ros2Transport  |  |
|  +---------------+  /DDS  |  2. TelemetryBridge (asyncio)            |  |
|                           |     +-> SessionManager (ML-KEM-768)      |  |
|                           |     +-> Envelope (AES-256-GCM + ML-DSA)  |  |
|                           |  3. StoreAndForwardBuffer (SQLite WAL)   |  |
|                           +--------------------+---------------------+  |
|                                                |                        |
+------------------------------------------------|------------------------+
                                                 | Untrusted WAN / 5G / Sat
                                                 v
                                    +-------------------------+
                                    | Upstream MQTT Broker /  |
                                    | Cloud PQC Ingestion     |
                                    +-------------------------+
```

### 2.1 Cryptographic Core (`src/pq_edge_bridge/crypto/`)
- **`kem.py`**: Wraps `liboqs` `ML-KEM-768` (NIST FIPS 203) key encapsulation and `HKDF-SHA256` (RFC 5869) key derivation.
- **`signer.py`**: Wraps `liboqs` `ML-DSA-65` (NIST FIPS 204) digital signatures.
- **`session.py`**: Implements `SessionManager` with thread-safe LRU inbound session caching and automatic outbound key rotation on message count (`session_max_messages`) or elapsed time (`session_max_age_seconds`).
- **`envelope.py`**: Implements the binary `PQEB` v1 wire format, `Encrypt-then-Sign` / `Verify-then-Decrypt` ordering, and `ReplayProtector` (timestamp skew + sliding-window sequence bitmap).
- **`keys.py`**: Atomic key generation and serialization enforcing `0o600` POSIX permissions on private keys.

### 2.2 Storage Layer (`src/pq_edge_bridge/storage/buffer.py`)
- **`StoreAndForwardBuffer`**: Backed by `sqlite3` in `WAL` journal mode (`synchronous=NORMAL`, `busy_timeout=5000`).
- Persists every outbound PQC envelope *before* network transmission.
- Enforces configurable `max_bytes` and `max_messages` quotas with `drop_oldest` or `reject_new` overflow policies.
- Executes all SQLite operations off the `asyncio` event loop via `asyncio.to_thread` under a `threading.RLock`.

### 2.3 Transport Layer (`src/pq_edge_bridge/transport/`)
- **`base.py`**: Defines `BaseTransport` and `TransportMessage`.
- **`mqtt_adapter.py`**: Dual-client `paho-mqtt` v2 adapter (`_local_client` + `_upstream_client`) with automatic exponential-backoff reconnect, TLS support, and QoS 1 `PUBACK` confirmation before buffer deletion.
- **`ros2_adapter.py`**: Optional `rclpy` adapter (`std_msgs/msg/UInt8MultiArray`) running `SingleThreadedExecutor` in a dedicated daemon thread and marshalling messages to `asyncio` via `loop.call_soon_threadsafe`.

---

## 3. Concurrency & Ordering Guarantees

1. **Non-Blocking Event Loop:** All network callbacks from `paho-mqtt` and `rclpy` push `TransportMessage` objects into `asyncio.Queue` instances via `call_soon_threadsafe`.
2. **Strict FIFO Store-and-Forward:** `TelemetryBridge._flush_loop` peeks batches in `ORDER BY id ASC`, publishes sequentially, and only calls `ack(acked_ids)` after `wait_for_publish()` confirms delivery. If any publish fails, flushing stops immediately so out-of-order delivery never occurs.
3. **Verify-then-Decrypt:** Inbound commands are signature-verified with `ML-DSA-65` *before* KEM decapsulation or AES-GCM decryption, mitigating unauthenticated CPU/DoS exhaustion.
