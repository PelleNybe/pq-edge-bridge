# Benchmarks — `pq-edge-bridge`

**Organization:** Corax CoLAB  
**Author:** Pelle Nyberg (`@PelleNybe`)

---

## 1. Test Environment & Methodology

All benchmarks were executed using `benchmarks/run_benchmarks.py` (`--iterations 200`) backed by compiled `liboqs 0.16.0` (C library) and `cryptography` (OpenSSL AES-256-GCM + HKDF-SHA256) on Linux `x86_64` (Python 3.12.3).

To reproduce on your own `x86_64` or `ARM64` (e.g., Raspberry Pi 5 / NVIDIA Jetson) target:

```bash
python -m benchmarks.run_benchmarks --iterations 200 --json-out benchmarks/results.json
```

---

## 2. Cryptographic Primitive Latency (`x86_64`)

| Operation | p50 (ms) | p95 (ms) | p99 (ms) | Throughput (ops/s) |
| :--- | ---: | ---: | ---: | ---: |
| `ML-KEM-768` KeyGen | 0.0308 | 0.0358 | 0.0410 | 31,619.6 |
| `ML-KEM-768` Encaps | 0.0309 | 0.0356 | 0.0390 | 31,455.1 |
| `ML-KEM-768` Decaps | 0.0320 | 0.0359 | 0.0404 | 30,671.2 |
| `ML-DSA-65` KeyGen | 0.0624 | 0.0678 | 0.0700 | 15,835.3 |
| `ML-DSA-65` Sign | 0.1097 | 0.2912 | 0.4383 | 7,482.9 |
| `ML-DSA-65` Verify | 0.0562 | 0.0610 | 0.0689 | 17,593.2 |

---

## 3. End-to-End Envelope Performance & Wire Overhead

Comparison of **Full Per-Message KEM** vs. **Session-Reuse Mode** (1,000-message rotation threshold, `sender_id="bench-edge-01"`, `topic="telemetry/imu"`):

| Mode | Payload | Wire Size | Overhead | Pack p50 / p99 (ms) | Unpack p50 / p99 (ms) | RSS (MiB) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Full Per-Message KEM | 128 B | 4,628 B | +4,500 B | 0.190 / 0.667 | 0.129 / 0.144 | 36.86 |
| Session-Reuse (1000 msgs) | 128 B | 3,545 B | +3,417 B | 0.153 / 0.351 | 0.093 / 0.110 | 36.87 |
| Full Per-Message KEM | 1,024 B | 5,524 B | +4,500 B | 0.187 / 0.429 | 0.131 / 0.143 | 36.88 |
| Session-Reuse (1000 msgs) | 1,024 B | 4,441 B | +3,417 B | 0.152 / 0.491 | 0.096 / 0.105 | 36.89 |
| Full Per-Message KEM | 16,384 B | 20,884 B | +4,500 B | 0.230 / 0.471 | 0.171 / 0.184 | 36.97 |
| Session-Reuse (1000 msgs) | 16,384 B | 19,801 B | +3,417 B | 0.203 / 0.439 | 0.136 / 0.147 | 36.98 |

### Key Takeaways
- **Sub-millisecond PQC:** End-to-end ML-KEM-768 + AES-256-GCM + ML-DSA-65 encryption & signing completes in **~0.15 ms (p50)** in Session-Reuse mode.
- **Bandwidth Savings:** Session-Reuse eliminates the 1,088-byte `ML-KEM-768` ciphertext on 99.9% of packets, reducing per-message overhead by ~24%.
- **Low Memory Footprint:** ~37 MiB RSS total, comfortably fitting on constrained ARM64 SBCs (Raspberry Pi 5, Jetson Orin Nano, industrial gateways).
