# Protocol Specification — `PQEB` Wire Format v1

**Version:** `0x01`  
**Organization:** Corax CoLAB  
**Author:** Pelle Nyberg (`@PelleNybe`)

---

## 1. Cryptographic Primitives

| Role | Algorithm | Standard | Key / Output Sizes |
| :--- | :--- | :--- | :--- |
| Key Encapsulation | `ML-KEM-768` | NIST FIPS 203 | PK: 1,184 B, SK: 2,400 B, CT: 1,088 B, SS: 32 B |
| Digital Signature | `ML-DSA-65` | NIST FIPS 204 | PK: 1,952 B, SK: 4,032 B, Sig: 3,309 B |
| Key Derivation | `HKDF-SHA256` | RFC 5869 | 256-bit (32 B) AES key |
| Authenticated Encryption | `AES-256-GCM` | NIST SP 800-38D | 256-bit key, 96-bit nonce, 128-bit (16 B) tag |

---

## 2. Binary Wire Layout (`0x01`)

All multi-byte integers are unsigned and encoded in **big-endian (network) byte order**.

| Offset | Field | Size (bytes) | Description |
| :--- | :--- | :--- | :--- |
| `0` | `magic` | `4` | ASCII `PQEB` (`0x50 0x51 0x45 0x42`) |
| `4` | `version` | `1` | Protocol version (`0x01`) |
| `5` | `flags` | `1` | `0x00` = Full-KEM per message; `0x01` = Session-Reuse mode |
| `6` | `sender_id_len` | `1` | UTF-8 byte length $N \in [1, 64]$ |
| `7` | `sender_id` | $N$ | UTF-8 sender identifier |
| `7 + N` | `topic_len` | `2` | UTF-8 byte length $M \in [0, 1024]$ |
| `9 + N` | `topic` | $M$ | UTF-8 topic name |
| `9 + N + M` | `timestamp_ns` | `8` | UTC Unix timestamp in nanoseconds (`uint64`) |
| `17 + N + M` | `sequence` | `8` | Monotonic per-sender sequence number (`uint64`) |
| `25 + N + M` | `session_id` | `16` | All-zero in Full-KEM mode; random 16 B UUID in Session mode |
| `41 + N + M` | `kem_ct_len` | `2` | `1088` when KEM ciphertext is present, `0` otherwise |
| `43 + N + M` | `kem_ct` | `kem_ct_len` | `ML-KEM-768` ciphertext |
| ... | `nonce` | `12` | AES-256-GCM 96-bit nonce (**end of AAD**) |
| ... | `ct_len` | `4` | Byte length $L \ge 16$ of ciphertext + GCM tag |
| ... | `ciphertext_and_tag` | $L$ | AES-256-GCM ciphertext followed by 16 B tag (**end of signed region**) |
| ... | `sig_len` | `2` | Byte length of `ML-DSA-65` signature (`3309`) |
| ... | `signature` | `sig_len` | `ML-DSA-65` signature over bytes `[0 .. signed_end)` |

---

## 3. Key Derivation & Nonce Construction

### 3.1 Full-KEM Mode (`flags = 0x00`)
- `shared_secret` = `ML-KEM-768.Decaps(sk, kem_ct)`
- `salt` = `sender_id_utf8 || uint64_be(sequence)`
- `info` = `"pq-edge-bridge-v1-full-kem-aes256gcm"`
- `aes_key` = `HKDF-SHA256(ikm=shared_secret, salt=salt, info=info, len=32)`
- `nonce` = 12 bytes from OS CSPRNG (`os.urandom(12)`)

### 3.2 Session-Reuse Mode (`flags = 0x01`)
1. **Session Establishment / Rotation (`kem_ct_len = 1088`):**
   - `session_root_key` = `HKDF-SHA256(ikm=shared_secret, salt=session_id, info="pq-edge-bridge-v1-session-root", len=32)`
   - Sender rotates `session_id` and `ML-KEM-768` encapsulation when `msg_count >= max_messages` or `elapsed >= max_age_seconds`.
2. **Per-Message Key & Nonce:**
   - `msg_key` = `HKDF-SHA256(ikm=session_root_key, salt=session_id || uint64_be(sequence), info="pq-edge-bridge-v1-session-msg", len=32)`
   - `nonce` = `session_nonce_prefix (4 B random) || uint64_be(sequence)`

---

## 4. Processing Order (Security Invariants)

1. **Parse & Frame-Check:** Reject truncated frames, unknown versions, invalid lengths, or trailing bytes.
2. **Verify-then-Decrypt:** Verify `ML-DSA-65` signature over `[0 .. signed_end)` *before* touching `ML-KEM-768` or `AES-256-GCM`.
3. **Replay & Freshness Check:** Validate `|now_ns - timestamp_ns| <= max_clock_skew_ns` and check `(sender_id, sequence)` against the sliding-window bitmap.
4. **Decrypt & Authenticate AAD:** Decrypt `ciphertext_and_tag` using `AES-256-GCM` with `AAD = [0 .. aad_end)`.
