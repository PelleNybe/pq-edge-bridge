# Security Policy — `pq-edge-bridge`

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Cryptographic Standards

`pq-edge-bridge` relies exclusively on standardized Post-Quantum Cryptography primitives via Open Quantum Safe (`liboqs`) and OpenSSL (`cryptography`):
- **Key Encapsulation:** `ML-KEM-768` (NIST FIPS 203)
- **Digital Signatures:** `ML-DSA-65` (NIST FIPS 204)
- **Key Derivation:** `HKDF-SHA256` (RFC 5869)
- **Symmetric AEAD:** `AES-256-GCM` (NIST SP 800-38D)

## Reporting a Vulnerability

If you discover a security vulnerability in `pq-edge-bridge`, **please do not open a public GitHub issue**.

Report vulnerabilities privately to:
- **Email:** `security@coraxcolab.com`
- **GitHub Security Advisories:** Use the private vulnerability reporting tab on `https://github.com/PelleNybe/pq-edge-bridge/security/advisories`.

Please include:
1. A clear description of the issue and affected component.
2. Steps to reproduce or a minimal proof-of-concept.
3. Any suggested remediation if known.

We will acknowledge receipt within 48 hours and provide a remediation timeline after triage.
