# Hybrid Secure Messaging System

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Test Coverage](https://img.shields.io/badge/coverage-fuzz--tested-blueviolet)
![Encryption](https://img.shields.io/badge/encryption-AES%2B%20RSA%2FElGamal%2FRabin-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

A modular, cryptographic messaging protocol implemented in Python. This system demonstrates a **Hybrid Encryption** architecture, combining the speed of **AES-128 (CBC)** for payloads with **RSA, ElGamal, and Rabin** cryptosystems for secure key encapsulation (KEM).

## Key Engineering Features

- **Hybrid Cryptography Engine:** Implements a layered security model where ephemeral AES keys are encapsulated using user-selectable asymmetric schemes (RSA-2048, ElGamal-256, Rabin-256).
- **Rabin Root Disambiguation:** Engineered a heuristic recovery mechanism to automatically resolve the 4-root ambiguity inherent in Rabin decryption by verifying AES padding structure.
- **Property-Based Fuzz Testing:** Validated cryptographic correctness using **Hypothesis**, proving that encryption/decryption routines hold true for stochastic byte inputs (chaos testing).
- **Automated Benchmarking:** Includes a performance analysis suite proving Rabin encryption is **~195x faster** than RSA for key encapsulation.
- **CI/CD Pipeline:** GitHub Actions workflow automatically triggers regression tests and linting on every push.
- **Containerized Deployment:** Dockerized the CLI application for reproducible, cross-platform execution.

## Architecture

1.  **Key Exchange (KEM):** The sender generates a random 16-byte AES key. This key is encrypted using the recipient's Public Key (RSA, ElGamal, or Rabin).
2.  **Payload Encryption (DEM):** The actual message is encrypted using the AES key in CBC mode.
3.  **Signing:** The sender hashes the plaintext (SHA-256) and signs it with their RSA Private Key.
4.  **Verification:** The receiver decrypts the AES key (handling math primitives), decrypts the payload, and verifies the signature.

## Prerequisites

- Python 3.9+
- PyCryptodome
- Hypothesis (for testing)

## Quick Start

### 1. Installation
```bash
pip install pycryptodome hypothesis
````

### 2\. Run the CLI

```bash
python3 main.py
```

### 3\. Run with Docker

Ensure reproducibility by running in a container:

```bash
docker build -t hybrid-msg .
docker run -it hybrid-msg
```

## Verification & Benchmarks

### Fuzz Testing (Hypothesis)

We utilize property-based testing to verify mathematical correctness against edge cases (e.g., zero-byte inputs, max-int keys).

```bash
python3 tests/test_fuzz.py
```

### Performance Benchmarking

Compare the latency of asymmetric primitives (100 iterations):

```bash
python3 benchmark.py
```

**Actual Performance Results (Apple Silicon M1):**
The Rabin cryptosystem ($m^2 \mod n$) significantly outperforms RSA and ElGamal for encryption operations due to lower computational complexity.

| Algorithm | Key Size | Time (100 runs) | Relative Speed |
| :--- | :--- | :--- | :--- |
| **Rabin** | 256-bit | **0.045s** | **1x (Fastest)** |
| **ElGamal** | 256-bit | 0.840s | \~18x Slower |
| **RSA** | 2048-bit | 8.795s | \~195x Slower |

## Threat Model

A STRIDE threat analysis was performed.

  - **Mitigated:** Spoofing (via Signatures), Information Disclosure (via Hybrid Encryption).
  - **Accepted Risk:** Keys are currently stored in-memory for the CLI prototype. Production requires HSM integration.
  - See [THREAT\_MODEL.md](https://www.google.com/search?q=./THREAT_MODEL.md) for full details.

## License

MIT License. Free for academic use.
