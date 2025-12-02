# Threat Model: Hybrid Messaging System

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

## System Architecture
A hybrid cryptosystem utilizing **AES-128-CBC** for payload encryption and **RSA/ElGamal/Rabin** for key encapsulation mechanism (KEM).

## Threat Analysis

| Threat | Description | Risk | Mitigation |
| :--- | :--- | :--- | :--- |
| **Tampering** | Attacker modifies ciphertext in transit. | High | **Implemented:** Messages are signed (SHA256+RSA). If ciphertext changes, signature verification fails. |
| **Information Disclosure** | AES Key leakage. | Critical | **Implemented:** AES keys are ephemeral and encrypted via Asymmetric schemes (Rabin/RSA) before transmission. |
| **Cryptographic Ambiguity** | Rabin decryption yields 4 roots. | Medium | **Implemented:** Heuristic validation. The system attempts AES decryption with all 4 roots; only the correct root yields valid PKCS7 padding. |
| **Key Management** | Keys stored in volatile memory (`users` dict). | Medium | **Accepted Risk:** Current implementation is a CLI prototype. Production would require Hardware Security Module (HSM) integration. |

## Audit Findings (Self-Assessment)
1.  **Rabin Heuristic:** Relies on AES padding to distinguish roots. Statistically robust, but theoretically allows false positives (1/256 probability per byte).
2.  **ECB/CBC Oracle:** AES-CBC is used. Ensure padding oracle attacks are mitigated in the transport layer.