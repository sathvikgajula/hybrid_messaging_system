==============================
HYBRID MESSAGING SYSTEM (CLI)
==============================

Author: Sathvik Gajula
Course: Prac Aspects Of Modern Cryptography
Project: Hybrid Messaging System
Language: Python 
Dependencies: pycryptodome

-----------------------------------
 PROJECT DESCRIPTION
-----------------------------------
This project implements a secure messaging system that combines:
- Symmetric encryption (AES in CBC mode)
- Asymmetric encryption (RSA, ElGamal, and Rabin)
- Digital signatures for authenticity
- CLI-based user interaction

-----------------------------------
 CRYPTOGRAPHIC FEATURES
-----------------------------------
1. AES (Advanced Encryption Standard):
   - Used in CBC mode
   - Requires a 16-character (128-bit) user-provided key

2. RSA:
   - Key size: 2048 bits
   - Used for AES key encryption and digital signatures

3. ElGamal:
   - Based on discrete logarithms
   - Used for AES key encryption
   - Key size: 256-bit prime

4. Rabin:
   - Based on integer factorization
   - AES key is encrypted using m² mod n
   - Requires special handling to recover one of four possible roots

5. SHA-256 + Digital Signature (RSA):
   - Original message is hashed and signed
   - Receiver verifies the signature to ensure authenticity

-----------------------------------
 FILE STRUCTURE
-----------------------------------
- main.py               → CLI entry point
- user_operations.py    → User actions: register, send, view
- aes_utils.py          → AES encryption/decryption
- rsa_utils.py          → RSA keygen, encrypt/decrypt, sign/verify
- elgamal_utils.py      → ElGamal keygen and encryption
- rabin_utils.py        → Rabin keygen and encryption

-----------------------------------
 HOW TO RUN
-----------------------------------
1. Install dependencies:
   pip install pycryptodome

2. Run the system:
   python3 main.py

-----------------------------------
 CLI OPTIONS
-----------------------------------
1. Register User
   - Generates RSA, ElGamal, Rabin keys

2. Send Message
   - Input recipient
   - Choose asymmetric scheme (RSA, ElGamal, Rabin)
   - Enter 16-character AES key
   - Enter message
   - Message is encrypted + signed

3. View Message
   - View all received messages
   - Automatically decrypts and verifies signature

4. Exit
   - Safely exits the program

-----------------------------------
 CHALLENGES ENCOUNTERED
-----------------------------------
- Enforcing exact 16-byte AES key length
- RSA minimum size constraint (1024 bits)
- Rabin decryption returns 4 possible roots
- Managing multiple encryption schemes
- Securely integrating digital signature verification
- Scheme identification during decryption
- Key storage vs. runtime key management

-----------------------------------
 FUTURE ENHANCEMENTS
-----------------------------------
- Store/load private keys from disk
- GUI version of the messaging interface
- Add message export/import functionality
- Blockchain-based message logging

-----------------------------------
 LICENSE
-----------------------------------
For educational use only. Not intended for production deployment.

