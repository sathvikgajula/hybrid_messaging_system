# Threat Model

I used STRIDE as a checklist for this course project. This is not a production messenger.

**What it is now:** a windowed messenger (`Sealed`). AES-256-GCM for the message, RSA / Schnorr-group ElGamal / Rabin to wrap the AES key, RSA signatures over ciphertext + recipient + timestamp + nonce. `@username` is bound to the identity public key with a signature. Groups are not stored on the server.

## Threats I thought about

| Threat | What could go wrong | What I did / did not do |
| :--- | :--- | :--- |
| Spoofing | Someone sends a message as you | The server checks the sender's signature on the packet before storing it. Inbox fetch is also signed, so you cannot pull someone else's mailbox without their key. There is still no account recovery / real login. |
| Tampering | Ciphertext gets changed in transit or on the server | Signature is over the ciphertext (encrypt-then-sign). Verification happens **before** decrypt. AES-GCM would also refuse a modified body. |
| Repudiation | Sender denies sending a message | RSA signatures help, but a stolen keyfile+passphrase is still "you". |
| Information disclosure | Server or network observer reads the message | Server never gets the AES key in the clear. Key files on disk are passphrase-encrypted. AES keys are random per message. |
| Denial of service | Flood the inbox / smash the server | Rate limits on register/send/inbox/ICE/XFTP. Per-user inbox cap. Large-file store is quota’d (8 GB/account, 16 GB total) and expires in 48 h. Still a small SQLite box. |
| Elevation of privilege | Read someone else's mail | Inbox is an authenticated POST / WebSocket. Groups have no server-side member list. |
| Membership privacy | Server learns who is in a group | Groups exist only on devices. Fan-out looks like 1:1. A burst of N envelopes can still hint at N recipients (pad later). |
| Open signup | Anyone on the internet creates accounts | Registration is open. Rate-limited per IP. Group membership is invite-only by the creator. |
| Call MITM | Relay swaps SDP and sits on the audio | Signaling is encrypt-then-sign. Media is DTLS-SRTP. STUN/TURN run on your VM; TURN auth is short-lived and issued only after identity auth. TURN is blocked from relaying to RFC1918/loopback. |
| Attachment disclosure | Server reads a file, or a filename path-escapes | Small files sit inside the hybrid ciphertext. Large files are AES-GCM chunks; the relay sees only opaque blobs and capability tokens (in headers, not URLs). Names are stripped to a basename. 32 MB in-chat / 4 GB chunked. Local small-file copies are re-encrypted at rest. |

## Crypto-specific notes

- **Rabin 4 roots:** Each root is tried as an AES-GCM key. The GCM tag is the discriminator now, not PKCS7 padding.
- **ElGamal:** Safe prime `p = 2q+1`, `g` of order `q`, exponents in `1..q-1`. The AES-256 key is one integer modulo `p`.
- **AES-GCM:** Replaces CBC, so there is no padding oracle on the payload.
- **Key sizes:** RSA 2048. ElGamal/Rabin default 512 (the floor that still wraps AES-256). 512-bit DL/factoring is for class, not real-world.
- **Replay:** Envelope nonces are remembered for the auth window so a captured send cannot be replayed. Dummy-traffic padding for group size is still future work.

## Key storage

- Local CLI: keys sit in a Python dict until the process exits.
- Client: private keys and chat history are in an AES-GCM keyfile under `~/.sealed_messenger/`, unlocked with a passphrase.

A real system would use an OS keystore or an HSM. I did not do that here.
