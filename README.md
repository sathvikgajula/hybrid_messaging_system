# Sealed — Hybrid E2EE Messenger

Course project for **Practical Aspects of Modern Cryptography**, now a desktop messenger you can run locally or put on a small TLS server for friends.

The relay never sees plaintext, private keys, group member lists, or group size. Identity is your public key; `@username` is a signed handle bound to that key.

## Local demo (two windows on this computer)

```bash
pip install -r requirements.txt
python3 main.py server
```

Then two apps:

```bash
python3 main.py
```

Create accounts (invite can be empty on localhost). Find the other username, chat, attach (2 MB max), or Call.

Keys live in `~/.sealed_messenger/`. Old `alice.json` / `messenger.db` files will not work.

**Friends:** one download per OS from [Releases](https://github.com/sathvikgajula/hybrid_messaging_system/releases) (`Sealed-windows.exe`, `Sealed-macos`, `Sealed-linux`). The URL is already baked in. See [FRIENDS.md](FRIENDS.md). There is no single file that runs on Windows, macOS, and Linux.

## Friends over the internet (your machine)

The relay only answers while **your server is running** and on the internet.

1. DuckDNS name: `saled-max.duckdns.org` (updater: `~/duckdns/duck.sh`, LaunchAgent every 5 minutes).
2. Router: forward **TCP 80, 443** (and **3478** plus **UDP 3478, 49152–49300** if you want calls) to the computer running the relay.
3. Start the relay:

```bash
chmod +x deploy/run-relay.sh
./deploy/run-relay.sh
```

4. TLS in another terminal (install Caddy once with `brew install caddy`):

```bash
sudo caddy run --config deploy/Caddyfile.host --adapter caddyfile
```

5. You chatting as a user (separate from the relay):

```bash
chmod +x deploy/run-host-app.sh
./deploy/run-host-app.sh
```

That forces `http://127.0.0.1:8000` so your home router does not need hairpin NAT. Signup uses the invite in `deploy/.env` (`SEALED_INVITE`) — send that code to friends privately, never commit it.

6. Friends download the GitHub Release for their OS. The HTTPS URL is already inside the file.

If Let’s Encrypt fails, port 80 is not reachable from the internet (CGNAT or no port-forward).

## What is encrypted where

- **Signup:** RSA-2048 identity on the device. A public relay also requires your invite code. The server stores only the signed public bundle.
- **Lookup:** the client verifies the identity signature. Safety numbers are TOFU.
- **Chat / files:** AES-256-GCM, RSA-OAEP wrap of the AES key, encrypt-then-sign. Files are Save-only; copies on disk are encrypted again.
- **Groups:** no groups table. Fan-out is sealed 1:1 envelopes.
- **Voice:** WebRTC DTLS-SRTP. Signaling is sealed like chat. STUN/TURN credentials come from the relay (TURN secret never ships in the app).
- **Keyfiles:** PBKDF2 + AES-GCM. Use 8+ characters.

The WebView is display-only. JavaScript never talks to the relay and never sees private keys as protocol objects.

## Other entry points

```bash
python3 main.py local     # old in-memory CLI
python3 main.py client    # old networked CLI
python3 tests/test_fuzz.py
python3 tests/test_protocol.py
```

## License

MIT. Fine for class use.
