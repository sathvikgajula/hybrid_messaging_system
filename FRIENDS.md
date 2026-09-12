# Sealed — for friends

There is **one download per operating system**, not one file for Windows+Mac+Linux. Grab the build for your computer from [Releases](https://github.com/sathvikgajula/hybrid_messaging_system/releases).

| Your computer | File |
| :--- | :--- |
| Windows 10/11 | `Sealed-windows.exe` |
| macOS 12+ (Intel, or Apple Silicon with Rosetta) | `Sealed-macos` |
| Linux (Ubuntu 22.04+ / Debian with glibc 2.35+) | `Sealed-linux` |

The app already talks to `https://saled-max.duckdns.org`. You need internet, and the host must have the relay running.

## Run

**Windows:** double-click the `.exe`. If SmartScreen warns, More info → Run anyway.

**macOS:** in Terminal, from the folder with the file:

```bash
chmod +x Sealed-macos
xattr -dr com.apple.quarantine Sealed-macos
./Sealed-macos
```

Or right-click → Open (needed once because it is unsigned).

**Linux:**

```bash
chmod +x Sealed-linux
sudo apt install -y gir1.2-webkit2-4.1 python3-gi
./Sealed-linux
```

## Account

Create account with the **invite code** the host sent you (not in this repo). Username like `alice`. Passphrase 8+ characters. Then find their `@username` and chat.

Do not post the invite code or your keyfile (`~/.sealed_messenger/`) anywhere public.
