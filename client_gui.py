"""Desktop messenger client. Crypto stays in this process; the WebView is display-only."""
import base64
import json
import os
import queue
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin

import requests
from websocket import WebSocketApp

import keyfile
import netconfig
import protocol
from aes_utils import aes_decrypt_bytes, aes_encrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

SERVER, WS_URL = netconfig.load_relay_urls()
DATA_DIR = os.path.join(os.path.expanduser("~"), ".sealed_messenger")
MAX_SEEN = 400
CALL_OFFER_SECONDS = 90
_BLOB_ID_RE = re.compile(r"^[0-9a-f]{64}$")
FRIEND_SCHEME = "rsa"
MAX_CHAT_MESSAGES = 400


def _guess_mime(name, data, mime=""):
    mime = (mime or "").strip()
    if mime.startswith("image/") or (mime and mime != "application/octet-stream"):
        return protocol.sanitize_mime(mime)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image/webp"
    lower = str(name or "").lower()
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    if lower.endswith(".gif"):
        return "image/gif"
    if lower.endswith(".webp"):
        return "image/webp"
    return protocol.sanitize_mime(mime)


def _http_error(resp):
    try:
        detail = resp.json().get("detail")
        if isinstance(detail, str) and detail:
            return detail
    except Exception:
        pass
    text = (resp.text or "").strip()
    return text[:300] if text else f"HTTP {resp.status_code}"


def _sanitize_ice_servers(servers):
    if not isinstance(servers, list):
        return []
    out = []
    for item in servers[:8]:
        if not isinstance(item, dict):
            continue
        urls = item.get("urls")
        if isinstance(urls, list):
            urls = urls[0] if urls else ""
        if not isinstance(urls, str) or len(urls) > 200:
            continue
        lower = urls.lower()
        if not (lower.startswith("stun:") or lower.startswith("turn:") or lower.startswith("turns:")):
            continue
        if any(bad in lower for bad in ("javascript:", "data:", "http:", "https:", "file:")):
            continue
        entry = {"urls": urls}
        user = item.get("username")
        cred = item.get("credential")
        if isinstance(user, str) and isinstance(cred, str) and user and cred:
            if len(user) <= 128 and len(cred) <= 256:
                entry["username"] = user
                entry["credential"] = cred
        out.append(entry)
    return out


def _key_path(username):
    os.makedirs(DATA_DIR, exist_ok=True)
    safe = protocol.normalize_username(username)
    return os.path.join(DATA_DIR, f"{safe}.key.json")


def _empty_state():
    return {"tofu": {}, "chats": {}, "seen": []}


def _size_label(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB".strip()
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB".strip()
    return f"{n / (1024 * 1024 * 1024):.1f} GB".strip()


def _serve_ui():
    ui_dir = netconfig.resource_dir("ui")
    allowed = {"/", "/index.html", "/app.js", "/app.css"}

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=ui_dir, **kwargs)

        def log_message(self, *_args):
            return

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path not in allowed:
                self.send_error(404)
                return
            super().do_GET()

        def do_POST(self):
            self.send_error(405)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    return f"http://127.0.0.1:{port}/index.html", httpd


class Messenger:
    def __init__(self):
        self.username = None
        self.keys = None
        self.passphrase = None
        self.state = _empty_state()
        self.events = queue.Queue()
        self.ws = None
        self.ws_thread = None
        self.lock = threading.RLock()
        self.active_chat = None
        self.online = False
        self.call = None
        self.ice_servers = []
        self._job = {"status": "idle"}
        self._xftp_tx = None

    def _emit(self, event):
        self.events.put(event)

    def _persist(self):
        if not (self.username and self.keys and self.passphrase):
            return
        keyfile.save_keyfile(_key_path(self.username), self.username, self.keys, self.passphrase, self.state)

    def _mark_seen(self, nonce):
        if not nonce:
            return False
        seen = self.state.setdefault("seen", [])
        if nonce in seen:
            return True
        seen.append(nonce)
        if len(seen) > MAX_SEEN:
            self.state["seen"] = seen[-MAX_SEEN:]
        return False

    def _blob_dir(self):
        path = os.path.join(DATA_DIR, f"{self.username}.blobs")
        os.makedirs(path, exist_ok=True)
        return path

    def _blob_key(self):
        key_hex = self.state.get("blob_key")
        if not (isinstance(key_hex, str) and len(key_hex) == 64):
            key_hex = None
        else:
            try:
                return bytes.fromhex(key_hex)
            except ValueError:
                key_hex = None
        key_hex = get_random_bytes(32).hex()
        self.state["blob_key"] = key_hex
        self._persist()
        return bytes.fromhex(key_hex)

    def _blob_path(self, digest):
        if not isinstance(digest, str) or not _BLOB_ID_RE.fullmatch(digest):
            raise ValueError("Invalid attachment id")
        return os.path.join(self._blob_dir(), digest)

    def _store_blob(self, digest, data):
        path = self._blob_path(digest)
        if os.path.exists(path):
            return
        sealed = aes_encrypt(data, self._blob_key())
        with open(path, "w") as f:
            f.write(sealed)

    def _load_blob(self, digest):
        try:
            path = self._blob_path(digest)
        except ValueError:
            return None
        if not os.path.exists(path):
            return None
        with open(path) as f:
            sealed = f.read()
        return aes_decrypt_bytes(sealed, self._blob_key())

    def _ensure_dm(self, username, fingerprint):
        cid = f"dm:{username}"
        chats = self.state.setdefault("chats", {})
        if cid not in chats:
            chats[cid] = {
                "type": "dm",
                "title": username,
                "members": [self.username, username],
                "fingerprint": fingerprint,
                "messages": [],
                "updated": time.time(),
            }
        return cid

    def snapshot(self):
        with self.lock:
            if not self.username:
                return {"authed": False}
            chats = []
            for cid, chat in self.state.get("chats", {}).items():
                last = ""
                if chat["messages"]:
                    last_msg = chat["messages"][-1]
                    if last_msg.get("file"):
                        last = "📎 " + last_msg["file"]["name"]
                    elif last_msg.get("xftp"):
                        last = "📦 " + last_msg["xftp"]["name"]
                    else:
                        last = last_msg.get("text") or ""
                chats.append({
                    "id": cid,
                    "type": chat["type"],
                    "title": chat["title"],
                    "preview": last[:80],
                    "members": chat.get("members", []),
                    "fingerprint": chat.get("fingerprint"),
                    "updated": chat.get("updated", 0),
                })
            chats.sort(key=lambda c: c["updated"], reverse=True)
            active = None
            if self.active_chat and self.active_chat in self.state["chats"]:
                ch = self.state["chats"][self.active_chat]
                messages = []
                for msg in ch["messages"][-200:]:
                    item = dict(msg)
                    if item.get("xftp"):
                        xf = dict(item["xftp"])
                        xf.pop("key", None)
                        xf.pop("get_secret", None)
                        item["xftp"] = xf
                    messages.append(item)
                active = {
                    "id": self.active_chat,
                    "type": ch["type"],
                    "title": ch["title"],
                    "members": ch.get("members", []),
                    "fingerprint": ch.get("fingerprint"),
                    "messages": messages,
                    "can_call": ch["type"] == "dm",
                    "can_invite": ch["type"] == "group" and ch.get("creator") == self.username,
                }
            return {
                "authed": True,
                "username": self.username,
                "fingerprint": protocol.public_fingerprint(protocol.public_keys_from(self.keys)),
                "online": self.online,
                "chats": chats,
                "active": active,
                "call": self.call,
                "max_file_bytes": protocol.MAX_FILE_BYTES,
                "max_xftp_bytes": protocol.MAX_XFTP_BYTES,
                "xftp_slice": protocol.XFTP_PUSH_SLICE,
                "ice_servers": list(self.ice_servers),
                "scheme": FRIEND_SCHEME,
            }

    def poll(self):
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                break
        return out

    def job_status(self):
        return dict(self._job)

    def signup(self, username, passphrase, confirm, invite=""):
        if self._job.get("status") == "running":
            return {"ok": False, "error": "Already creating an account"}
        if passphrase != confirm:
            return {"ok": False, "error": "Passphrases do not match"}
        if not passphrase or len(passphrase) < 8:
            return {"ok": False, "error": "Use a passphrase of at least 8 characters"}
        try:
            username = protocol.normalize_username(username)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        if os.path.exists(_key_path(username)):
            return {"ok": False, "error": "A keyfile for that username already exists on this device. Log in instead."}

        self._job = {"status": "running", "message": "Generating keys…"}

        def work():
            try:
                self._job["message"] = "Generating RSA-2048 identity keys…"
                keys = protocol.generate_user_keys(rsa_only=True)
                self._job["message"] = "Registering with the relay…"
                pubs, sig = protocol.sign_identity_bundle(username, keys)
                resp = requests.post(
                    urljoin(SERVER, "/register"),
                    json={
                        "username": username,
                        "public_keys": pubs,
                        "identity_sig": sig,
                    },
                    timeout=30,
                )
                if resp.status_code != 200:
                    self._job = {"status": "error", "error": _http_error(resp)}
                    self._emit({"type": "error", "error": _http_error(resp)})
                    return
                with self.lock:
                    self.username = username
                    self.keys = keys
                    self.passphrase = passphrase
                    self.state = _empty_state()
                    self._persist()
                self._job["message"] = "Connecting…"
                err = self._connect_ws()
                if err:
                    self._job = {"status": "error", "error": err}
                    self._emit({"type": "error", "error": err})
                    return
                self._refresh_ice()
                result = {"ok": True, "username": username, "fingerprint": resp.json().get("fingerprint")}
                self._job = {"status": "done", "result": result}
                self._emit({"type": "ready"})
            except requests.RequestException as e:
                self._job = {"status": "error", "error": f"Relay offline ({e})"}
                self._emit({"type": "error", "error": str(e)})
            except Exception as e:
                self._job = {"status": "error", "error": str(e)}
                self._emit({"type": "error", "error": str(e)})

        threading.Thread(target=work, daemon=True).start()
        return {"ok": True, "pending": True}

    def login(self, username, passphrase):
        try:
            username = protocol.normalize_username(username)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        path = _key_path(username)
        if not os.path.exists(path):
            return {"ok": False, "error": "No keyfile for that username on this device"}
        try:
            stored_user, keys, _, state = keyfile.load_keyfile(path, passphrase, require_encrypted=True)
        except Exception:
            return {"ok": False, "error": "Could not unlock keyfile (wrong passphrase or corrupt file)"}
        if protocol.normalize_username(stored_user) != username:
            return {"ok": False, "error": "Keyfile username mismatch"}
        with self.lock:
            self.username = username
            self.keys = keys
            self.passphrase = passphrase
            self.state = state or _empty_state()
            self.state.setdefault("tofu", {})
            self.state.setdefault("chats", {})
            self.state.setdefault("seen", [])
            self.call = None
        err = self._connect_ws()
        if err:
            return {"ok": False, "error": err}
        self._refresh_ice()
        self._emit({"type": "ready"})
        return {"ok": True, "username": username}

    def _refresh_ice(self):
        if not (self.username and self.keys):
            self.ice_servers = []
            return
        try:
            auth = protocol.inbox_auth_payload(self.username, self.keys["rsa"]["priv"])
            resp = requests.post(urljoin(SERVER, "/ice"), json=auth, timeout=15)
            if resp.status_code != 200:
                self.ice_servers = []
                return
            servers = resp.json().get("iceServers")
            self.ice_servers = _sanitize_ice_servers(servers)
        except Exception:
            self.ice_servers = []

    def _connect_ws(self):
        auth = protocol.inbox_auth_payload(self.username, self.keys["rsa"]["priv"])
        auth["type"] = "auth"
        opened = threading.Event()
        fail = []

        def on_open(ws):
            ws.send(json.dumps(auth))

        def on_message(ws, message):
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                return
            self._on_ws(data, opened, fail)

        def on_error(ws, error):
            fail.append(str(error))
            opened.set()

        def on_close(ws, status, msg):
            self.online = False
            self._emit({"type": "offline"})
            opened.set()

        self.ws = WebSocketApp(WS_URL, on_open=on_open, on_message=on_message, on_error=on_error, on_close=on_close)
        sslopt = {"cert_reqs": ssl.CERT_REQUIRED} if WS_URL.startswith("wss://") else None
        self.ws_thread = threading.Thread(
            target=lambda: self.ws.run_forever(sslopt=sslopt),
            daemon=True,
        )
        self.ws_thread.start()
        if not opened.wait(timeout=8) and not self.online:
            # on_message sets online; wait a bit more for auth ok
            deadline = time.time() + 8
            while time.time() < deadline and not self.online and not fail:
                time.sleep(0.05)
        if fail and not self.online:
            return fail[0]
        if not self.online:
            return "Could not authenticate to the relay. Is the server running?"
        return None

    def _on_ws(self, data, opened, fail):
        typ = data.get("type")
        if typ == "ok":
            self.online = True
            opened.set()
            return
        if typ == "queued":
            for item in data.get("messages") or []:
                self._ingest(item.get("from"), item.get("payload"), persist=False)
            self._persist()
            self._emit({"type": "inbox"})
            return
        if typ == "msg":
            self._ingest(data.get("from"), data.get("payload"), persist=True)
            self._emit({"type": "inbox"})
            return
        if typ == "error":
            self._emit({"type": "error", "error": data.get("detail")})

    def lookup(self, username, trust_if_new=True):
        try:
            username = protocol.normalize_username(username)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        if username == self.username:
            return {"ok": False, "error": "That is you"}
        try:
            resp = requests.get(urljoin(SERVER, f"/keys/{username}"), timeout=15)
        except requests.RequestException as e:
            return {"ok": False, "error": f"Relay offline ({e})"}
        if resp.status_code != 200:
            return {"ok": False, "error": "No user with that username"}
        bundle = resp.json()
        pubs = bundle.get("public_keys")
        sig = bundle.get("identity_sig")
        if not protocol.verify_identity_bundle(username, pubs, sig):
            return {"ok": False, "error": "Identity signature failed — refusing this key bundle"}
        fp = protocol.public_fingerprint(pubs)
        known = self.state.get("tofu", {}).get(username)
        if known and known != fp:
            return {
                "ok": False,
                "error": "Safety number changed. This can mean a new device — or an attack. Confirm in person before trusting.",
                "code": "tofu",
                "fingerprint": fp,
                "previous": known,
                "username": username,
            }
        if trust_if_new or known == fp:
            self.state.setdefault("tofu", {})[username] = fp
            self._persist()
        return {"ok": True, "username": username, "public_keys": pubs, "fingerprint": fp}

    def confirm_key(self, username):
        result = self.lookup(username, trust_if_new=False)
        if result.get("code") != "tofu":
            return result
        try:
            username = protocol.normalize_username(username)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        resp = requests.get(urljoin(SERVER, f"/keys/{username}"), timeout=15)
        bundle = resp.json()
        if not protocol.verify_identity_bundle(username, bundle["public_keys"], bundle["identity_sig"]):
            return {"ok": False, "error": "Identity signature failed"}
        fp = protocol.public_fingerprint(bundle["public_keys"])
        self.state.setdefault("tofu", {})[username] = fp
        self._persist()
        return {"ok": True, "username": username, "fingerprint": fp}

    def start_dm(self, username):
        looked = self.lookup(username)
        if not looked.get("ok"):
            return looked
        cid = f"dm:{looked['username']}"
        with self.lock:
            self.state.setdefault("chats", {}).setdefault(cid, {
                "type": "dm",
                "title": looked["username"],
                "members": [self.username, looked["username"]],
                "fingerprint": looked["fingerprint"],
                "messages": [],
                "updated": time.time(),
            })
            self.state["chats"][cid]["fingerprint"] = looked["fingerprint"]
            self.active_chat = cid
            self._persist()
        self._emit({"type": "ready"})
        return {"ok": True, "id": cid}

    def open_chat(self, chat_id):
        if chat_id not in self.state.get("chats", {}):
            return {"ok": False, "error": "No such conversation"}
        self.active_chat = chat_id
        self._emit({"type": "ready"})
        return {"ok": True}

    def _send_envelope(self, to_user, plaintext, scheme):
        looked = self.lookup(to_user)
        if not looked.get("ok"):
            return looked
        payload = protocol.hybrid_encrypt(
            plaintext, self.keys, looked["public_keys"], scheme, self.username, looked["username"]
        )
        if self.ws and self.online:
            try:
                self.ws.send(json.dumps({"type": "send", "to": looked["username"], "payload": payload}))
                return {"ok": True, "nonce": payload["nonce"]}
            except Exception:
                pass
        try:
            resp = requests.post(
                urljoin(SERVER, "/send"),
                json={"sender": self.username, "recipient": looked["username"], "payload": payload},
                timeout=180,
            )
        except requests.RequestException as e:
            return {"ok": False, "error": str(e)}
        if resp.status_code != 200:
            return {"ok": False, "error": _http_error(resp)}
        return {"ok": True, "nonce": payload["nonce"]}

    def send(self, text, scheme="rsa"):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        scheme = FRIEND_SCHEME
        text = (text or "").strip()
        if not text:
            return {"ok": False, "error": "Message cannot be empty"}
        chat_id = self.active_chat
        if not chat_id or chat_id not in self.state["chats"]:
            return {"ok": False, "error": "Pick a conversation first"}
        chat = self.state["chats"][chat_id]
        if chat["type"] == "dm":
            other = [m for m in chat["members"] if m != self.username][0]
            packed = protocol.pack_direct(text)
            result = self._send_envelope(other, packed, scheme)
            if not result.get("ok"):
                return result
            self._append_local(chat_id, self.username, text, scheme)
            self._persist()
            self._emit({"type": "ready"})
            return {"ok": True}
        # group: fan-out 1:1 envelopes; relay never sees a group object
        members = [m for m in chat["members"] if m != self.username]
        packed = protocol.pack_group(chat["group_id"], chat["title"], chat["members"], text, event="message")
        for member in members:
            result = self._send_envelope(member, packed, scheme)
            if not result.get("ok"):
                return {"ok": False, "error": f"Could not reach @{member}: {result.get('error')}"}
        self._append_local(chat_id, self.username, text, scheme)
        self._persist()
        self._emit({"type": "ready"})
        return {"ok": True}

    def send_file(self, name, data_b64, mime="", scheme="rsa"):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        scheme = FRIEND_SCHEME
        chat_id = self.active_chat
        if not chat_id or chat_id not in self.state["chats"]:
            return {"ok": False, "error": "Pick a conversation first"}
        try:
            data = base64.b64decode(data_b64 or "", validate=True)
        except (ValueError, TypeError):
            return {"ok": False, "error": "Could not read the file"}
        try:
            fields = protocol.file_fields(name, data, mime)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        chat = self.state["chats"][chat_id]
        extra = {"file": {k: fields[k] for k in ("name", "mime", "size", "sha256")}}
        preview = f"📎 {fields['name']} ({_size_label(fields['size'])})"
        if chat["type"] == "dm":
            other = [m for m in chat["members"] if m != self.username][0]
            packed = protocol.pack_file(name, data, mime)
            result = self._send_envelope(other, packed, scheme)
            if not result.get("ok"):
                return result
        else:
            members = [m for m in chat["members"] if m != self.username]
            packed = protocol.pack_group(
                chat["group_id"],
                chat["title"],
                chat["members"],
                fields["name"],
                event="file",
                file={"name": name, "data": data, "mime": mime},
            )
            for member in members:
                result = self._send_envelope(member, packed, scheme)
                if not result.get("ok"):
                    return {"ok": False, "error": f"Could not reach @{member}: {result.get('error')}"}
        self._store_blob(fields["sha256"], data)
        self._append_local(chat_id, self.username, preview, scheme, extra)
        self._persist()
        self._emit({"type": "ready"})
        return {"ok": True, "sha256": fields["sha256"]}

    def _xftp_url(self, file_id, index):
        return urljoin(SERVER, f"/xftp/{file_id}/{index}")

    def xftp_begin(self, name, size, mime=""):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        chat_id = self.active_chat
        if not chat_id or chat_id not in self.state.get("chats", {}):
            return {"ok": False, "error": "Pick a conversation first"}
        try:
            size = int(size)
        except (TypeError, ValueError):
            return {"ok": False, "error": "Invalid file size"}
        if size <= 0:
            return {"ok": False, "error": "Empty file"}
        if size > protocol.MAX_XFTP_BYTES:
            return {"ok": False, "error": "Attachment too large (max 4 GB)"}
        self._xftp_abort()
        chunk_size = protocol.choose_xftp_chunk_size(size)
        n_chunks = protocol.xftp_chunk_count(size, chunk_size)
        auth = protocol.inbox_auth_payload(self.username, self.keys["rsa"]["priv"])
        auth["chunk_size"] = chunk_size
        auth["n_chunks"] = n_chunks
        try:
            resp = requests.post(urljoin(SERVER, "/xftp/create"), json=auth, timeout=30)
        except requests.RequestException as e:
            return {"ok": False, "error": str(e)}
        if resp.status_code != 200:
            return {"ok": False, "error": _http_error(resp)}
        info = resp.json()
        self._xftp_tx = {
            "chat_id": chat_id,
            "name": protocol.sanitize_filename(name),
            "mime": protocol.sanitize_mime(mime),
            "size": size,
            "chunk_size": info["chunk_size"],
            "n_chunks": info["n_chunks"],
            "file_id": info["file_id"],
            "put_secret": info["put_secret"],
            "get_secret": info["get_secret"],
            "expires": info["expires"],
            "key": get_random_bytes(32),
            "hasher": SHA256.new(),
            "buf": bytearray(),
            "index": 0,
            "received": 0,
        }
        return {
            "ok": True,
            "id": info["file_id"],
            "slice": protocol.XFTP_PUSH_SLICE,
            "n_chunks": n_chunks,
            "chunk_size": chunk_size,
        }

    def _xftp_abort(self):
        tx = self._xftp_tx
        self._xftp_tx = None
        if not tx:
            return
        try:
            requests.delete(
                urljoin(SERVER, f"/xftp/{tx['file_id']}"),
                headers={"X-Sealed-Put": tx["put_secret"]},
                timeout=15,
            )
        except Exception:
            pass

    def _xftp_put_plain(self, plain):
        tx = self._xftp_tx
        blob = protocol.xftp_seal_chunk(plain, tx["key"], tx["index"])
        resp = requests.put(
            self._xftp_url(tx["file_id"], tx["index"]),
            headers={"X-Sealed-Put": tx["put_secret"]},
            data=blob,
            timeout=180,
        )
        if resp.status_code != 200:
            raise RuntimeError(_http_error(resp))
        tx["index"] += 1

    def xftp_push(self, file_id, data_b64):
        tx = self._xftp_tx
        if not tx or tx["file_id"] != file_id:
            return {"ok": False, "error": "No large-file upload in progress"}
        try:
            data = base64.b64decode(data_b64 or "", validate=True)
        except (ValueError, TypeError):
            return {"ok": False, "error": "Could not read the file"}
        if tx["received"] + len(data) > tx["size"]:
            return {"ok": False, "error": "File was larger than announced"}
        try:
            tx["hasher"].update(data)
            tx["received"] += len(data)
            tx["buf"].extend(data)
            while len(tx["buf"]) >= tx["chunk_size"]:
                block = bytes(tx["buf"][: tx["chunk_size"]])
                del tx["buf"][: tx["chunk_size"]]
                self._xftp_put_plain(block)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        pct = int(100 * tx["received"] / tx["size"]) if tx["size"] else 100
        return {"ok": True, "pct": pct}

    def xftp_finish(self, file_id):
        tx = self._xftp_tx
        if not tx or tx["file_id"] != file_id:
            return {"ok": False, "error": "No large-file upload in progress"}
        if tx["received"] != tx["size"]:
            self._xftp_abort()
            return {"ok": False, "error": "File upload was incomplete"}
        try:
            published = False
            if tx["buf"]:
                pad = tx["chunk_size"] - len(tx["buf"])
                tx["buf"].extend(b"\x00" * pad)
                self._xftp_put_plain(bytes(tx["buf"]))
                tx["buf"].clear()
            if tx["index"] != tx["n_chunks"]:
                self._xftp_abort()
                return {"ok": False, "error": "Chunk count mismatch"}
            offer = {
                "name": tx["name"],
                "mime": tx["mime"],
                "size": tx["size"],
                "chunk_size": tx["chunk_size"],
                "n_chunks": tx["n_chunks"],
                "sha256": tx["hasher"].hexdigest(),
                "file_id": tx["file_id"],
                "get_secret": tx["get_secret"],
                "key": tx["key"].hex(),
                "expires": tx["expires"],
            }
            chat = self.state["chats"][tx["chat_id"]]
            extra = {"xftp": dict(offer)}
            preview = f"📦 {offer['name']} ({_size_label(offer['size'])}) · large file"
            if chat["type"] == "dm":
                other = [m for m in chat["members"] if m != self.username][0]
                packed = protocol.pack_xftp(offer)
                result = self._send_envelope(other, packed, FRIEND_SCHEME)
                if not result.get("ok"):
                    return result
            else:
                packed = protocol.pack_group(
                    chat["group_id"],
                    chat["title"],
                    chat["members"],
                    offer["name"],
                    event="xftp",
                    xftp=offer,
                )
                for member in [m for m in chat["members"] if m != self.username]:
                    result = self._send_envelope(member, packed, FRIEND_SCHEME)
                    if not result.get("ok"):
                        return {"ok": False, "error": f"Could not reach @{member}: {result.get('error')}"}
            published = True
            self._append_local(tx["chat_id"], self.username, preview, FRIEND_SCHEME, extra)
            self._persist()
            self._emit({"type": "ready"})
            self._xftp_tx = None
            return {"ok": True, "file_id": offer["file_id"]}
        except Exception as e:
            if published:
                self._xftp_tx = None
            else:
                self._xftp_abort()
            return {"ok": False, "error": str(e)}

    def download_xftp(self, file_id):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        offer = None
        for chat in self.state.get("chats", {}).values():
            for msg in chat.get("messages", []):
                info = msg.get("xftp") or {}
                if info.get("file_id") == file_id:
                    offer = info
                    break
            if offer:
                break
        parsed = protocol._xftp_offer_fields(offer or {})
        if not parsed:
            return {"ok": False, "error": "Unknown large file"}
        path, cancelled = self._pick_save_path(parsed["name"])
        if cancelled or not path:
            return {"ok": False, "cancelled": True, "error": "Save cancelled"}
        path = os.path.abspath(os.path.expanduser(str(path)))
        parent = os.path.dirname(path)
        if not parent or not os.path.isdir(parent):
            return {"ok": False, "error": "That folder does not exist"}
        key = bytes.fromhex(parsed["key"])
        hasher = SHA256.new()
        written = 0
        tmp = path + ".part"
        try:
            with open(tmp, "wb") as out:
                for index in range(parsed["n_chunks"]):
                    resp = requests.get(
                        self._xftp_url(parsed["file_id"], index),
                        headers={"X-Sealed-Get": parsed["get_secret"]},
                        timeout=180,
                    )
                    if resp.status_code != 200:
                        raise RuntimeError(_http_error(resp) if resp.text is not None else "Download failed")
                    plain = protocol.xftp_open_chunk(resp.content, key, index)
                    remain = parsed["size"] - written
                    if remain <= 0:
                        raise RuntimeError("File was larger than announced")
                    if len(plain) > remain:
                        plain = plain[:remain]
                    hasher.update(plain)
                    out.write(plain)
                    written += len(plain)
            if written != parsed["size"] or hasher.hexdigest() != parsed["sha256"]:
                raise RuntimeError("File failed integrity check")
            os.replace(tmp, path)
        except Exception as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return {"ok": False, "error": str(e)}
        self._save_dir = parent
        self._reveal_path(path)
        return {"ok": True, "path": path}

    def export_file(self, digest):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        if not isinstance(digest, str) or not _BLOB_ID_RE.fullmatch(digest):
            return {"ok": False, "error": "Unknown attachment"}
        data = self._load_blob(digest)
        if data is None:
            return {"ok": False, "error": "Attachment is not on this device"}
        name, mime = self._file_meta(digest)
        return {
            "ok": True,
            "name": protocol.sanitize_filename(name),
            "mime": _guess_mime(name, data, mime),
            "data": base64.b64encode(data).decode(),
        }

    def _file_meta(self, digest):
        name = "attachment"
        mime = "application/octet-stream"
        for chat in self.state.get("chats", {}).values():
            for msg in chat.get("messages", []):
                info = msg.get("file") or {}
                if info.get("sha256") == digest:
                    name = info.get("name") or name
                    mime = info.get("mime") or mime
                    return name, mime
        return name, mime

    def _reveal_path(self, path):
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            elif sys.platform == "win32":
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path) or "."])
        except Exception:
            pass

    def _unique_path(self, folder, name):
        base, ext = os.path.splitext(name)
        path = os.path.join(folder, name)
        n = 1
        while os.path.exists(path):
            path = os.path.join(folder, f"{base} ({n}){ext}")
            n += 1
        return path

    def _pick_save_path(self, name):
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        os.makedirs(downloads, exist_ok=True)
        start_dir = getattr(self, "_save_dir", None) or downloads
        try:
            import webview
            window = getattr(self, "_window", None)
            if window is None:
                windows = getattr(webview, "windows", None) or []
                window = windows[0] if windows else None
            if window is None:
                return self._unique_path(downloads, name), False
            save_kind = getattr(webview, "SAVE_DIALOG", None)
            if save_kind is None:
                save_kind = webview.FileDialog.SAVE
            chosen = window.create_file_dialog(
                save_kind,
                directory=start_dir,
                save_filename=name,
            )
            if not chosen:
                return None, True
            path = chosen[0] if isinstance(chosen, (list, tuple)) else chosen
            return str(path), False
        except Exception:
            return self._unique_path(downloads, name), False

    def save_file(self, digest):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        if not isinstance(digest, str) or not _BLOB_ID_RE.fullmatch(digest):
            return {"ok": False, "error": "Unknown attachment"}
        data = self._load_blob(digest)
        if data is None:
            return {"ok": False, "error": "Attachment is not on this device"}
        name = protocol.sanitize_filename(self._file_meta(digest)[0])
        path, cancelled = self._pick_save_path(name)
        if cancelled or not path:
            return {"ok": False, "cancelled": True, "error": "Save cancelled"}
        path = os.path.abspath(os.path.expanduser(str(path)))
        parent = os.path.dirname(path)
        if not parent or not os.path.isdir(parent):
            return {"ok": False, "error": "That folder does not exist"}
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError as exc:
            return {"ok": False, "error": f"Could not write file: {exc}"}
        self._save_dir = parent
        self._reveal_path(path)
        return {"ok": True, "path": path}

    def copy_file(self, digest):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        if not isinstance(digest, str) or not _BLOB_ID_RE.fullmatch(digest):
            return {"ok": False, "error": "Unknown attachment"}
        data = self._load_blob(digest)
        if data is None:
            return {"ok": False, "error": "Attachment is not on this device"}
        name, mime = self._file_meta(digest)
        mime = _guess_mime(name, data, mime)
        if sys.platform == "darwin" and mime.startswith("image/"):
            import tempfile
            suffix = ".png" if "png" in mime else ".jpg" if "jpeg" in mime else ".gif" if "gif" in mime else ".bin"
            handle, tmp = tempfile.mkstemp(suffix=suffix)
            try:
                with os.fdopen(handle, "wb") as f:
                    f.write(data)
                quoted = tmp.replace("\\", "\\\\").replace('"', '\\"')
                kind = "«class PNGf»" if suffix == ".png" else "JPEG picture" if suffix == ".jpg" else "«class GIFf»"
                script = f'set the clipboard to (read (POSIX file "{quoted}") as {kind})'
                done = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
                if done.returncode != 0:
                    return {"ok": False, "error": "Could not copy image"}
                return {"ok": True, "kind": "image"}
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return {"ok": False, "error": "Use Save as… then copy the file from that folder"}

    def _active_dm_peer(self):
        chat_id = self.active_chat
        if not chat_id or chat_id not in self.state.get("chats", {}):
            return None, "Pick a conversation first"
        chat = self.state["chats"][chat_id]
        if chat["type"] != "dm":
            return None, "Voice calls are 1:1 only"
        peers = [m for m in chat["members"] if m != self.username]
        if not peers:
            return None, "No one to call"
        return peers[0], None

    def call_start(self, sdp):
        peer, err = self._active_dm_peer()
        if err:
            return {"ok": False, "error": err}
        if self.call and self.call.get("status") in ("calling", "ringing", "live"):
            return {"ok": False, "error": "Already in a call"}
        call_id = protocol.new_call_id()
        try:
            packed = protocol.pack_call("offer", call_id, sdp=sdp)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        result = self._send_envelope(peer, packed, "rsa")
        if not result.get("ok"):
            return result
        self.call = {"id": call_id, "peer": peer, "role": "caller", "status": "calling", "sdp": sdp}
        self._emit({"type": "call", "event": "local-start", "call_id": call_id, "peer": peer})
        return {"ok": True, "call_id": call_id, "peer": peer}

    def call_signal(self, event, call_id, sdp=None, candidate=None):
        if event not in ("answer", "ice", "hangup", "reject"):
            return {"ok": False, "error": "Invalid call event"}
        if not self.call or self.call.get("id") != call_id or not self.call.get("peer"):
            return {"ok": False, "error": "No matching call"}
        peer = self.call["peer"]
        try:
            packed = protocol.pack_call(event, call_id, sdp=sdp, candidate=candidate)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        result = self._send_envelope(peer, packed, "rsa")
        if not result.get("ok"):
            return result
        if event in ("hangup", "reject"):
            self.call = None
            self._emit({"type": "call", "event": event, "call_id": call_id, "from": self.username})
        elif event == "answer":
            self.call["status"] = "live"
        return {"ok": True}

    def call_hangup(self):
        if not self.call:
            return {"ok": True}
        call_id = self.call["id"]
        peer = self.call["peer"]
        try:
            packed = protocol.pack_call("hangup", call_id)
            self._send_envelope(peer, packed, "rsa")
        except Exception:
            pass
        self.call = None
        self._emit({"type": "call", "event": "hangup", "call_id": call_id})
        return {"ok": True}

    def create_group(self, title, usernames):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        raw = [u.strip() for u in (usernames or "").replace(",", " ").split() if u.strip()]
        try:
            members = [self.username] + [protocol.normalize_username(u) for u in raw]
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        members = list(dict.fromkeys(members))
        if self.username not in members:
            members.insert(0, self.username)
        if len(members) < 2:
            return {"ok": False, "error": "Add at least one other username"}
        pubs_ok = []
        for u in members:
            if u == self.username:
                continue
            looked = self.lookup(u)
            if not looked.get("ok"):
                return {"ok": False, "error": f"@{u}: {looked.get('error')}"}
            pubs_ok.append(u)
        group_id = protocol.new_group_id()
        try:
            packed = protocol.pack_group(group_id, title, members, "", event="invite")
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        cid = f"grp:{group_id}"
        with self.lock:
            self.state["chats"][cid] = {
                "type": "group",
                "group_id": group_id,
                "title": (title or "Group").strip()[:40] or "Group",
                "members": members,
                "creator": self.username,
                "messages": [],
                "updated": time.time(),
            }
            self.active_chat = cid
        for u in pubs_ok:
            result = self._send_envelope(u, packed, "rsa")
            if not result.get("ok"):
                return {"ok": False, "error": f"Invite to @{u} failed: {result.get('error')}"}
        self._append_local(cid, self.username, "Created an encrypted group. The relay cannot see the member list.", "rsa")
        self._persist()
        self._emit({"type": "ready"})
        return {"ok": True, "id": cid}

    def invite_to_group(self, usernames):
        if not self.username:
            return {"ok": False, "error": "Not signed in"}
        chat_id = self.active_chat
        if not chat_id or chat_id not in self.state.get("chats", {}):
            return {"ok": False, "error": "Open a group first"}
        chat = self.state["chats"][chat_id]
        if chat["type"] != "group":
            return {"ok": False, "error": "Invites are for groups only"}
        if chat.get("creator") != self.username:
            return {"ok": False, "error": "Only the group creator can invite"}
        raw = [u.strip() for u in (usernames or "").replace(",", " ").split() if u.strip()]
        try:
            newcomers = [protocol.normalize_username(u) for u in raw]
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        newcomers = [u for u in dict.fromkeys(newcomers) if u not in chat["members"]]
        if not newcomers:
            return {"ok": False, "error": "Add at least one new username"}
        members = list(chat["members"]) + newcomers
        if len(members) > protocol.MAX_GROUP_MEMBERS:
            return {"ok": False, "error": f"Groups can have at most {protocol.MAX_GROUP_MEMBERS} members"}
        for u in newcomers:
            looked = self.lookup(u)
            if not looked.get("ok"):
                return {"ok": False, "error": f"@{u}: {looked.get('error')}"}
        try:
            packed_invite = protocol.pack_group(chat["group_id"], chat["title"], members, "", event="invite")
            packed_update = protocol.pack_group(chat["group_id"], chat["title"], members, "", event="update")
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        existing = [m for m in chat["members"] if m != self.username]
        for u in newcomers:
            result = self._send_envelope(u, packed_invite, "rsa")
            if not result.get("ok"):
                return {"ok": False, "error": f"Invite to @{u} failed: {result.get('error')}"}
        for u in existing:
            result = self._send_envelope(u, packed_update, "rsa")
            if not result.get("ok"):
                return {"ok": False, "error": f"Could not update @{u}: {result.get('error')}"}
        chat["members"] = members
        names = ", ".join("@" + u for u in newcomers)
        self._append_local(chat_id, self.username, "Invited " + names + ".", "rsa")
        self._persist()
        self._emit({"type": "ready"})
        return {"ok": True, "id": chat_id, "members": members}

    def _append_local(self, chat_id, sender, text, scheme, extra=None):
        chat = self.state["chats"][chat_id]
        msg = {
            "from": sender,
            "text": text,
            "ts": int(time.time()),
            "scheme": scheme,
            "mine": sender == self.username,
        }
        if extra:
            msg.update(extra)
        chat["messages"].append(msg)
        if len(chat["messages"]) > MAX_CHAT_MESSAGES:
            chat["messages"] = chat["messages"][-MAX_CHAT_MESSAGES:]
        chat["updated"] = time.time()

    def _handle_file(self, chat_id, sender, scheme, file_info):
        self._store_blob(file_info["sha256"], file_info["data"])
        extra = {"file": {k: file_info[k] for k in ("name", "mime", "size", "sha256")}}
        preview = f"📎 {file_info['name']} ({_size_label(file_info['size'])})"
        self._append_local(chat_id, sender, preview, scheme, extra)

    def _ingest_call(self, sender, payload, inner, fingerprint=None):
        event = inner["event"]
        call_id = inner["call_id"]
        if event == "offer":
            self._ensure_dm(sender, fingerprint)
            age = abs(int(time.time()) - int(payload.get("timestamp", 0)))
            if age > CALL_OFFER_SECONDS:
                return
            if self.call and self.call.get("status") in ("calling", "ringing", "live"):
                if self.call.get("id") != call_id:
                    try:
                        packed = protocol.pack_call("reject", call_id)
                        self._send_envelope(sender, packed, "rsa")
                    except Exception:
                        pass
                return
            self.call = {
                "id": call_id,
                "peer": sender,
                "role": "callee",
                "status": "ringing",
                "sdp": inner.get("sdp"),
            }
            self._emit({
                "type": "call",
                "event": "offer",
                "from": sender,
                "call_id": call_id,
                "sdp": inner.get("sdp"),
            })
            return
        if not self.call or self.call.get("id") != call_id or self.call.get("peer") != sender:
            return
        if event == "answer":
            if self.call.get("role") != "caller":
                return
            self.call["status"] = "live"
        elif event in ("hangup", "reject"):
            self.call = None
        elif event != "ice":
            return
        self._emit({
            "type": "call",
            "event": event,
            "from": sender,
            "call_id": call_id,
            "sdp": inner.get("sdp"),
            "candidate": inner.get("candidate"),
        })

    def _ingest(self, sender, payload, persist=True):
        if not payload:
            return
        nonce = payload.get("nonce")
        with self.lock:
            if nonce and nonce in self.state.get("seen", []):
                return
            try:
                sender = protocol.normalize_username(sender or payload.get("sender"))
            except ValueError:
                self._mark_seen(nonce)
                return
            looked = self.lookup(sender)
            if looked.get("code") == "tofu":
                self._mark_seen(nonce)
                self._emit({"type": "error", "error": looked.get("error")})
                return
            if not looked.get("ok"):
                return
            plaintext, ok, reason = protocol.hybrid_decrypt(
                payload, self.keys, looked["public_keys"]["rsa"].encode(), expected_recipient=self.username
            )
            if not ok:
                self._mark_seen(nonce)
                return
            inner = protocol.parse_inner(plaintext)
            if not inner:
                self._mark_seen(nonce)
                return
            scheme = payload.get("scheme")
            if inner["kind"] == "call":
                self._ingest_call(sender, payload, inner, looked.get("fingerprint"))
                self._mark_seen(nonce)
                if persist:
                    self._persist()
                return
            if inner["kind"] == "file":
                cid = self._ensure_dm(sender, looked["fingerprint"])
                self._handle_file(cid, sender, scheme, inner)
            elif inner["kind"] == "xftp":
                cid = self._ensure_dm(sender, looked["fingerprint"])
                self._handle_xftp(cid, sender, scheme, inner)
            elif inner["kind"] == "direct":
                cid = self._ensure_dm(sender, looked["fingerprint"])
                self._append_local(cid, sender, inner["text"], scheme)
            else:
                self._ingest_group(sender, inner, scheme, looked.get("fingerprint"))
            self._mark_seen(nonce)
            if persist:
                self._persist()

    def _ingest_group(self, sender, inner, scheme, fingerprint=None):
        gid = inner["group_id"]
        cid = f"grp:{gid}"
        chats = self.state.setdefault("chats", {})
        packet_members = inner["members"]
        if self.username not in packet_members or sender not in packet_members:
            return
        event = inner.get("event")
        if cid not in chats:
            if event != "invite":
                return
            chats[cid] = {
                "type": "group",
                "group_id": gid,
                "title": inner["title"],
                "members": packet_members,
                "creator": sender,
                "messages": [],
                "updated": time.time(),
            }
            if inner.get("text"):
                self._append_local(cid, sender, inner["text"], scheme)
            else:
                self._append_local(
                    cid, sender,
                    f"Added you to “{inner['title']}”. Member list stays on your device.",
                    scheme,
                )
            return
        chat = chats[cid]
        if sender not in chat["members"]:
            return
        creator = chat.get("creator")
        if event in ("invite", "update"):
            if creator and sender == creator:
                chat["members"] = packet_members
                chat["title"] = inner["title"]
            return
        if event == "file" and inner.get("file"):
            self._handle_file(cid, sender, scheme, inner["file"])
            return
        if event == "xftp" and inner.get("xftp"):
            self._handle_xftp(cid, sender, scheme, inner["xftp"])
            return
        if inner.get("text"):
            self._append_local(cid, sender, inner["text"], scheme)

    def _handle_xftp(self, chat_id, sender, scheme, offer):
        parsed = protocol._xftp_offer_fields(offer)
        if not parsed:
            return
        extra = {"xftp": parsed}
        preview = f"📦 {parsed['name']} ({_size_label(parsed['size'])}) · large file"
        self._append_local(chat_id, sender, preview, scheme, extra)


class JsBridge:
    def __init__(self, messenger):
        self.m = messenger

    def signup(self, username, passphrase, confirm, invite=""):
        return self.m.signup(username, passphrase, confirm, invite)

    def job_status(self):
        return self.m.job_status()

    def login(self, username, passphrase):
        return self.m.login(username, passphrase)

    def snapshot(self):
        return self.m.snapshot()

    def poll(self):
        return self.m.poll()

    def lookup(self, username):
        return self.m.lookup(username)

    def start_dm(self, username):
        return self.m.start_dm(username)

    def open_chat(self, chat_id):
        return self.m.open_chat(chat_id)

    def send(self, text, scheme):
        return self.m.send(text, scheme)

    def send_file(self, name, data_b64, mime, scheme):
        return self.m.send_file(name, data_b64, mime, scheme)

    def xftp_begin(self, name, size, mime):
        return self.m.xftp_begin(name, size, mime)

    def xftp_push(self, file_id, data_b64):
        return self.m.xftp_push(file_id, data_b64)

    def xftp_finish(self, file_id):
        return self.m.xftp_finish(file_id)

    def download_xftp(self, file_id):
        return self.m.download_xftp(file_id)

    def export_file(self, digest):
        return self.m.export_file(digest)

    def save_file(self, digest):
        return self.m.save_file(digest)

    def copy_file(self, digest):
        return self.m.copy_file(digest)

    def call_start(self, sdp):
        return self.m.call_start(sdp)

    def call_signal(self, event, call_id, sdp, candidate):
        return self.m.call_signal(event, call_id, sdp, candidate)

    def call_hangup(self):
        return self.m.call_hangup()

    def create_group(self, title, usernames):
        return self.m.create_group(title, usernames)

    def invite_to_group(self, usernames):
        return self.m.invite_to_group(usernames)

    def confirm_key(self, username):
        return self.m.confirm_key(username)


def run_gui():
    import webview

    messenger = Messenger()
    bridge = JsBridge(messenger)
    url, httpd = _serve_ui()
    window = webview.create_window(
        "Sealed",
        url,
        js_api=bridge,
        width=1120,
        height=740,
        min_size=(880, 580),
        background_color="#0c1117",
    )
    messenger._window = window
    try:
        webview.start()
    finally:
        httpd.shutdown()
