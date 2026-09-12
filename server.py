# server.py — untrusted ciphertext relay. Never handles private keys or plaintext.
import hashlib
import hmac
import json
import os
import re
import threading
import time
import base64

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

import database
import protocol

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
MAX_ENVELOPE_BYTES = 8 * 1024 * 1024
MAX_INBOX_MESSAGES = 400
MAX_INBOX_BYTES = 32 * 1024 * 1024
TURN_TTL_SECONDS = 6 * 3600
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_nonce_lock = threading.Lock()
_seen_nonces = {}
_rate_lock = threading.Lock()
_rate_hits = {}


def assert_safe_bind():
    host = os.environ.get("SEALED_BIND", "127.0.0.1")
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    if not (os.environ.get("SEALED_INVITE") or "").strip():
        raise SystemExit("Refusing to bind on a public address without SEALED_INVITE")


def _invite_ok(provided):
    expected = os.environ.get("SEALED_INVITE") or ""
    if not expected:
        return True
    if not isinstance(provided, str) or not provided or len(provided) > 128:
        return False
    left = hashlib.sha256(provided.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


def _client_ip(request: Request):
    if os.environ.get("SEALED_TRUST_PROXY") == "1":
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64] or "0.0.0.0"
    if request.client and request.client.host:
        return request.client.host
    return "0.0.0.0"


def _rate_ok(key, limit, window_s):
    now = time.time()
    with _rate_lock:
        hits = _rate_hits.setdefault(key, [])
        hits[:] = [t for t in hits if now - t < window_s]
        if len(_rate_hits) > 20000:
            stale = [k for k, v in _rate_hits.items() if not v]
            for k in stale[:5000]:
                _rate_hits.pop(k, None)
        if len(hits) >= limit:
            return False
        hits.append(now)
        return True


def _fresh_nonce(nonce):
    if not isinstance(nonce, str) or not (16 <= len(nonce) <= 128):
        return False
    now = int(time.time())
    with _nonce_lock:
        expired = [n for n, exp in _seen_nonces.items() if exp < now]
        for n in expired:
            del _seen_nonces[n]
        if nonce in _seen_nonces:
            return False
        _seen_nonces[nonce] = now + protocol.AUTH_WINDOW_SECONDS
        return True


def _turn_credentials(secret):
    expiry = str(int(time.time()) + TURN_TTL_SECONDS)
    digest = hmac.new(secret.encode("utf-8"), expiry.encode("utf-8"), hashlib.sha1).digest()
    return expiry, base64.b64encode(digest).decode("ascii")


def ice_servers():
    host = (os.environ.get("SEALED_TURN_HOST") or "").strip()
    secret = os.environ.get("SEALED_TURN_SECRET") or ""
    if not host or not _HOST_RE.fullmatch(host):
        return []
    servers = [{"urls": "stun:" + host + ":3478"}]
    if secret:
        user, cred = _turn_credentials(secret)
        servers.append({
            "urls": "turn:" + host + ":3478?transport=udp",
            "username": user,
            "credential": cred,
        })
        servers.append({
            "urls": "turn:" + host + ":3478?transport=tcp",
            "username": user,
            "credential": cred,
        })
    return servers


def _authed_user(req):
    try:
        username = protocol.normalize_username(req.username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    keys = database.get_public_keys(username)
    if not keys:
        raise HTTPException(status_code=404, detail="User not found")
    if not protocol.verify_inbox_auth(username, req.timestamp, req.nonce, req.signature, keys["rsa"]):
        raise HTTPException(status_code=401, detail="Authentication failed")
    return username, keys


class RegisterRequest(BaseModel):
    username: str
    public_keys: dict
    identity_sig: str = Field(min_length=20, max_length=8192)
    invite: str = Field(default="", max_length=128)


class MessageRequest(BaseModel):
    sender: str
    recipient: str
    payload: dict


class InboxAuthRequest(BaseModel):
    username: str
    timestamp: int
    nonce: str
    signature: str


class ConnectionManager:
    def __init__(self):
        self.active = {}

    async def connect(self, username, ws):
        old = self.active.get(username)
        if old is not None:
            try:
                await old.close()
            except Exception:
                pass
        self.active[username] = ws

    def disconnect(self, username, ws):
        if self.active.get(username) is ws:
            self.active.pop(username, None)

    async def push(self, username, message):
        ws = self.active.get(username)
        if ws is None:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception:
            self.disconnect(username, ws)
            return False


manager = ConnectionManager()


@app.get("/")
def home():
    return {
        "status": "running",
        "service": "Sealed relay",
        "invite_required": bool(os.environ.get("SEALED_INVITE")),
    }


@app.post("/register")
def register(req: RegisterRequest, request: Request):
    if not _rate_ok("reg:" + _client_ip(request), 8, 3600):
        raise HTTPException(status_code=429, detail="Too many attempts")
    if not _invite_ok(req.invite):
        raise HTTPException(status_code=403, detail="Invite required")
    try:
        username = protocol.normalize_username(req.username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not protocol.verify_identity_bundle(username, req.public_keys, req.identity_sig):
        raise HTTPException(status_code=400, detail="Identity signature invalid")
    success = database.register_user_db(username, req.public_keys, req.identity_sig)
    if not success:
        raise HTTPException(status_code=400, detail="Username taken")
    fp = protocol.public_fingerprint(req.public_keys)
    return {"msg": "Registered successfully", "username": username, "fingerprint": fp}


@app.get("/keys/{username}")
def get_keys(username: str, request: Request):
    if not _rate_ok("keys:" + _client_ip(request), 120, 60):
        raise HTTPException(status_code=429, detail="Too many attempts")
    try:
        username = protocol.normalize_username(username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    bundle = database.get_user_bundle(username)
    if not bundle:
        raise HTTPException(status_code=404, detail="User not found")
    if not protocol.verify_identity_bundle(username, bundle["public_keys"], bundle["identity_sig"]):
        raise HTTPException(status_code=500, detail="Stored identity bundle is corrupt")
    bundle["fingerprint"] = protocol.public_fingerprint(bundle["public_keys"])
    return bundle


def _accept_envelope(sender, recipient, payload):
    try:
        sender = protocol.normalize_username(sender)
        recipient = protocol.normalize_username(recipient)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    sender_keys = database.get_public_keys(sender)
    if not sender_keys:
        raise HTTPException(status_code=404, detail="Sender not found")
    if not database.get_public_keys(recipient):
        raise HTTPException(status_code=404, detail="Recipient not found")
    raw = str(payload)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise HTTPException(status_code=400, detail="Envelope too large")
    ok, reason = protocol.verify_send_payload(sender, recipient, payload, sender_keys["rsa"].encode())
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    if not _fresh_nonce("msg:" + str(payload.get("nonce"))):
        raise HTTPException(status_code=400, detail="Replayed envelope")
    return sender, recipient, payload


async def _deliver(sender, recipient, payload):
    pushed = await manager.push(recipient, {"type": "msg", "from": sender, "payload": payload})
    if pushed:
        return sender, recipient, payload
    count, nbytes = database.inbox_usage(recipient)
    extra = json_size(payload)
    if count >= MAX_INBOX_MESSAGES or nbytes + extra > MAX_INBOX_BYTES:
        raise HTTPException(status_code=507, detail="Recipient inbox is full")
    database.store_message(sender, recipient, payload)
    return sender, recipient, payload


def json_size(payload):
    return len(json.dumps(payload, separators=(",", ":")))


@app.post("/send")
async def send_message(req: MessageRequest, request: Request):
    if not _rate_ok("send:" + _client_ip(request), 90, 60):
        raise HTTPException(status_code=429, detail="Too many attempts")
    sender, recipient, payload = _accept_envelope(req.sender, req.recipient, req.payload)
    await _deliver(sender, recipient, payload)
    return {"msg": "Message queued for delivery"}


@app.post("/inbox")
def get_inbox(req: InboxAuthRequest, request: Request):
    if not _rate_ok("inbox:" + _client_ip(request), 60, 60):
        raise HTTPException(status_code=429, detail="Too many attempts")
    username, _keys = _authed_user(req)
    if not _fresh_nonce("inbox:" + username + ":" + str(req.nonce)):
        raise HTTPException(status_code=401, detail="Replayed inbox auth")
    msgs = database.fetch_messages(username, consume=True)
    return {"messages": msgs}


@app.post("/ice")
def get_ice(req: InboxAuthRequest, request: Request):
    if not _rate_ok("ice:" + _client_ip(request), 30, 60):
        raise HTTPException(status_code=429, detail="Too many attempts")
    username, _keys = _authed_user(req)
    if not _fresh_nonce("ice:" + username + ":" + str(req.nonce)):
        raise HTTPException(status_code=401, detail="Replayed ice auth")
    return {"iceServers": ice_servers()}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    username = None
    try:
        first = await ws.receive_json()
        if not isinstance(first, dict) or first.get("type") != "auth":
            await ws.close(code=1008)
            return
        username = protocol.normalize_username(first.get("username"))
        keys = database.get_public_keys(username)
        if not keys:
            await ws.close(code=1008)
            return
        if not protocol.verify_inbox_auth(
            username, first.get("timestamp"), first.get("nonce"), first.get("signature"), keys["rsa"]
        ):
            await ws.close(code=1008)
            return
        if not _fresh_nonce("ws:" + username + ":" + str(first.get("nonce"))):
            await ws.close(code=1008)
            return
        await manager.connect(username, ws)
        await ws.send_json({"type": "ok", "username": username})
        queued = database.fetch_messages(username, consume=True)
        if queued:
            await ws.send_json({"type": "queued", "messages": queued})
        sent = 0
        window_start = time.time()
        while True:
            data = await ws.receive_json()
            if not isinstance(data, dict):
                continue
            if data.get("type") == "ping":
                await ws.send_json({"type": "pong"})
                continue
            if data.get("type") == "send":
                now = time.time()
                if now - window_start > 60:
                    sent = 0
                    window_start = now
                sent += 1
                if sent > 90:
                    await ws.send_json({"type": "error", "detail": "Too many attempts"})
                    continue
                try:
                    sender, recipient, payload = _accept_envelope(
                        username, data.get("to"), data.get("payload") or {}
                    )
                except HTTPException as e:
                    await ws.send_json({"type": "error", "detail": e.detail})
                    continue
                try:
                    await _deliver(sender, recipient, payload)
                except HTTPException as e:
                    await ws.send_json({"type": "error", "detail": e.detail})
                    continue
                await ws.send_json({"type": "sent", "to": recipient, "nonce": payload.get("nonce")})
    except (WebSocketDisconnect, ValueError):
        pass
    finally:
        if username:
            manager.disconnect(username, ws)


if __name__ == "__main__":
    import uvicorn
    assert_safe_bind()
    uvicorn.run(
        app,
        host=os.environ.get("SEALED_BIND", "127.0.0.1"),
        port=int(os.environ.get("SEALED_PORT", "8000")),
        proxy_headers=os.environ.get("SEALED_TRUST_PROXY") == "1",
    )
