"""Hybrid encrypt / sign helpers shared by the local CLI, the client, and tests."""
import base64
import json
import re
import time
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

from concurrent.futures import ThreadPoolExecutor

from aes_utils import AES_KEY_LEN, aes_encrypt, aes_decrypt
from rsa_utils import generate_rsa_keys, rsa_encrypt, rsa_decrypt, sign_message, verify_signature
from elgamal_utils import generate_elgamal_keys, elgamal_encrypt, elgamal_decrypt
from rabin_utils import generate_rabin_keys, rabin_encrypt, rabin_decrypt, recover_rabin_aes_key_and_decrypt

DEFAULT_RSA_BITS = 2048
# 1024-bit Sophie-Germain primes can take minutes and freeze a GUI.
# 512-bit is the floor that still wraps an AES-256 key.
DEFAULT_ELGAMAL_BITS = 512
DEFAULT_RABIN_BITS = 512
AUTH_WINDOW_SECONDS = 300
SCHEMES = ("rsa", "elgamal", "rabin")
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
MAX_TEXT_BYTES = 16 * 1024
# Screenshots and ordinary docs; not a file-share for movies.
MAX_FILE_BYTES = 32 * 1024 * 1024
# Inner JSON stores the file as base64 (~4/3) plus names.
MAX_PLAINTEXT_BYTES = MAX_FILE_BYTES * 4 // 3 + 256 * 1024
# AES-GCM ciphertext of that inner JSON, then base64 again on the wire.
MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES * 4 // 3 + 2 * 1024 * 1024
MAX_GROUP_MEMBERS = 32
# SimpleX XFTP-style large files: opaque fixed-size chunks on the relay,
# keys only inside the sealed chat description. 4 GB cap.
XFTP_CHUNK_SIZES = (256 * 1024, 1024 * 1024, 4 * 1024 * 1024)
MAX_XFTP_BYTES = 4 * 1024 * 1024 * 1024
XFTP_TTL_SECONDS = 48 * 3600
XFTP_TAG_LEN = 16
XFTP_PUSH_SLICE = 256 * 1024
XFTP_FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
XFTP_SECRET_RE = re.compile(r"^[0-9a-f]{64}$")
CALL_EVENTS = ("offer", "answer", "ice", "hangup", "reject")
GROUP_EVENTS = ("message", "invite", "update", "file", "xftp")
MIME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,40}/[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]{0,40}$")


def generate_user_keys(rsa_bits=DEFAULT_RSA_BITS, elgamal_bits=DEFAULT_ELGAMAL_BITS, rabin_bits=DEFAULT_RABIN_BITS, rsa_only=False):
    rsa_priv, rsa_pub = generate_rsa_keys(rsa_bits)
    keys = {'rsa': {'priv': rsa_priv.decode(), 'pub': rsa_pub.decode()}}
    if rsa_only:
        return keys
    with ThreadPoolExecutor(max_workers=2) as pool:
        el_f = pool.submit(generate_elgamal_keys, elgamal_bits)
        rab_f = pool.submit(generate_rabin_keys, rabin_bits)
        el_pub, el_priv = el_f.result()
        r_n, r_p, r_q = rab_f.result()
    keys['elgamal'] = {'pub': el_pub, 'priv': el_priv}
    keys['rabin'] = {'n': r_n, 'p': r_p, 'q': r_q}
    return keys


def public_keys_from(keys):
    out = {'rsa': keys['rsa']['pub']}
    if 'elgamal' in keys:
        out['elgamal'] = keys['elgamal']['pub']
    if 'rabin' in keys:
        out['rabin'] = {'n': keys['rabin']['n']}
    return out


def normalize_username(name):
    name = (name or "").strip().lstrip("@").lower()
    if not USERNAME_RE.fullmatch(name):
        raise ValueError("Username must be 3–32 characters, start with a letter, and use only a-z, 0-9, _")
    return name


def identity_transcript(username, public_keys):
    return json.dumps(
        {"public_keys": public_keys, "username": username},
        sort_keys=True,
        separators=(',', ':'),
    ).encode()


def sign_identity_bundle(username, keys):
    username = normalize_username(username)
    pubs = public_keys_from(keys)
    signature = sign_message(identity_transcript(username, pubs), keys['rsa']['priv'].encode())
    return pubs, signature


def verify_identity_bundle(username, public_keys, signature):
    try:
        username = normalize_username(username)
    except ValueError:
        return False
    if not isinstance(public_keys, dict) or "rsa" not in public_keys:
        return False
    if not isinstance(public_keys.get("rsa"), str) or "BEGIN PUBLIC KEY" not in public_keys["rsa"]:
        return False
    return verify_signature(
        identity_transcript(username, public_keys),
        signature,
        public_keys["rsa"].encode(),
    )


def sanitize_filename(name):
    name = str(name or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = re.sub(r"[^\w.\-+() ]+", "_", name)
    name = name.strip(" .")
    if not name or name in (".", ".."):
        return "attachment"
    return name[:128]


def sanitize_mime(mime):
    mime = (mime or "application/octet-stream").strip()[:80]
    if not MIME_RE.fullmatch(mime):
        return "application/octet-stream"
    return mime


def file_fields(name, data, mime=""):
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("File data must be bytes")
    data = bytes(data)
    if not data:
        raise ValueError("Empty file")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"Attachment too large (max {MAX_FILE_BYTES // (1024 * 1024)} MB)")
    name = sanitize_filename(name)
    mime = sanitize_mime(mime)
    digest = SHA256.new(data).hexdigest()
    return {
        "name": name,
        "mime": mime,
        "size": len(data),
        "sha256": digest,
        "data": base64.b64encode(data).decode(),
    }


def _parse_file_fields(data):
    if not isinstance(data, dict):
        return None
    raw_b64 = data.get("data")
    if not isinstance(raw_b64, str) or len(raw_b64) > MAX_FILE_BYTES * 2:
        return None
    try:
        raw = base64.b64decode(raw_b64, validate=True)
    except (ValueError, TypeError):
        return None
    size = data.get("size")
    digest = data.get("sha256")
    if type(size) is not int or size != len(raw) or size > MAX_FILE_BYTES:
        return None
    if not isinstance(digest, str) or SHA256.new(raw).hexdigest() != digest:
        return None
    return {
        "name": sanitize_filename(data.get("name")),
        "mime": sanitize_mime(data.get("mime")),
        "size": size,
        "sha256": digest,
        "data": raw,
    }


def validate_sdp(sdp):
    """Audio-only SDP whose DTLS fingerprint is SHA-256. Relay never sees this; we still
    refuse a 'trusted' peer stuffing video or a data channel into the call."""
    if not isinstance(sdp, str) or not sdp.strip() or len(sdp) > 24000 or "\x00" in sdp:
        return False
    lower = sdp.lower()
    if "m=video" in lower or "m=application" in lower:
        return False
    if not re.search(r"(?m)^m=audio\s", sdp, re.IGNORECASE):
        return False
    if "a=fingerprint:sha-256" not in lower:
        return False
    return True


def sanitize_ice(candidate):
    if not isinstance(candidate, dict):
        return None
    cand = candidate.get("candidate")
    if not isinstance(cand, str) or not cand or len(cand) > 2000 or "\x00" in cand:
        return None
    if not cand.lstrip().lower().startswith("candidate:"):
        return None
    mid = candidate.get("sdpMid")
    index = candidate.get("sdpMLineIndex")
    out = {
        "candidate": cand,
        "sdpMid": mid if isinstance(mid, str) and len(mid) <= 64 and "\x00" not in mid else None,
        "sdpMLineIndex": index if type(index) is int and 0 <= index <= 32 else None,
    }
    ufrag = candidate.get("usernameFragment")
    if isinstance(ufrag, str) and 1 <= len(ufrag) <= 256 and "\x00" not in ufrag:
        out["usernameFragment"] = ufrag
    return out


def pack_direct(text):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Message cannot be empty")
    if len(text.encode()) > MAX_TEXT_BYTES:
        raise ValueError("Message too long")
    return json.dumps({"v": 1, "kind": "direct", "text": text}, separators=(',', ':'))


def pack_file(name, data, mime=""):
    body = {"v": 1, "kind": "file"}
    body.update(file_fields(name, data, mime))
    return json.dumps(body, separators=(',', ':'))


def choose_xftp_chunk_size(size):
    size = int(size)
    if size > 64 * 1024 * 1024:
        return XFTP_CHUNK_SIZES[2]
    if size > 4 * 1024 * 1024:
        return XFTP_CHUNK_SIZES[1]
    return XFTP_CHUNK_SIZES[0]


def xftp_chunk_count(size, chunk_size):
    if size <= 0:
        return 1
    return (int(size) + int(chunk_size) - 1) // int(chunk_size)


def xftp_nonce(key, index):
    return SHA256.new(key + b"|xftp|" + int(index).to_bytes(8, "big")).digest()[:16]


def xftp_seal_chunk(plain, key, index):
    from Crypto.Cipher import AES
    from aes_utils import AES_KEY_LEN, _GCM_TAG_LEN
    if len(key) != AES_KEY_LEN:
        raise ValueError("Bad file key")
    cipher = AES.new(key, AES.MODE_GCM, nonce=xftp_nonce(key, index))
    ct, tag = cipher.encrypt_and_digest(plain)
    if len(tag) != _GCM_TAG_LEN:
        raise ValueError("Bad GCM tag")
    return tag + ct


def xftp_open_chunk(blob, key, index):
    from Crypto.Cipher import AES
    from aes_utils import AES_KEY_LEN, _GCM_TAG_LEN
    if len(key) != AES_KEY_LEN or len(blob) < _GCM_TAG_LEN:
        raise ValueError("Bad chunk")
    tag, ct = blob[:_GCM_TAG_LEN], blob[_GCM_TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=xftp_nonce(key, index))
    return cipher.decrypt_and_verify(ct, tag)


def _xftp_offer_fields(data):
    if not isinstance(data, dict):
        return None
    name = sanitize_filename(data.get("name"))
    mime = sanitize_mime(data.get("mime"))
    size = data.get("size")
    chunk_size = data.get("chunk_size")
    n_chunks = data.get("n_chunks")
    sha256 = data.get("sha256")
    file_id = data.get("file_id")
    get_secret = data.get("get_secret")
    key = data.get("key")
    expires = data.get("expires")
    if type(size) is not int or size <= 0 or size > MAX_XFTP_BYTES:
        return None
    if chunk_size not in XFTP_CHUNK_SIZES:
        return None
    if type(n_chunks) is not int or n_chunks != xftp_chunk_count(size, chunk_size):
        return None
    if n_chunks > MAX_XFTP_BYTES // XFTP_CHUNK_SIZES[0]:
        return None
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return None
    if not isinstance(file_id, str) or not XFTP_FILE_ID_RE.fullmatch(file_id):
        return None
    if not isinstance(get_secret, str) or not XFTP_SECRET_RE.fullmatch(get_secret):
        return None
    if not isinstance(key, str) or not XFTP_SECRET_RE.fullmatch(key):
        return None
    if type(expires) is not int or expires <= 0:
        return None
    return {
        "name": name,
        "mime": mime,
        "size": size,
        "chunk_size": chunk_size,
        "n_chunks": n_chunks,
        "sha256": sha256,
        "file_id": file_id,
        "get_secret": get_secret,
        "key": key,
        "expires": expires,
    }


def pack_xftp(offer):
    parsed = _xftp_offer_fields(offer)
    if not parsed:
        raise ValueError("Invalid large-file description")
    body = {"v": 1, "kind": "xftp"}
    body.update(parsed)
    packed = json.dumps(body, separators=(",", ":"))
    if len(packed.encode()) > MAX_TEXT_BYTES:
        raise ValueError("Large-file description too big")
    return packed


def pack_group(group_id, title, members, text, event="message", file=None, xftp=None):
    if event not in GROUP_EVENTS:
        raise ValueError("Invalid group event")
    if not isinstance(group_id, str) or len(group_id) != 64:
        raise ValueError("Invalid group id")
    members = [normalize_username(m) for m in members]
    if len(members) < 2 or len(members) > MAX_GROUP_MEMBERS:
        raise ValueError(f"Groups must have 2–{MAX_GROUP_MEMBERS} members")
    if len(set(members)) != len(members):
        raise ValueError("Duplicate group members")
    title = (title or "Group").strip()[:40]
    if not title:
        title = "Group"
    body = {
        "v": 1,
        "kind": "group",
        "event": event,
        "group_id": group_id,
        "title": title,
        "members": members,
        "text": text or "",
    }
    if file is not None:
        if event != "file":
            raise ValueError("File payload requires event=file")
        body["file"] = file_fields(file["name"], file["data"], file.get("mime", ""))
        if not body["text"]:
            body["text"] = body["file"]["name"]
    if xftp is not None:
        if event != "xftp":
            raise ValueError("XFTP payload requires event=xftp")
        parsed = _xftp_offer_fields(xftp)
        if not parsed:
            raise ValueError("Invalid large-file description")
        body["xftp"] = parsed
        if not body["text"]:
            body["text"] = parsed["name"]
    return json.dumps(body, separators=(',', ':'))


def new_call_id():
    return get_random_bytes(16).hex()


def pack_call(event, call_id, sdp=None, candidate=None):
    if event not in CALL_EVENTS:
        raise ValueError("Invalid call event")
    if not isinstance(call_id, str) or not re.fullmatch(r"[0-9a-f]{32}", call_id):
        raise ValueError("Invalid call id")
    body = {"v": 1, "kind": "call", "event": event, "call_id": call_id}
    if event in ("offer", "answer"):
        if not validate_sdp(sdp):
            raise ValueError("Invalid SDP")
        body["sdp"] = sdp
    if event == "ice":
        cleaned = sanitize_ice(candidate)
        if not cleaned:
            raise ValueError("Invalid ICE candidate")
        body["candidate"] = cleaned
    packed = json.dumps(body, separators=(',', ':'))
    if len(packed.encode()) > MAX_TEXT_BYTES:
        raise ValueError("Call signal too large")
    return packed


def parse_inner(plaintext):
    try:
        data = json.loads(plaintext)
    except (TypeError, json.JSONDecodeError):
        return {"kind": "direct", "text": str(plaintext)}
    if not isinstance(data, dict) or data.get("v") != 1:
        return {"kind": "direct", "text": plaintext}
    kind = data.get("kind")
    if kind == "direct":
        text = data.get("text")
        if not isinstance(text, str):
            return None
        return {"kind": "direct", "text": text}
    if kind == "file":
        parsed = _parse_file_fields(data)
        if not parsed:
            return None
        parsed["kind"] = "file"
        return parsed
    if kind == "xftp":
        parsed = _xftp_offer_fields(data)
        if not parsed:
            return None
        parsed["kind"] = "xftp"
        return parsed
    if kind == "call":
        event = data.get("event")
        call_id = data.get("call_id")
        if event not in CALL_EVENTS:
            return None
        if not isinstance(call_id, str) or not re.fullmatch(r"[0-9a-f]{32}", call_id):
            return None
        out = {"kind": "call", "event": event, "call_id": call_id}
        if event in ("offer", "answer"):
            sdp = data.get("sdp")
            if not validate_sdp(sdp):
                return None
            out["sdp"] = sdp
        if event == "ice":
            cleaned = sanitize_ice(data.get("candidate"))
            if not cleaned:
                return None
            out["candidate"] = cleaned
        return out
    if kind == "group":
        try:
            members = [normalize_username(m) for m in data.get("members", [])]
        except (ValueError, TypeError):
            return None
        group_id = data.get("group_id")
        event = data.get("event", "message")
        if not isinstance(group_id, str) or len(group_id) != 64:
            return None
        if event not in GROUP_EVENTS:
            return None
        if not isinstance(data.get("text", ""), str):
            return None
        out = {
            "kind": "group",
            "event": event,
            "group_id": group_id,
            "title": str(data.get("title") or "Group")[:40],
            "members": members,
            "text": data.get("text") or "",
        }
        if event == "file":
            parsed = _parse_file_fields(data.get("file"))
            if not parsed:
                return None
            out["file"] = parsed
        if event == "xftp":
            parsed = _xftp_offer_fields(data.get("xftp"))
            if not parsed:
                return None
            out["xftp"] = parsed
        return out
    return None


def new_group_id():
    return get_random_bytes(32).hex()


def public_fingerprint(public_keys):
    blob = json.dumps(public_keys, sort_keys=True, separators=(',', ':')).encode()
    digest = SHA256.new(blob).hexdigest()
    return ':'.join(digest[i:i + 2] for i in range(0, 16, 2))


def canonical_transcript(sender, recipient, scheme, timestamp, nonce, ciphertext, aes_key_enc):
    return json.dumps({
        "aes_key_enc": aes_key_enc,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "recipient": recipient,
        "scheme": scheme,
        "sender": sender,
        "timestamp": timestamp,
    }, sort_keys=True, separators=(',', ':')).encode()


def wrap_aes_key(aes_key, recipient_pubs, scheme):
    if scheme == 'rsa':
        return rsa_encrypt(aes_key, recipient_pubs['rsa'].encode())
    if scheme == 'elgamal':
        return elgamal_encrypt(aes_key, recipient_pubs['elgamal'])
    if scheme == 'rabin':
        return rabin_encrypt(aes_key, recipient_pubs['rabin']['n'])
    raise ValueError(f"Unknown scheme: {scheme}")


def unwrap_aes_key(wrapped, recipient_keys, scheme, ciphertext=None):
    if scheme == 'rsa':
        return rsa_decrypt(wrapped, recipient_keys['rsa']['priv'].encode())
    if scheme == 'elgamal':
        return elgamal_decrypt(
            wrapped,
            recipient_keys['elgamal']['priv'],
            recipient_keys['elgamal']['pub']['p'],
            out_len=AES_KEY_LEN
        )
    if scheme == 'rabin':
        roots = rabin_decrypt(wrapped, recipient_keys['rabin']['p'], recipient_keys['rabin']['q'])
        key, _ = recover_rabin_aes_key_and_decrypt(ciphertext, roots)
        return key
    raise ValueError(f"Unknown scheme: {scheme}")


def hybrid_encrypt(plaintext, sender_keys, recipient_pubs, scheme, sender, recipient):
    if scheme not in SCHEMES:
        raise ValueError(f"Unknown scheme: {scheme}")
    sender = normalize_username(sender)
    recipient = normalize_username(recipient)
    if isinstance(plaintext, str):
        raw = plaintext.encode()
    else:
        raw = plaintext
        plaintext = plaintext.decode()
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise ValueError("Message too long")
    aes_key = get_random_bytes(AES_KEY_LEN)
    ciphertext = aes_encrypt(plaintext, aes_key)
    wrapped = wrap_aes_key(aes_key, recipient_pubs, scheme)
    timestamp = int(time.time())
    nonce = get_random_bytes(16).hex()
    transcript = canonical_transcript(sender, recipient, scheme, timestamp, nonce, ciphertext, wrapped)
    signature = sign_message(transcript, sender_keys['rsa']['priv'].encode())
    return {
        "ciphertext": ciphertext,
        "aes_key_enc": wrapped,
        "scheme": scheme,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
        "sender": sender,
        "recipient": recipient,
    }


def hybrid_decrypt(payload, recipient_keys, sender_rsa_pub, expected_recipient):
    """Verify the signature first, then decrypt (encrypt-then-sign + AES-GCM)."""
    required = ("ciphertext", "aes_key_enc", "scheme", "timestamp", "nonce", "signature", "sender", "recipient")
    if any(k not in payload for k in required):
        return None, False, "missing fields"

    try:
        expected_recipient = normalize_username(expected_recipient)
        payload_recipient = normalize_username(payload["recipient"])
        payload_sender = normalize_username(payload["sender"])
    except ValueError:
        return None, False, "bad username"

    if payload_recipient != expected_recipient:
        return None, False, "wrong recipient"

    transcript = canonical_transcript(
        payload["sender"],
        payload["recipient"],
        payload["scheme"],
        payload["timestamp"],
        payload["nonce"],
        payload["ciphertext"],
        payload["aes_key_enc"],
    )
    if not verify_signature(transcript, payload["signature"], sender_rsa_pub):
        return None, False, "bad signature"

    try:
        aes_key = unwrap_aes_key(
            payload["aes_key_enc"],
            recipient_keys,
            payload["scheme"],
            ciphertext=payload["ciphertext"],
        )
        if aes_key is None:
            return None, False, "key unwrap failed"
        plaintext = aes_decrypt(payload["ciphertext"], aes_key)
    except Exception as e:
        return None, False, str(e)

    return plaintext, True, "ok"


def inbox_auth_payload(username, rsa_priv_pem):
    username = normalize_username(username)
    timestamp = int(time.time())
    nonce = get_random_bytes(16).hex()
    signature = sign_message(f"{username}|{timestamp}|{nonce}".encode(), rsa_priv_pem.encode())
    return {
        "username": username,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
    }


def verify_inbox_auth(username, timestamp, nonce, signature, rsa_pub_pem):
    try:
        username = normalize_username(username)
    except ValueError:
        return False
    now = int(time.time())
    if abs(now - int(timestamp)) > AUTH_WINDOW_SECONDS:
        return False
    return verify_signature(
        f"{username}|{timestamp}|{nonce}".encode(),
        signature,
        rsa_pub_pem.encode() if isinstance(rsa_pub_pem, str) else rsa_pub_pem,
    )


def verify_send_payload(sender, recipient, payload, sender_rsa_pub):
    try:
        sender = normalize_username(sender)
        recipient = normalize_username(recipient)
        payload_sender = normalize_username(payload.get("sender"))
        payload_recipient = normalize_username(payload.get("recipient"))
    except ValueError:
        return False, "bad username"
    if payload_sender != sender or payload_recipient != recipient:
        return False, "sender/recipient mismatch"
    if abs(int(time.time()) - int(payload.get("timestamp", 0))) > AUTH_WINDOW_SECONDS:
        return False, "stale timestamp"
    transcript = canonical_transcript(
        payload["sender"],
        payload["recipient"],
        payload["scheme"],
        payload["timestamp"],
        payload["nonce"],
        payload["ciphertext"],
        payload["aes_key_enc"],
    )
    if not verify_signature(transcript, payload["signature"], sender_rsa_pub):
        return False, "bad signature"
    return True, "ok"
