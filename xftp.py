"""Opaque XFTP-style chunk store. The relay never sees filenames, keys, or plaintext."""
import hashlib
import hmac
import json
import os
import threading
import time

import protocol

_lock = threading.Lock()
_ID_RE = protocol.XFTP_FILE_ID_RE
_SECRET_RE = protocol.XFTP_SECRET_RE
MAX_STORE_BYTES = 16 * 1024 * 1024 * 1024
MAX_USER_BYTES = 8 * 1024 * 1024 * 1024
MAX_CHUNK_WIRE = protocol.XFTP_CHUNK_SIZES[-1] + protocol.XFTP_TAG_LEN


def _root():
    path = os.environ.get("SEALED_XFTP_DIR") or os.path.join(
        os.path.expanduser("~"), ".sealed_relay", "xftp"
    )
    os.makedirs(path, exist_ok=True)
    return path


def _meta_path(file_id):
    return os.path.join(_root(), file_id + ".json")


def _chunk_path(file_id, index):
    return os.path.join(_root(), file_id, f"{int(index):08d}")


def _hash_secret(secret):
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def _load_meta(file_id):
    path = _meta_path(file_id)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_meta(file_id, meta):
    path = _meta_path(file_id)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(meta, f, separators=(",", ":"))
    os.replace(tmp, path)


def _purge_file(file_id):
    folder = os.path.join(_root(), file_id)
    if os.path.isdir(folder):
        for name in os.listdir(folder):
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass
        try:
            os.rmdir(folder)
        except OSError:
            pass
    try:
        os.unlink(_meta_path(file_id))
    except OSError:
        pass


def expire_old():
    now = int(time.time())
    root = _root()
    for name in os.listdir(root):
        if not name.endswith(".json"):
            continue
        file_id = name[:-5]
        if not _ID_RE.fullmatch(file_id):
            continue
        try:
            meta = _load_meta(file_id)
        except (OSError, json.JSONDecodeError):
            continue
        if not meta or int(meta.get("expires") or 0) < now:
            _purge_file(file_id)


def store_bytes():
    total = 0
    root = _root()
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total


def _reserved_bytes(owner=None):
    total = 0
    root = _root()
    for name in os.listdir(root):
        if not name.endswith(".json"):
            continue
        file_id = name[:-5]
        if not _ID_RE.fullmatch(file_id):
            continue
        try:
            meta = _load_meta(file_id)
        except (OSError, json.JSONDecodeError):
            continue
        if not meta:
            continue
        if owner is not None and meta.get("owner") != owner:
            continue
        total += int(meta.get("n_chunks") or 0) * int(meta.get("wire_size") or 0)
    return total


def create(chunk_size, n_chunks, owner=""):
    with _lock:
        expire_old()
        if chunk_size not in protocol.XFTP_CHUNK_SIZES:
            raise ValueError("Invalid chunk size")
        if type(n_chunks) is not int or n_chunks < 1:
            raise ValueError("Invalid chunk count")
        if n_chunks > protocol.MAX_XFTP_BYTES // protocol.XFTP_CHUNK_SIZES[0]:
            raise ValueError("Too many chunks")
        wire = n_chunks * (chunk_size + protocol.XFTP_TAG_LEN)
        if _reserved_bytes() + wire > MAX_STORE_BYTES:
            raise ValueError("File relay is full")
        if owner and _reserved_bytes(owner) + wire > MAX_USER_BYTES:
            raise ValueError("Too much queued file data for this account")
        file_id = os.urandom(16).hex()
        put_secret = os.urandom(32).hex()
        get_secret = os.urandom(32).hex()
        now = int(time.time())
        meta = {
            "file_id": file_id,
            "owner": owner or "",
            "put_hash": _hash_secret(put_secret),
            "get_hash": _hash_secret(get_secret),
            "chunk_size": chunk_size,
            "n_chunks": n_chunks,
            "wire_size": chunk_size + protocol.XFTP_TAG_LEN,
            "expires": now + protocol.XFTP_TTL_SECONDS,
            "ready": [False] * n_chunks,
            "created": now,
        }
        os.makedirs(os.path.join(_root(), file_id), exist_ok=True)
        _save_meta(file_id, meta)
        return {
            "file_id": file_id,
            "put_secret": put_secret,
            "get_secret": get_secret,
            "chunk_size": chunk_size,
            "n_chunks": n_chunks,
            "expires": meta["expires"],
            "wire_size": meta["wire_size"],
        }


def _check_secret(meta, secret, kind):
    if not isinstance(secret, str) or not _SECRET_RE.fullmatch(secret):
        return False
    expected = meta.get("put_hash" if kind == "put" else "get_hash")
    return isinstance(expected, str) and hmac.compare_digest(_hash_secret(secret), expected)


def put_chunk(file_id, index, put_secret, data):
    if not isinstance(file_id, str) or not _ID_RE.fullmatch(file_id):
        raise ValueError("Unknown file")
    with _lock:
        expire_old()
        meta = _load_meta(file_id)
        if not meta:
            raise FileNotFoundError("Unknown or expired file")
        if int(meta.get("expires") or 0) < int(time.time()):
            _purge_file(file_id)
            raise FileNotFoundError("Unknown or expired file")
        if not _check_secret(meta, put_secret, "put"):
            raise PermissionError("Bad upload token")
        if type(index) is not int or not (0 <= index < meta["n_chunks"]):
            raise ValueError("Bad chunk index")
        if not isinstance(data, (bytes, bytearray)) or len(data) != meta["wire_size"]:
            raise ValueError("Chunk must be exactly %s bytes" % meta["wire_size"])
        path = _chunk_path(file_id, index)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        meta["ready"][index] = True
        _save_meta(file_id, meta)
        return {"ok": True, "index": index}


def get_chunk(file_id, index, get_secret):
    if not isinstance(file_id, str) or not _ID_RE.fullmatch(file_id):
        raise FileNotFoundError("Unknown or expired file")
    with _lock:
        meta = _load_meta(file_id)
        if not meta:
            raise FileNotFoundError("Unknown or expired file")
        if int(meta.get("expires") or 0) < int(time.time()):
            _purge_file(file_id)
            raise FileNotFoundError("Unknown or expired file")
        if not _check_secret(meta, get_secret, "get"):
            raise PermissionError("Bad download token")
        if type(index) is not int or not (0 <= index < meta["n_chunks"]):
            raise ValueError("Bad chunk index")
        if not meta["ready"][index]:
            raise FileNotFoundError("Chunk is not on the relay yet")
        path = _chunk_path(file_id, index)
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != meta["wire_size"]:
        raise FileNotFoundError("Corrupt chunk")
    return data


def delete_file(file_id, put_secret):
    if not isinstance(file_id, str) or not _ID_RE.fullmatch(file_id):
        return
    with _lock:
        meta = _load_meta(file_id)
        if not meta:
            return
        if not _check_secret(meta, put_secret, "put"):
            raise PermissionError("Bad upload token")
        _purge_file(file_id)
