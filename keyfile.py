"""Passphrase-encrypted local key files (AES-256-GCM + PBKDF2)."""
import json
import os
import getpass
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from aes_utils import AES_KEY_LEN

KDF_ITERATIONS = 200_000
ENV_PASSPHRASE = "HYBRID_PASSPHRASE"


def prompt_passphrase(confirm=False):
    env = os.environ.get(ENV_PASSPHRASE)
    if env:
        return env
    pw = getpass.getpass("Keyfile passphrase: ")
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            raise SystemExit("Passphrases do not match.")
    if not pw:
        raise SystemExit("Passphrase cannot be empty.")
    return pw


def _derive_key(passphrase, salt, iterations=KDF_ITERATIONS):
    return PBKDF2(passphrase, salt, dkLen=AES_KEY_LEN, count=iterations, hmac_hash_module=SHA256)


def save_keyfile(path, username, keys, passphrase, state=None):
    salt = get_random_bytes(16)
    nonce = get_random_bytes(16)
    key = _derive_key(passphrase, salt)
    plaintext = json.dumps({
        'username': username,
        'keys': keys,
        'state': state or {},
    }).encode()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    blob = {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct + tag).decode(),
    }
    with open(path, 'w') as f:
        json.dump(blob, f)


def _decrypt_blob(data, passphrase):
    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    raw = base64.b64decode(data["ciphertext"])
    ct, tag = raw[:-16], raw[-16:]
    key = _derive_key(passphrase, salt, iterations=int(data.get("iterations", KDF_ITERATIONS)))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ct, tag)
    return json.loads(plaintext.decode())


def load_keyfile(path, passphrase):
    with open(path, 'r') as f:
        data = json.load(f)

    if data.get("kdf") == "pbkdf2-sha256":
        inner = _decrypt_blob(data, passphrase)
        return inner["username"], inner["keys"], True, inner.get("state") or {}

    if "username" in data and "keys" in data:
        return data["username"], data["keys"], False, data.get("state") or {}

    raise ValueError("Unrecognized keyfile format.")
