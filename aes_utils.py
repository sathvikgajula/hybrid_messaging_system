from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

AES_KEY_LEN = 32  # AES-256
_GCM_NONCE_LEN = 16
_GCM_TAG_LEN = 16


def aes_encrypt(message, key):
    if len(key) != AES_KEY_LEN:
        raise ValueError(f"AES key must be {AES_KEY_LEN} bytes (AES-256)")
    if isinstance(message, str):
        message = message.encode()
    nonce = get_random_bytes(_GCM_NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(message)
    return base64.b64encode(nonce + tag + ct).decode()


def aes_decrypt_bytes(ciphertext_b64, key):
    if len(key) != AES_KEY_LEN:
        raise ValueError(f"AES key must be {AES_KEY_LEN} bytes (AES-256)")
    raw = base64.b64decode(ciphertext_b64)
    nonce = raw[:_GCM_NONCE_LEN]
    tag = raw[_GCM_NONCE_LEN:_GCM_NONCE_LEN + _GCM_TAG_LEN]
    ct = raw[_GCM_NONCE_LEN + _GCM_TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def aes_decrypt(ciphertext_b64, key):
    return aes_decrypt_bytes(ciphertext_b64, key).decode()
