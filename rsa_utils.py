from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# Project floor for number-theoretic sizes. PyCryptodome still requires RSA >= 1024.
MIN_BITS = 256
MIN_RSA_BITS = 1024

def generate_rsa_keys(key_size=2048):
    if key_size < MIN_BITS:
        raise ValueError(f"RSA key size must be at least {MIN_BITS} bits (got {key_size})")
    # PyCryptodome will not generate RSA keys below 1024 bits
    if key_size < MIN_RSA_BITS:
        raise ValueError(f"RSA key size must be at least {MIN_RSA_BITS} bits (got {key_size})")
    key = RSA.generate(key_size)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(message, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return base64.b64encode(cipher_rsa.encrypt(message)).decode()

def rsa_decrypt(ciphertext_b64, private_key):
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.decrypt(base64.b64decode(ciphertext_b64))

def sign_message(message: bytes, private_key: bytes):
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(message: bytes, signature_b64: str, public_key: bytes):
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False