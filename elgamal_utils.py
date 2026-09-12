from Crypto.Util.number import getPrime, inverse, isPrime
from Crypto.Random.random import randint

from aes_utils import AES_KEY_LEN

# p must be bigger than a 256-bit AES key, so 256-bit moduli are not enough.
MIN_BITS = 512


def _require_min_bits(bits, label):
    if bits < MIN_BITS:
        raise ValueError(f"{label} must be at least {MIN_BITS} bits (got {bits})")


def _rand_in_subgroup(q):
    """Random exponent in 1..q-1, at least 256 bits when q is large enough."""
    min_bits = min(256, q.bit_length() - 1)
    lo = 1 << (min_bits - 1)
    if lo >= q:
        return randint(1, q - 1)
    return randint(lo, q - 1)


def _safe_prime(bits):
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and isPrime(p):
            return p, q


def generate_elgamal_keys(bits=MIN_BITS):
    """Schnorr-group ElGamal: p = 2q+1, g has order q."""
    _require_min_bits(bits, "ElGamal prime")
    p, q = _safe_prime(bits)
    while True:
        h = randint(2, p - 2)
        g = pow(h, 2, p)
        if g not in (0, 1):
            break
    x = _rand_in_subgroup(q)
    y = pow(g, x, p)
    return {'p': p, 'q': q, 'g': g, 'y': y}, x


def elgamal_encrypt(message, pubkey):
    p, g, y = pubkey['p'], pubkey['g'], pubkey['y']
    q = pubkey.get('q', (p - 1) // 2)
    if isinstance(message, str):
        message = message.encode()

    m = int.from_bytes(message, byteorder='big')
    if m >= p:
        raise ValueError("Message is too large for this ElGamal modulus.")

    k = _rand_in_subgroup(q)
    a = pow(g, k, p)
    b = (pow(y, k, p) * m) % p
    return [a, b]


def elgamal_decrypt(ciphertext, x, p, out_len=AES_KEY_LEN):
    if ciphertext and isinstance(ciphertext[0], (list, tuple)):
        return bytes([(b * inverse(pow(a, x, p), p)) % p for a, b in ciphertext])

    a, b = ciphertext[0], ciphertext[1]
    m = (b * inverse(pow(a, x, p), p)) % p
    return m.to_bytes(out_len, byteorder='big')
