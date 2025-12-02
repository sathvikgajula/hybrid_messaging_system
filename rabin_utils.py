from Crypto.Util.number import getPrime, inverse

def generate_rabin_keys(bits):
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits)
        if q % 4 == 3:
            break
    return p * q, p, q

def rabin_encrypt(message, n):
    m = int.from_bytes(message, byteorder='big')
    return pow(m, 2, n)

def rabin_decrypt(ciphertext, p, q):

    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    yp = inverse(p, q)
    yq = inverse(q, p)

    # Four possible roots
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    return [r1, r2, r3, r4]

from aes_utils import aes_decrypt

def recover_rabin_aes_key_and_decrypt(ciphertext, roots):
    for root in roots:
        candidate_bytes = root.to_bytes((root.bit_length() + 7) // 8, byteorder='big')

        if len(candidate_bytes) < 16:
            candidate_bytes = (b'\x00' * (16 - len(candidate_bytes))) + candidate_bytes
        elif len(candidate_bytes) > 16:
            candidate_bytes = candidate_bytes[-16:]

        try:
            plaintext = aes_decrypt(ciphertext, candidate_bytes)
            return candidate_bytes, plaintext
        except Exception:
            continue
    return None, None
