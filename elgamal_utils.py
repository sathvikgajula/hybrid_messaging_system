import random
from Crypto.Util.number import getPrime, inverse

def generate_elgamal_keys(bits):
    p = getPrime(bits)
    g = random.randint(2, p-2)
    x = random.randint(1, p-2)
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'y': y}, x

def elgamal_encrypt(message, pubkey):
    p, g, y = pubkey['p'], pubkey['g'], pubkey['y']
    k = random.randint(1, p-2)
    a = pow(g, k, p)
    s = pow(y, k, p)
    
    # Ensure we are iterating over bytes, not string characters
    if isinstance(message, str):
        message = message.encode()
        
    return [(a, (s * b) % p) for b in message]

def elgamal_decrypt(ciphertext, x, p):
    # Fixed: Removed .decode() to support raw binary data (like AES keys)
    return bytes([(b * inverse(pow(a, x, p), p)) % p for a, b in ciphertext])