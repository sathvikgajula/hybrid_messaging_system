import timeit
import aes_utils
import rsa_utils
import elgamal_utils
import rabin_utils
from Crypto.Random import get_random_bytes

# 1. Setup Phase (One-time cost)
print("⚙️  Generating 2048-bit RSA, 256-bit ElGamal, and 256-bit Rabin keys...")
rsa_priv, rsa_pub = rsa_utils.generate_rsa_keys(2048)
el_pub, el_priv = elgamal_utils.generate_elgamal_keys(256)
r_n, r_p, r_q = rabin_utils.generate_rabin_keys(256)

# We use a random 16-byte AES key for the payload
aes_key = get_random_bytes(16)

# 2. Define Benchmarks
def bench_rsa():
    # Simulate full KEM cycle: Encrypt AES key -> Decrypt AES key
    enc = rsa_utils.rsa_encrypt(aes_key, rsa_pub)
    rsa_utils.rsa_decrypt(enc, rsa_priv)

def bench_elgamal():
    # ElGamal encryption + decryption
    enc = elgamal_utils.elgamal_encrypt(aes_key, el_pub)
    elgamal_utils.elgamal_decrypt(enc, el_priv, el_pub['p'])

def bench_rabin():
    # Rabin encryption + decryption (getting all 4 roots)
    enc = rabin_utils.rabin_encrypt(aes_key, r_n)
    # We benchmark the raw math of finding roots, as this is the heavy lifting
    rabin_utils.rabin_decrypt(enc, r_p, r_q)

# 3. Execute
print("\n🚀 Starting Benchmarks (100 iterations each)...")
ITERATIONS = 100

t_rsa = timeit.timeit(bench_rsa, number=ITERATIONS)
t_elg = timeit.timeit(bench_elgamal, number=ITERATIONS)
t_rab = timeit.timeit(bench_rabin, number=ITERATIONS)

# 4. Report
print("-" * 40)
print(f"RSA (2048-bit):     {t_rsa:.4f} seconds")
print(f"ElGamal (256-bit):  {t_elg:.4f} seconds")
print(f"Rabin (256-bit):    {t_rab:.4f} seconds")
print("-" * 40)

fastest = min(t_rsa, t_elg, t_rab)
if fastest == t_rab:
    print("🏆 Winner: Rabin is the fastest algorithm.")
elif fastest == t_rsa:
    print("🏆 Winner: RSA is the fastest algorithm.")
else:
    print("🏆 Winner: ElGamal is the fastest algorithm.")