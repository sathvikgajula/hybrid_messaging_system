import timeit
from Crypto.Random import get_random_bytes

import rsa_utils
import elgamal_utils
import rabin_utils
from aes_utils import AES_KEY_LEN

print("Generating 2048-bit RSA, 1024-bit safe-prime ElGamal, and 1024-bit Rabin keys...")
print("(ElGamal safe-prime search can take a little while)")
rsa_priv, rsa_pub = rsa_utils.generate_rsa_keys(2048)
el_pub, el_priv = elgamal_utils.generate_elgamal_keys(1024)
r_n, r_p, r_q = rabin_utils.generate_rabin_keys(1024)

aes_key = get_random_bytes(AES_KEY_LEN)


def bench_rsa():
    enc = rsa_utils.rsa_encrypt(aes_key, rsa_pub)
    rsa_utils.rsa_decrypt(enc, rsa_priv)


def bench_elgamal():
    enc = elgamal_utils.elgamal_encrypt(aes_key, el_pub)
    elgamal_utils.elgamal_decrypt(enc, el_priv, el_pub['p'])


def bench_rabin():
    enc = rabin_utils.rabin_encrypt(aes_key, r_n)
    rabin_utils.rabin_decrypt(enc, r_p, r_q)


print("\nStarting benchmarks (100 wrap/unwrap iterations each)...")
ITERATIONS = 100

t_rsa = timeit.timeit(bench_rsa, number=ITERATIONS)
t_elg = timeit.timeit(bench_elgamal, number=ITERATIONS)
t_rab = timeit.timeit(bench_rabin, number=ITERATIONS)

print("-" * 40)
print(f"RSA (2048-bit):              {t_rsa:.4f} seconds")
print(f"ElGamal (1024-bit safe p):   {t_elg:.4f} seconds")
print(f"Rabin (1024-bit primes):     {t_rab:.4f} seconds")
print("-" * 40)

fastest = min(t_rsa, t_elg, t_rab)
if fastest == t_rab:
    print("Fastest here: Rabin.")
elif fastest == t_rsa:
    print("Fastest here: RSA.")
else:
    print("Fastest here: ElGamal.")
