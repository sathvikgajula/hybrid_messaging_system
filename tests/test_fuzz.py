import sys
import os
import unittest
from hypothesis import strategies as st
from hypothesis import given, settings

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aes_utils
import rabin_utils
import elgamal_utils
import rsa_utils


class TestCryptoMath(unittest.TestCase):
    n = p = q = None
    el_pub = el_priv = None
    rsa_priv = rsa_pub = None

    @classmethod
    def setUpClass(cls):
        cls.n, cls.p, cls.q = rabin_utils.generate_rabin_keys(512)
        cls.el_pub, cls.el_priv = elgamal_utils.generate_elgamal_keys(512)
        cls.rsa_priv, cls.rsa_pub = rsa_utils.generate_rsa_keys(1024)

    @given(aes_key=st.binary(min_size=32, max_size=32))
    @settings(max_examples=20, deadline=None)
    def test_rabin_recovery_heuristic(self, aes_key):
        self.assertGreaterEqual(self.p.bit_length(), 512)
        encrypted_int = rabin_utils.rabin_encrypt(aes_key, self.n)
        roots = rabin_utils.rabin_decrypt(encrypted_int, self.p, self.q)
        dummy_ct = aes_utils.aes_encrypt("test", aes_key)
        recovered_key, decrypted_msg = rabin_utils.recover_rabin_aes_key_and_decrypt(dummy_ct, roots)
        self.assertIsNotNone(recovered_key)
        self.assertEqual(recovered_key, aes_key)
        self.assertEqual(decrypted_msg, "test")

    @given(random_bytes=st.binary(min_size=32, max_size=32))
    @settings(max_examples=20, deadline=None)
    def test_elgamal_roundtrip(self, random_bytes):
        self.assertGreaterEqual(self.el_pub['p'].bit_length(), 512)
        ciphertext = elgamal_utils.elgamal_encrypt(random_bytes, self.el_pub)
        decrypted = elgamal_utils.elgamal_decrypt(ciphertext, self.el_priv, self.el_pub['p'])
        self.assertEqual(decrypted, random_bytes)
        self.assertEqual(len(ciphertext), 2)

    @given(msg=st.text(min_size=0, max_size=80), aes_key=st.binary(min_size=32, max_size=32))
    @settings(max_examples=30, deadline=None)
    def test_aes_gcm_roundtrip(self, msg, aes_key):
        ct = aes_utils.aes_encrypt(msg, aes_key)
        self.assertEqual(aes_utils.aes_decrypt(ct, aes_key), msg)

    @given(aes_key=st.binary(min_size=32, max_size=32))
    @settings(max_examples=10, deadline=None)
    def test_rsa_key_wrap_roundtrip(self, aes_key):
        enc = rsa_utils.rsa_encrypt(aes_key, self.rsa_pub)
        self.assertEqual(rsa_utils.rsa_decrypt(enc, self.rsa_priv), aes_key)

    def test_aes_rejects_short_key(self):
        with self.assertRaises(ValueError):
            aes_utils.aes_encrypt("hi", b"sixteen byte key")

    def test_rejects_small_params(self):
        with self.assertRaises(ValueError):
            elgamal_utils.generate_elgamal_keys(256)
        with self.assertRaises(ValueError):
            rabin_utils.generate_rabin_keys(256)
        with self.assertRaises(ValueError):
            rsa_utils.generate_rsa_keys(128)


if __name__ == '__main__':
    unittest.main()
