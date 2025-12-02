import sys
import os
import unittest
from hypothesis import strategies as st
from hypothesis import given, settings, example

# Add parent dir to path to import your modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aes_utils
import rabin_utils
import elgamal_utils

class TestCryptoMath(unittest.TestCase):

    # 1. FUZZ TEST: Rabin 4-Root Ambiguity
    # We verify that for ANY random AES key, your logic correctly recovers it
    # from the 4 mathematical roots of m^2 mod n.
    @given(aes_key=st.binary(min_size=16, max_size=16))
    @settings(max_examples=50, deadline=None)
    def test_rabin_recovery_heuristic(self, aes_key):
        # Setup
        n, p, q = rabin_utils.generate_rabin_keys(128)
        
        # Encrypt the random AES key
        encrypted_int = rabin_utils.rabin_encrypt(aes_key, n)
        
        # Decrypt to get 4 candidates
        roots = rabin_utils.rabin_decrypt(encrypted_int, p, q)
        
        # Verify your recovery function works
        # We simulate a "dummy" ciphertext because your recovery function
        # tries to decrypt using the candidate key.
        dummy_msg = "test"
        dummy_ct = aes_utils.aes_encrypt(dummy_msg, aes_key)
        
        recovered_key, decrypted_msg = rabin_utils.recover_rabin_aes_key_and_decrypt(dummy_ct, roots)
        
        # Assertions
        self.assertIsNotNone(recovered_key, "Failed to recover key from Rabin roots")
        self.assertEqual(recovered_key, aes_key, "Recovered key does not match original")
        self.assertEqual(decrypted_msg, dummy_msg, "Decryption failed with recovered key")

    # 2. FUZZ TEST: ElGamal Homomorphic Properties
    # Verify encryption/decryption holds for random bytes
    @given(random_bytes=st.binary(min_size=16, max_size=16))
    @settings(max_examples=20, deadline=None)
    def test_elgamal_roundtrip(self, random_bytes):
        pub, priv = elgamal_utils.generate_elgamal_keys(128)
        
        # Your ElGamal implementation encrypts byte-by-byte or chunks
        # We need to ensure input format matches your util expectation
        ciphertext = elgamal_utils.elgamal_encrypt(random_bytes, pub)
        decrypted = elgamal_utils.elgamal_decrypt(ciphertext, priv, pub['p'])
        
        # Convert result back to bytes if it comes out as string
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('latin-1')
            
        self.assertEqual(decrypted, random_bytes)

if __name__ == '__main__':
    unittest.main()