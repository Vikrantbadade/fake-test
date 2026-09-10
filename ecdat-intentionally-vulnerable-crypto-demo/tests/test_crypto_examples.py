"""
Unit tests verifying execution of synthetic cryptographic demo functions.
INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
"""

import os
import sys
import unittest

# Ensure app module is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.crypto_examples import (
    generate_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    aes_128_encrypt,
    aes_128_decrypt,
    aes_256_encrypt,
    aes_256_decrypt,
)
from app.authentication import (
    generate_ecdsa_keypair,
    ecdsa_sign,
    ecdsa_verify,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
)
from app.key_exchange import ecdh_key_exchange, dh_key_exchange
from app.hashing import sha1_hash, md5_hash, sha256_hash
from app.tls_config import get_demo_cert_path, create_demo_tls_context


class TestCryptoExamples(unittest.TestCase):

    def test_rsa_encryption_and_signing(self):
        priv_key, pub_key = generate_rsa_keys(key_size=2048)
        message = b"Synthetic test message for RSA"
        
        # Test encryption / decryption
        ciphertext = rsa_encrypt(pub_key, message)
        decrypted = rsa_decrypt(priv_key, ciphertext)
        self.assertEqual(decrypted, message)

        # Test signing / verification
        signature = rsa_sign(priv_key, message)
        verified = rsa_verify(pub_key, signature, message)
        self.assertTrue(verified)

    def test_aes_128_encryption(self):
        plaintext = b"Test message for AES-128 encryption algorithm"
        iv, ciphertext = aes_128_encrypt(plaintext)
        decrypted = aes_128_decrypt(iv, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_aes_256_encryption(self):
        plaintext = b"Test message for AES-256 encryption algorithm"
        iv, ciphertext = aes_256_encrypt(plaintext)
        decrypted = aes_256_decrypt(iv, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_ecdsa_signing(self):
        priv_key, pub_key = generate_ecdsa_keypair()
        data = b"ECDSA digital signature test data"
        signature = ecdsa_sign(priv_key, data)
        verified = ecdsa_verify(pub_key, signature, data)
        self.assertTrue(verified)

    def test_ed25519_signing(self):
        priv_key, pub_key = generate_ed25519_keypair()
        data = b"Ed25519 digital signature test data"
        signature = ed25519_sign(priv_key, data)
        verified = ed25519_verify(pub_key, signature, data)
        self.assertTrue(verified)

    def test_ecdh_key_exchange(self):
        alice_key, bob_key = ecdh_key_exchange()
        self.assertEqual(len(alice_key), 32)
        self.assertEqual(len(bob_key), 32)
        self.assertEqual(alice_key, bob_key)

    def test_dh_key_exchange(self):
        alice_key, bob_key = dh_key_exchange()
        self.assertGreater(len(alice_key), 0)
        self.assertEqual(alice_key, bob_key)

    def test_hashing_functions(self):
        data = b"Test hashing data payload"
        
        # Test SHA-1
        sha1_res = sha1_hash(data)
        self.assertEqual(len(sha1_res), 40)

        # Test MD5
        md5_res = md5_hash(data)
        self.assertEqual(len(md5_res), 32)

        # Test SHA-256
        sha256_res = sha256_hash(data)
        self.assertEqual(len(sha256_res), 64)

    def test_tls_config(self):
        cert_path = get_demo_cert_path()
        self.assertTrue(os.path.exists(cert_path))
        ctx = create_demo_tls_context()
        self.assertIsNotNone(ctx)


if __name__ == "__main__":
    unittest.main()
