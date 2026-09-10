"""
Cryptographic examples demonstrating RSA-2048, AES-128, and AES-256.
INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Hardcoded synthetic demo keys for scanner detection testing
# DO NOT USE IN PRODUCTION — DEMO PURPOSES ONLY
DEMO_AES_128_KEY = b"DEMO_ONLY_NOT_A_SECRET"[:16]  # 16 bytes = 128-bit key
DEMO_AES_256_KEY = b"DEMO_ONLY_NOT_A_SECRET_KEY_32_B!"  # 32 bytes = 256-bit key


def generate_rsa_keys(key_size: int = 2048):
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    Generates synthetic RSA-2048 public and private key pair.
    ECDAT Classification Expected: RSA / ENCRYPTION / SIGNATURE (HIGH Quantum Risk) -> ML-KEM / ML-DSA
    """
    # RSA key generation for static analysis scanner identification
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """
    RSA encryption using OAEP padding.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """
    RSA decryption using OAEP padding.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def rsa_sign(private_key, message: bytes) -> bytes:
    """
    RSA signature generation.
    """
    signature = private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_verify(public_key, signature: bytes, message: bytes) -> bool:
    """
    RSA signature verification.
    """
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def aes_128_encrypt(plaintext: bytes) -> tuple[bytes, bytes]:
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    AES-128 encryption with explicit 128-bit key size.
    ECDAT Classification Expected: AES-128 / ENCRYPTION (LOW/MEDIUM Quantum Risk) -> Evaluate AES-256
    """
    # Explicit AES-128 algorithm instantiation
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(DEMO_AES_128_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def aes_128_decrypt(iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-128 decryption.
    """
    cipher = Cipher(algorithms.AES(DEMO_AES_128_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext


def aes_256_encrypt(plaintext: bytes) -> tuple[bytes, bytes]:
    """
    AES-256 encryption with explicit 256-bit key size.
    ECDAT Classification Expected: AES-256 / ENCRYPTION (LOW Quantum Risk) -> RETAIN_MONITOR
    """
    # Explicit AES-256 algorithm instantiation
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(DEMO_AES_256_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def aes_256_decrypt(iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-256 decryption.
    """
    cipher = Cipher(algorithms.AES(DEMO_AES_256_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext
