"""
Hashing algorithm examples (SHA-1, MD5, SHA-256).
INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
"""

import hashlib
from cryptography.hazmat.primitives import hashes


def sha1_hash(data: bytes) -> str:
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    SHA-1 / SHA1 / sha1 hashing function.
    ECDAT Classification Expected: SHA-1 / HASH (MEDIUM/attention Risk) -> DEPRECATE
    """
    # Standard Python hashlib SHA1 explicit usage
    hasher = hashlib.sha1()
    hasher.update(data)
    digest_hex = hasher.hexdigest()

    # Cryptography library SHA1 explicit usage
    crypto_hasher = hashes.Hash(hashes.SHA1())
    crypto_hasher.update(data)
    _ = crypto_hasher.finalize()

    return digest_hex


def md5_hash(data: bytes) -> str:
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    MD5 / md5 hashing function.
    ECDAT Classification Expected: MD5 / HASH (MEDIUM/attention Risk) -> DEPRECATE
    """
    # Standard Python hashlib MD5 explicit usage
    hasher = hashlib.md5()
    hasher.update(data)
    digest_hex = hasher.hexdigest()

    # Cryptography library MD5 explicit usage
    crypto_hasher = hashes.Hash(hashes.MD5())
    crypto_hasher.update(data)
    _ = crypto_hasher.finalize()

    return digest_hex


def sha256_hash(data: bytes) -> str:
    """
    SHA-256 / SHA256 / sha256 baseline secure hashing function.
    ECDAT Classification Expected: SHA-256 / HASH (LOW Quantum Risk) -> RETAIN_MONITOR
    """
    # Standard Python hashlib SHA256 explicit usage
    hasher = hashlib.sha256()
    hasher.update(data)
    digest_hex = hasher.hexdigest()

    # Cryptography library SHA256 explicit usage
    crypto_hasher = hashes.Hash(hashes.SHA256())
    crypto_hasher.update(data)
    _ = crypto_hasher.finalize()

    return digest_hex
