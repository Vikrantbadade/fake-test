"""
Authentication and digital signature examples (ECDSA & Ed25519).
INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
"""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes


def generate_ecdsa_keypair():
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    Generates ECDSA private and public key pair using SECP256R1 curve.
    ECDAT Classification Expected: ECDSA / SIGNATURE (HIGH Quantum Risk) -> ML-DSA
    """
    # ECDSA key generation
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def ecdsa_sign(private_key, data: bytes) -> bytes:
    """
    ECDSA sign operation.
    """
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


def ecdsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """
    ECDSA verify operation.
    """
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False


def generate_ed25519_keypair():
    """
    Generates Ed25519 private and public key pair.
    ECDAT Classification Expected: Ed25519 / SIGNATURE (HIGH Quantum Risk) -> ML-DSA
    """
    # Ed25519 key generation
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def ed25519_sign(private_key, data: bytes) -> bytes:
    """
    Ed25519 sign operation.
    """
    signature = private_key.sign(data)
    return signature


def ed25519_verify(public_key, signature: bytes, data: bytes) -> bool:
    """
    Ed25519 verify operation.
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
