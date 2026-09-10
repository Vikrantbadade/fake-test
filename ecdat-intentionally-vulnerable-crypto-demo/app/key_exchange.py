"""
Key exchange examples (ECDH and Diffie-Hellman / DH).
INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
"""

from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def ecdh_key_exchange():
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    ECDH (Elliptic Curve Diffie-Hellman) key exchange example.
    ECDAT Classification Expected: ECDH / KEY_EXCHANGE_ALGORITHM (HIGH Quantum Risk) -> ML-KEM
    """
    # Generate ECDH private keys and public keys for two parties (Alice and Bob)
    alice_private_key = ec.generate_private_key(ec.SECP256R1())
    alice_public_key = alice_private_key.public_key()

    bob_private_key = ec.generate_private_key(ec.SECP256R1())
    bob_public_key = bob_private_key.public_key()

    # Perform ECDH key exchange
    alice_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
    bob_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)

    # Derive shared secret key
    alice_derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh key exchange demo"
    ).derive(alice_shared_key)

    bob_derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh key exchange demo"
    ).derive(bob_shared_key)

    return alice_derived, bob_derived


def dh_key_exchange():
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    Diffie-Hellman (DH / DiffieHellman) key exchange example.
    ECDAT Classification Expected: DH / DiffieHellman / KEY_EXCHANGE_ALGORITHM (HIGH Quantum Risk) -> ML-KEM
    """
    # DiffieHellman parameters generation (2048-bit DH)
    parameters = dh.generate_parameters(generator=2, key_size=2048)

    # Generate DH private key and public key for Alice and Bob
    alice_private_key = parameters.generate_private_key()
    alice_public_key = alice_private_key.public_key()

    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()

    # Perform classical Diffie-Hellman key exchange
    alice_shared_key = alice_private_key.exchange(bob_public_key)
    bob_shared_key = bob_private_key.exchange(alice_public_key)

    return alice_shared_key, bob_shared_key
