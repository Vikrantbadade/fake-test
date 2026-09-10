"""
TLS configuration helper referencing demo self-signed TLS certificate.
INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
"""

import os
import ssl


def get_demo_cert_path() -> str:
    """
    Returns the absolute path to the synthetic demo-server.crt certificate file.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_path = os.path.join(base_dir, "certs", "demo-server.crt")
    return cert_path


def create_demo_tls_context() -> ssl.SSLContext:
    """
    INTENTIONALLY INSECURE — ECDAT TEST FIXTURE
    Creates an ssl.SSLContext loading the synthetic RSA-2048 demo certificate demo-server.crt.
    ECDAT Classification Expected: RSA certificate / CERTIFICATE (HIGH Quantum Risk) -> PQC certificate/key migration
    """
    # Create SSL context for TLS static analysis detection
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    cert_file = get_demo_cert_path()
    if os.path.exists(cert_file):
        # Load disposable demo self-signed cert for static analysis discovery
        context.load_verify_locations(cafile=cert_file)
    return context
