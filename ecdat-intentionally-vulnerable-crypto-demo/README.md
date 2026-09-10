# ECDAT Intentionally Vulnerable Crypto Demo Repository

> **WARNING: INTENTIONALLY INSECURE — ECDAT TEST FIXTURE ONLY**
> 
> This repository is a controlled security-testing demonstration fixture built to validate the **ECDAT** (Enterprise Cryptographic Discovery and Assessment Tool) framework.
> 
> - All cryptographic implementations, private keys, certificates, and hard-coded secrets in this repository are strictly **synthetic** and intended solely for static code scanning, SBOM discovery, and assessment workflow testing.
> - **THIS REPOSITORY MUST NEVER BE DEPLOYED TO PRODUCTION OR UNTRUSTED ENVIRONMENTS.**

---

## Purpose

The primary objective of this repository is to demonstrate the end-to-end cryptographic discovery lifecycle through ECDAT:

$$\text{Find} \longrightarrow \text{Assess} \longrightarrow \text{Recommend}$$

It contains recognizable Python source code patterns, library imports, and self-signed certificates spanning classical public-key cryptography, post-quantum vulnerable key exchange mechanisms, symmetric ciphers, legacy hash functions, and modern signatures.

---

## Included Cryptographic Cases

The demo codebase explicitly implements 11 cryptographic cases for scanner recognition:

1. **RSA (2048-bit)** (`app/crypto_examples.py`): Explicit key generation, encryption, decryption, and PSS signing.
2. **ECDSA** (`app/authentication.py`): Digital signature creation and verification using curve SECP256R1.
3. **ECDH** (`app/key_exchange.py`): Elliptic Curve Diffie-Hellman key exchange algorithm.
4. **AES-128** (`app/crypto_examples.py`): Symmetric encryption with explicit 128-bit key size.
5. **AES-256** (`app/crypto_examples.py`): Symmetric encryption baseline with explicit 256-bit key size.
6. **SHA-1** (`app/hashing.py`): Legacy cryptographic hash algorithm.
7. **MD5** (`app/hashing.py`): Legacy broken hash algorithm.
8. **SHA-256** (`app/hashing.py`): Modern secure hash baseline.
9. **DH / Diffie-Hellman** (`app/key_exchange.py`): Classical Diffie-Hellman key exchange.
10. **Ed25519** (`app/authentication.py`): Modern Edwards-curve digital signature algorithm.
11. **RSA X.509 Certificate** (`certs/demo-server.crt` & `app/tls_config.py`): Disposable self-signed TLS certificate with subject `CN=ecdat-demo.local`, `O=ECDAT Demo`.

In addition, `requirements.txt` contains pinned cryptographic dependencies (`cryptography`, `pycryptodome`, `ecdsa`) for SBOM analysis via Syft, and a controlled outdated dependency (`urllib3==1.26.5`) for vulnerability inventory validation via Trivy.

---

## Expected ECDAT Scanner Results (Demo / Expected Behavior)

The table below outlines the anticipated classification, quantum vulnerability assessment, and PQC migration recommendations when ECDAT scans this repository:

| Asset | Expected ECDAT Classification | Expected Quantum Risk | Expected PQC Direction |
| :--- | :--- | :--- | :--- |
| **RSA** | encryption / signature (depending on usage) | HIGH | ML-KEM / ML-DSA |
| **ECDSA** | signature | HIGH | ML-DSA |
| **ECDH** | key exchange | HIGH | ML-KEM |
| **DH** | key exchange | HIGH | ML-KEM |
| **AES-128** | encryption | LOW/MEDIUM | Evaluate AES-256 |
| **AES-256** | encryption | LOW | RETAIN_MONITOR |
| **SHA-1** | hash | MEDIUM/attention | DEPRECATE |
| **MD5** | hash | MEDIUM/attention | DEPRECATE |
| **SHA-256** | hash | LOW | RETAIN_MONITOR |
| **Ed25519** | signature | HIGH | ML-DSA |
| **RSA certificate** | certificate | HIGH | PQC certificate / key migration |

*Note: Risk levels and recommendations in the table above represent standard post-quantum migration guidelines (NIST PQC standards FIPS 203 ML-KEM and FIPS 204 ML-DSA).*

---

## Project Structure

```
ecdat-intentionally-vulnerable-crypto-demo/
├── README.md
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── crypto_examples.py    # RSA-2048, AES-128, AES-256
│   ├── authentication.py     # ECDSA, Ed25519
│   ├── key_exchange.py       # ECDH, DH (Diffie-Hellman)
│   ├── hashing.py            # SHA-1, MD5, SHA-256
│   └── tls_config.py         # TLS configuration loading demo-server.crt
├── certs/
│   ├── demo-server.crt       # Synthetic self-signed RSA-2048 certificate
│   └── README.md             # Certificate documentation notice
└── tests/
    └── test_crypto_examples.py # Execution verification unit tests
```

---

## Running Verification Tests

To verify that all cryptographic examples execute properly without external dependencies:

```bash
# 1. Compile all Python files for syntax verification
python3 -m compileall .

# 2. Execute unit test suite
python3 -m unittest discover -s tests
```
