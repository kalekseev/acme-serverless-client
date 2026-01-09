import typing

import josepy.jwk
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ACC_KEY_BITS = 2048
CERT_PKEY_BITS = 2048


def make_csr(private_key_pem: bytes, domains: typing.Sequence[str]) -> bytes:
    """Generate a CSR with CN set to the first domain and all domains as SANs."""
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Only RSA private keys are supported")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def load_certificate(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem, default_backend())


def generate_private_key() -> bytes:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=CERT_PKEY_BITS, backend=default_backend()
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_account_key() -> josepy.jwk.JWKRSA:
    return josepy.jwk.JWKRSA(
        key=rsa.generate_private_key(
            public_exponent=65537, key_size=ACC_KEY_BITS, backend=default_backend()
        )
    )
