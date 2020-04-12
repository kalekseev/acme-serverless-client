import typing

import josepy as jose
import OpenSSL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

ACC_KEY_BITS = 2048
CERT_PKEY_BITS = 2048


def load_certificate(pem: bytes) -> bytes:
    return typing.cast(
        bytes,
        jose.ComparableX509(
            OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
        ),
    )


def generate_domain_key() -> bytes:
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
    return typing.cast(
        bytes, OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
    )


def generate_account_key() -> jose.JWKRSA:
    return jose.JWKRSA(
        key=rsa.generate_private_key(
            public_exponent=65537, key_size=ACC_KEY_BITS, backend=default_backend(),
        )
    )
