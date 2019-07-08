import base64
import json
from typing import Tuple, Dict
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from authlib import jose
from molten import Settings

jwt = jose.JWT()

SECRET = "keepthissafe"


@pytest.fixture(scope="module")
def token_check():
    def _token_check(token: str) -> Tuple[Dict, Dict]:
        header, payload, _ = token.split(".")

        if len(header) % 4 != 0:
            mod = len(header) % 4
            header = header + "=" * (4 - mod)

        if len(payload) % 4 != 0:
            mod = len(payload) % 4
            payload = payload + "=" * (4 - mod)

        dheader = json.loads(base64.urlsafe_b64decode(header))
        dpayload = json.loads(base64.urlsafe_b64decode(payload))
        return dheader, dpayload

    return _token_check


@pytest.fixture(scope="module")
def rsa_keys() -> Tuple[bytes, bytes]:
    rsa_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    rsa_private_key = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rsa_public_key = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
    )
    return rsa_private_key, rsa_public_key


@pytest.fixture(scope="function")
def testing_token(secret=SECRET, algorithm="HS256") -> str:
    """A basic JWT token for testing purposes"""
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    return jwt.encode({"alg": algorithm}, payload, secret).decode("utf-8")


@pytest.fixture(scope="module")
def app_settings():
    return Settings({"JWT_SECRET_KEY": SECRET, "JWT_ALGORITHM": "HS256"})
