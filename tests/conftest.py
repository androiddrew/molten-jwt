import pytest
from authlib.specs.rfc7519 import jwt


@pytest.fixture(scope="function")
def testing_token(secret="keepthissafe", algorithm="HS256") -> str:
    """A basic JWT token for testing purposes"""
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    return jwt.encode({"alg": algorithm}, payload, secret).decode("utf-8")
