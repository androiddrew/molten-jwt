import pytest
import jwt as pyjwt


@pytest.fixture(scope="function")
def testing_token(secret="keepthissafe", algorithm="HS256") -> str:
    """A basic JWT token for testing purposes"""
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    return pyjwt.encode(payload, secret, algorithm=algorithm).decode("utf-8")
