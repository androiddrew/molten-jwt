import pytest
from authlib import jose
from molten import Settings

jwt = jose.JWT()

SECRET = "keepthissafe"


@pytest.fixture(scope="function")
def testing_token(secret=SECRET, algorithm="HS256") -> str:
    """A basic JWT token for testing purposes"""
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    return jwt.encode({"alg": algorithm}, payload, secret).decode("utf-8")


@pytest.fixture(scope="module")
def app_settings():
    return Settings({"JWT_SECRET_KEY": SECRET, "JWT_ALGORITHM": "HS256"})
