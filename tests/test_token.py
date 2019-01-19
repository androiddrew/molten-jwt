import pytest
import inspect

from molten import Settings
from molten_jwt.token import JWT, JWTComponent
from molten_jwt.exceptions import ConfigurationError

secret = "keepthissafe"

settings = Settings({"JWT_SECRET": secret})


def test_JWT_raises_config_error():
    with pytest.raises(ConfigurationError):
        JWT(settings={})


def test_JWT_encode(testing_token):
    jwt = JWT(settings)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    assert testing_token == jwt.encode(payload)


def test_JWT_decode(testing_token):
    jwt = JWT(settings)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    token = jwt.decode(testing_token)
    assert payload.get("sub") == token.get("sub")


def test_JWTComponent_resolve():
    jwt_component = JWTComponent()
    jwt_obj = jwt_component.resolve(settings)
    assert isinstance(jwt_obj, JWT)


def test_JWTComponet_can_handle():
    jwt_component = JWTComponent()

    def test_handler(jwt: JWT, other: str):
        return

    jwt_param = inspect.signature(test_handler).parameters.get("jwt")
    other_param = inspect.signature(test_handler).parameters.get("other")

    assert jwt_component.can_handle_parameter(jwt_param)
    assert not jwt_component.can_handle_parameter(other_param)
