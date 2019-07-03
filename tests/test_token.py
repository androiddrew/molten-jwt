import datetime as dt
import inspect
import pytest
from authlib.jose.errors import BadSignatureError
from molten_jwt.token import JWT, JWTComponent, config_jwt_from_settings
from molten_jwt.exceptions import (
    AuthenticationError,
    ConfigurationError,
    TokenValidationError,
)


def test_config_jwt_from_settings_raises_config_error():
    with pytest.raises(ConfigurationError):
        config_jwt_from_settings(settings={})


# TODO enumerate testing with the other JWS algorithms
def test_JWT_encode(app_settings, testing_token):
    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg="HS256")
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    assert testing_token == jwt.encode(payload)


# TODO enumerate testing with the other JWS algorithms
def test_JWT_decode(app_settings, testing_token):
    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg="HS256")
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    token = jwt.decode(testing_token)
    assert payload.get("sub") == token.get("sub")


def test_JWT_decode_raises_token_validation_error_on_exp(app_settings):
    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg="HS256")
    iat = dt.datetime.now() + dt.timedelta(seconds=-10)
    exp = iat + dt.timedelta(seconds=5)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": iat, "exp": exp}
    token = jwt.encode(payload)
    with pytest.raises(TokenValidationError):
        jwt.decode(token).validate()


def test_JWT_decode_raises_error_on_empty_payload(app_settings):
    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg="HS256")
    empty_token = jwt.encode({})
    with pytest.raises(AuthenticationError):
        jwt.decode(empty_token)


def test_JWT_decode_raises_authentication_error_on_tampered_token(
    app_settings, testing_token
):
    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg="HS256")
    with pytest.raises(AuthenticationError) as err:
        jwt.decode(testing_token[:-2])
        assert err.__cause__.errisinstance(BadSignatureError)


def test_JWTComponent_resolve(app_settings):
    jwt_component = JWTComponent()
    jwt_obj = jwt_component.resolve(app_settings)
    assert isinstance(jwt_obj, JWT)


def test_JWTComponet_can_handle():
    jwt_component = JWTComponent()

    def test_handler(jwt: JWT, other: str):
        return

    jwt_param = inspect.signature(test_handler).parameters.get("jwt")
    other_param = inspect.signature(test_handler).parameters.get("other")

    assert jwt_component.can_handle_parameter(jwt_param)
    assert not jwt_component.can_handle_parameter(other_param)
