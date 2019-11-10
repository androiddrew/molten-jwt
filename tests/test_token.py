import datetime as dt
import inspect
import pytest
from authlib.jose.errors import BadSignatureError
from molten_jwt.token import JWT, JWTClaims, JWTComponent, config_jwt_from_settings
from molten_jwt.exceptions import (
    AuthenticationError,
    ConfigurationError,
    TokenValidationError,
)


def test_bad_alg_for_JWT_raises_error():
    with pytest.raises(ValueError):
        JWT(key="secret", alg="BAD")


def test_JWT_init_raises_error_for_missing_public_key(rsa_keys):
    with pytest.raises(ValueError):
        JWT(key=rsa_keys[0], alg="RS256")


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"JWT_ALGORITHM": "dirp"},
        {"JWT_ALGORITHM": "RS256"},
        {
            "JWT_ALGORITHM": "RS256",
            "JWT_PRIVATE_KEY_FILE": "notafilepath",
            "JWT_PUBLIC_KEY_FILE": "alsonotapath",
        },
        {"JWT_ALGORITHM": "HS256"},
    ],
)
def test_config_jwt_from_settings_raises_config_error(settings):
    with pytest.raises(ConfigurationError):
        config_jwt_from_settings(settings=settings)


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_JWT_encode_using_HMAC(alg, app_settings, token_check):
    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg=alg)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    token = jwt.encode(payload)
    b64decoded_header, b64decoded_payload = token_check(token)
    assert b64decoded_header.get("alg") == alg
    decoded_token = jwt.decode(token)
    assert isinstance(decoded_token, JWTClaims)
    assert decoded_token.get("sub") == payload.get("sub")
    assert b64decoded_payload.keys() == payload.keys()


@pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
def test_JWT_encode_using_RSA_keys(alg, rsa_keys, testing_token):
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    jwt = JWT(key=rsa_keys[0], pub_key=rsa_keys[1], alg=alg)
    token = jwt.encode(payload)
    assert token.count(".") == 2
    decoded_token = jwt.decode(token)
    assert isinstance(decoded_token, JWTClaims)
    assert decoded_token.get("sub") == "1234567890"


@pytest.mark.skip
def test_JWT_encode_using_EC_keys():
    pass


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
