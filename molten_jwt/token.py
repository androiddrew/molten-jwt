from inspect import Parameter
import logging
from typing import Dict

from authlib import jose
from authlib.jose.errors import BadSignatureError, JoseError
from authlib.jose.rfc7519.claims import JWTClaims as JWTClaimsBase
from molten import Settings

from .exceptions import AuthenticationError, ConfigurationError, TokenValidationError

logger = logging.getLogger(__name__)

jwt = jose.JWT()


class JWTClaims(JWTClaimsBase):
    """wrapper class around `authlib.jose.rfc7519.claims.JWTClaims`."""

    def validate(self, now=None, leeway=0):
        """Calls all validators on the super class converting exceptions raised exceptions to a single type."""
        try:
            super().validate(now=now, leeway=leeway)
        except JoseError as err:
            raise TokenValidationError(err.error + ": " + err.description) from err


class JWT:
    """The `JWT` class provides the core methods to encode and decode JSON
    Web Tokens in your application or middleware. All tokens produced are
    signed with a key and algorithm according to the JSON Web Signature(JWS)
    specification.
    """

    def __init__(self, key: str, alg: str, **options) -> None:
        self.key = key
        self.alg = alg
        self.options = options

    def encode(self, payload: Dict) -> str:
        """Generates a JSON Web Token as a utf8 string from a dictionary payload."""
        return jwt.encode(
            header={"alg": self.alg}, payload=payload, key=self.key
        ).decode(encoding="utf8")

    def decode(self, token: str) -> JWTClaims:
        """Decodes a JWT token returning a JWTClaims instance."""
        try:
            jwt_claims = jwt.decode(
                token, key=self.key, claims_cls=JWTClaims, claims_options=self.options
            )
            if jwt_claims == {}:
                raise AuthenticationError("No payload present in token")
        except BadSignatureError as err:
            message = f"JWT Exception: {err.result}"
            logger.exception(message)
            raise AuthenticationError(message) from err
        except Exception as err:
            message = f"JWT Exception: {err.__class__.__name__}"
            logger.exception(message)
            raise AuthenticationError(message) from err
        return jwt_claims


def config_jwt_from_settings(settings: Settings) -> JWT:
    """Configures a `molten_jwt.JWT` instance from a `molten.Settings`
    instance.

    Your settings dictionary must contain a `JWT_SECRET_KEY` setting
    at a minimum, for use in signing and verifying JWTs. Additionally,
    you may include:

    `JWT_ALGORITHM`: Defaults to `HS256`.
    """
    key: str = settings.get("JWT_SECRET_KEY")
    alg: str = settings.get("JWT_ALGORITHM")
    options: dict = settings.get("JWT_CLAIMS_OPTIONS", {})

    if key is None or alg is None:
        raise ConfigurationError(
            "JWT_SECRET_KEY passed as part of settings on instantiation"
        )

    return JWT(key=key, alg=alg, **options)


class JWTComponent:
    """A component that configures a single cached JWT instance to be
    injected through Molten's dependency injection system. This component
    depends on the availability of a `molten.Settings` component.

    Your settings dictionary must contain a `JWT_SECRET_KEY` setting
    at a minimum, for use in signing and verifying JWTs. Additionally,
    you may include:

    `JWT_ALGORITHM`: is required.
    """

    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWT

    def resolve(self, settings: Settings) -> JWT:
        return config_jwt_from_settings(settings)
