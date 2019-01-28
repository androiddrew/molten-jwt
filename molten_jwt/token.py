from inspect import Parameter
import logging
from typing import Optional, Dict

from authlib.specs.rfc7515.errors import BadSignatureError
from authlib.specs.rfc7519 import jwt
from authlib.common.errors import AuthlibBaseError
from molten import Settings

from .exceptions import AuthenticationError, ConfigurationError

logger = logging.getLogger(__name__)


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
        try:

            return jwt.encode(
                header={"alg": self.alg}, payload=payload, key=self.key
            ).decode(encoding="utf8")

        except AuthlibBaseError as err:
            return err

    # TODO add support for claims to verify and, claim options, and claim params
    def decode(self, token: str) -> Optional[Dict]:
        """Decodes a JWT token"""
        try:
            payload = jwt.decode(token, self.key, **self.options)
            if payload == {}:
                raise AuthenticationError("No payload present in token")
        except BadSignatureError as err:
            message = f"JWT Exception: {err.result}"
            logger.exception(message)
            raise AuthenticationError(message)
        except Exception as err:
            message = f"JWT Exception: {err.__class__.__name__}"
            logger.exception(message)
            raise AuthenticationError(message)
        return payload


def config_jwt_from_settings(settings: Settings) -> JWT:
    """Configures a `molten_jwt.JWT` instance from a `molten.Settings`
    instance.

    Your settings dictionary must contain a `JWT_SECRET_KEY` setting
    at a minimum, for use in signing and verifying JWTs. Additionally,
    you may include:

    `JWT_ALGORITHM`: Defaults to `HS256`.
    """
    key: str = settings.get("JWT_SECRET_KEY")
    alg: str = settings.get("JWT_ALGORITHM", "HS256")

    if key is None:
        raise ConfigurationError(
            "JWT_SECRET_KEY passed as part of settings on instantiation"
        )

    return JWT(key=key, alg=alg)


class JWTComponent:
    """A component that configures a single cached JWT instance to be
    injected through Molten's dependency injection system. This component
    depends on the availability of a `molten.Settings` component.

    Your settings dictionary must contain a `JWT_SECRET_KEY` setting
    at a minimum, for use in signing and verifying JWTs. Additionally,
    you may include:

    `JWT_ALGORITHM`: Defaults to `HS256`.
    """

    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWT

    def resolve(self, settings: Settings) -> JWT:
        return config_jwt_from_settings(settings)
