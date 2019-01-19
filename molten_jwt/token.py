from inspect import Parameter
import logging
from typing import Optional, Dict

from authlib.specs.rfc7515.errors import BadSignatureError
from authlib.specs.rfc7519 import jwt
from authlib.common.errors import AuthlibBaseError
from molten import Settings

from .exceptions import ConfigurationError, AuthenticationError

logger = logging.getLogger(__name__)


# TODO init function should take parameters not a settings dictionary.
class JWT:
    """The `JWT` instance is used to both encode and decode JSON Web Tokens
    (JWTs) within your application. This class requires at a minimum that you
    provide a `JWT_SECRET` within a `molten.Settings` dictionary"""

    def __init__(self, settings: Settings) -> None:
        self.secret: str = settings.get("JWT_SECRET")
        self.algorithm: str = settings.get("JWT_ALGORITHM", "HS256")
        self.authorization_prefix: str = settings.get(
            "JWT_AUTHORIZATION_PREFIX", "bearer"
        )
        self.identity_claim: str = settings.get("JWT_USER_ID", "sub")
        self.user_name_claim: str = settings.get("JWT_USER_NAME", "name")
        self.options: Dict = settings.get("JWT_OPTIONS", {})

        if self.secret is None:
            raise ConfigurationError(
                "JWT_SECRET passed as part of settings on instantiation"
            )

    def encode(self, payload: Dict) -> str:
        """Generates a JWT auth token"""
        try:

            return jwt.encode(
                header={"alg": self.algorithm}, payload=payload, key=self.secret
            ).decode(encoding="utf8")

        except AuthlibBaseError as err:
            return err

    # TODO add support for claims to verify and, claim options, and claim params
    def decode(self, token: str) -> Optional[Dict]:
        """Decodes a JWT auth token"""
        try:
            payload = jwt.decode(token, self.secret, **self.options)
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


# TODO JWTComponent should be changed to provide a JWT instance for use in JWTIdentity
class JWTComponent:
    """A component that sets up a JWT instance for use in encoding
    and decoding JSON Web Tokens. This component depends on the
    availability of a `molten.Settings` component.

    Your settings dictionary must contain a `JWT_SECRET` setting
    at a minimum, for use in signing and verifying JWTs. Additionally,
    you may include:

    `JWT_ALGORITHM`: Defaults to `HS256`.

    `JWT_AUTHORIZATION_PREFIX`: a string for the tokeN scheme. Defaults
    to `bearer`."""

    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWT

    def resolve(self, settings: Settings) -> JWT:
        return JWT(settings)
