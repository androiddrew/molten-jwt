from inspect import Parameter
import logging
from typing import Optional, Dict, Callable, Any, Union

from authlib.specs.rfc7515.errors import BadSignatureError
from authlib.specs.rfc7519 import jwt
from authlib.common.errors import AuthlibBaseError
from molten import Settings, Header
from molten.errors import HTTPError
from molten.http import HTTP_401

from .exceptions import ConfigurationError, AuthenticationError
from .utils import get_token_from_header

logger = logging.getLogger(__name__)


# TODO add dynamic attribute access to the token contents
class JWTUser:
    """A `JWTUser` instance represents a decoded user token. All
    token claims are stored within the `JTWUser.token` dictionary."""

    __slots__ = ("id", "user_name", "token")

    def __init__(self, id: Union[int, str], user_name: str, token: Dict) -> None:
        self.id = id
        self.user_name = user_name
        self.token = token


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

    def jwt_user_factory(self, token: str) -> JWTUser:
        """A factory function for the creation of `molten_jwt.JWTUser
        objects."""
        _token = self.decode(token)
        user_id = _token.get(self.identity_claim)
        user_name = _token.get(self.user_name_claim)
        return JWTUser(user_id, user_name, _token)


class JWTComponent:
    """A component that sets up a JWT instance for use in encoding
    and decoding JSON Web Tokens. This component depends on the
    availability of a `molten.Settings` component.

    Your settings dictionary must contain a `JWT_SECRET` setting
    at a minimum, for use in signing and verifying JWTs. Additionally,
    you may include:

    `JWT_ALGORITHM`: a string for the `PyJWT` supported algorithm.
     Defaults to `HS256`.

    `JWT_AUTHORIZATION_PREFIX`: a string for the tokeN scheme. Defaults
    to `bearer`."""

    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWT

    def resolve(self, settings: Settings) -> JWT:
        return JWT(settings)


class JWTUserComponent:
    """A component that instantiates a JWTUser. This component
    depends on the availability of a `molten.Settings`
    component and on a `molten_jwt.JWT` component.

    In addition to the `molten_jwt.JWT` configuration settings,
    you can provide:

    `JWT_USER_ID`: a string value for the claim representing
    the user id within your token. Defaults to `sub`.

    `JWT_USER_NAME`: a string value for the claim representing
    the user name within your token. Defaults to `name`."""

    is_cacheable = True
    is_singleton = False

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWTUser

    def resolve(self, jwt: JWT, authorization: Optional[Header]) -> Optional[JWTUser]:
        try:
            token = get_token_from_header(authorization, jwt.authorization_prefix)
            jwt_user = jwt.jwt_user_factory(token)
        except AuthenticationError as err:
            return None
        return jwt_user


class JWTMiddleware:
    """A middleware that automatically validates a JWT passed within
    the `Authorization` header of the request. This middleware depends
    on the availability of a `molten.Settings`component, a
    `molten_jwt.JWT` component, and a molten_jwt.JWTUser` component.

    Use the `molten_jwt.decorators.allow_anonymous` decorator to allow,
    for non-authenticated access to endpoints when using this middleware"""

    def __call__(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        def middleware(jwt_user: JWTUser) -> Any:
            if getattr(handler, "allow_anonymous", False):
                return handler()

            if jwt_user is None:
                raise HTTPError(
                    HTTP_401,
                    response="UNAUTHORIZED",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return handler()

        return middleware
