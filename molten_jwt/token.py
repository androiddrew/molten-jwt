from inspect import Parameter
import logging
from typing import Optional, Dict, Callable, Any, Union

import jwt as pyjwt
from jwt.exceptions import PyJWTError
from molten import Settings, Header, DependencyResolver
from molten.errors import HTTPError
from molten.http import HTTP_401

from .exceptions import ConfigurationError, AuthenticationError
from .utils import get_token_from_header

logger = logging.getLogger(__name__)


class JWTUser:
    __slots__ = ("id", "user_name", "token")

    def __init__(self, id: Union[int, str], user_name: str, token: Dict) -> None:
        self.id = id
        self.user_name = user_name
        self.token = token


class JWT:
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
        """Generates a JWT Auth token"""
        try:

            return pyjwt.encode(payload, self.secret, algorithm=self.algorithm)

        except PyJWTError as err:
            return err

    # TODO Consider supporting multiple algorithms in decode
    def decode(self, token: str) -> Optional[Dict]:
        try:
            payload = pyjwt.decode(
                token, self.secret, algorithms=[self.algorithm], **self.options
            )
            if payload == {}:
                raise AuthenticationError("No payload present in token")
        except pyjwt.MissingRequiredClaimError as err:
            message = f"JWT Missing claim: {err.claim}"
            logger.warning(message)
            raise AuthenticationError(message)
        except pyjwt.InvalidTokenError as err:
            message = f"JWT Invalid Token: {err.__class__.__name__}"
            logger.exception(message)
            raise AuthenticationError(message)
        except Exception as err:
            message = f"JWT Exception: {err.__class__.__name__}"
            logger.exception(message)
            raise AuthenticationError(message)
        return payload

    def jwt_user_factory(self, token: str) -> JWTUser:
        _token = self.decode(token)
        user_id = _token.get(self.identity_claim)
        user_name = _token.get(self.user_name_claim)
        return JWTUser(user_id, user_name, _token)


class JWTComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWT

    def resolve(self, settings: Settings) -> JWT:
        return JWT(settings)


class JWTUserComponent:
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
    """A middleware that automatically validates"""

    def __call__(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        def middleware(
            dependency_resolver: DependencyResolver, jwt_user: JWTUser
        ) -> Any:
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
