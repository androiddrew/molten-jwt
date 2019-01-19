from inspect import Parameter
from typing import Callable, Any, Union, Dict, Optional

from molten import HTTPError, HTTP_401, Header

from molten_jwt.token import JWT
from molten_jwt.exceptions import AuthenticationError
from molten_jwt.utils import get_token_from_header


class JWTIdentity:
    """A `JWTIdentity` instance represents a decoded identity token. All
    token claims are stored within the `JTWIdentity.token` dictionary.
    Dynamic attribute access provides the token claims using regular dot
    notation.
    """

    __slots__ = ("id", "user_name", "token")

    def __init__(self, id: Union[int, str], user_name: str, token: Dict) -> None:
        self.id = id
        self.user_name = user_name
        self.token = token

    def __getattr__(self, item):
        value = self.token.get(item, None)
        if value is None:
            raise AttributeError(
                f"{self.__class__.__name__} object has no attribute '{item}'"
            )
        return value


class JWTIdentityComponent:
    """A component that instantiates a JWTIdentity. This component
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
        return parameter.annotation is JWTIdentity

    def resolve(
        self, jwt: JWT, authorization: Optional[Header]
    ) -> Optional[JWTIdentity]:
        try:
            token = get_token_from_header(authorization, jwt.authorization_prefix)
            decoded_token = jwt.decode(token)
            user_id = decoded_token.get(jwt.identity_claim)
            user_name = decoded_token.get(jwt.user_name_claim)
            jwt_identity = JWTIdentity(user_id, user_name, decoded_token)
        except AuthenticationError:
            return None
        return jwt_identity


# TODO add middleware checks for authorization claims.
class JWTAuthMiddleware:
    """A middleware that automatically validates a JWT passed within
    the `Authorization` header of the request. This middleware depends
    on the availability of a `molten.Settings`component, a
    `molten_jwt.JWT` component, and a molten_jwt.JWTIdentity` component.

    Use the `molten_jwt.decorators.allow_anonymous` decorator to allow,
    for non-authenticated access to endpoints when using this middleware"""

    def __call__(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        def middleware(jwt_identity: JWTIdentity) -> Any:
            if getattr(handler, "allow_anonymous", False):
                return handler()

            if jwt_identity is None:
                raise HTTPError(
                    HTTP_401,
                    response="UNAUTHORIZED",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return handler()

        return middleware
