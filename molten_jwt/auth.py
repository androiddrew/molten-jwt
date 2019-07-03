from inspect import Parameter
from typing import Callable, Any, Union, Optional

from molten import HTTPError, HTTP_401, HTTP_403, Header, Settings, Cookies

from molten_jwt.token import JWT, JWTClaims
from molten_jwt.exceptions import AuthenticationError, TokenValidationError
from molten_jwt.utils import get_token_from_header, get_token_from_cookie


class JWTIdentity:
    """
    A `JWTIdentity` instance represents a decoded identity token.

    All token claims are stored within the `JTWIdentity.token` dictionary.
    Dynamic attribute access provides the token claims using regular dot
    notation.
    """

    __slots__ = ("id", "user_name", "token")

    def __init__(self, id: Union[int, str], user_name: str, token: JWTClaims) -> None:
        self.id = id
        self.user_name = user_name
        self.token = token

    def __getattr__(self, item: Any):
        value = self.token.get(item, None)
        if value is None:
            raise AttributeError(
                f"{self.__class__.__name__} object has no attribute '{item}'"
            )
        return value


class JWTIdentityComponent:
    """A component that instantiates a JWTIdentity.

    This component depends on the availability of a `molten.Settings`
    component and on a `molten_jwt.JWT` component.

    In addition to the `molten_jwt.JWT` configuration settings,
    you can provide:

    `JWT_AUTH_USER_ID`: a string value for the claim representing
    the user id within your token. Defaults to `sub`.

    `JWT_AUTH_USER_NAME`: a string value for the claim representing
    the user name within your token. Defaults to `name`.

    `JWT_AUTH_COOKIE`: a string value specifying a cookie name the
    `JWTIdentityComponent` will use to locate an access token instead
    of the Authorization Header.

    `JWT_AUTH_PREFIX`: a string value that comes before the token in
    the Authorization header. Defaults to `bearer`.
    """

    is_cacheable = True
    is_singleton = False

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is JWTIdentity

    def resolve(
        self,
        settings: Settings,
        jwt: JWT,
        authorization: Optional[Header],
        cookies: Cookies,
    ) -> Optional[JWTIdentity]:

        auth_cookie_name: str = settings.get("JWT_AUTH_COOKIE")
        authorization_prefix: str = settings.get("JWT_AUTH_PREFIX", "bearer")
        identity_claim: str = settings.get("JWT_AUTH_USER_ID", "sub")
        user_name_claim: str = settings.get("JWT_AUTH_USER_NAME", "name")

        try:
            if auth_cookie_name is None:
                token = get_token_from_header(authorization, authorization_prefix)
            else:
                token = get_token_from_cookie(cookies, auth_cookie_name)
            decoded_token = jwt.decode(token)
            user_id = decoded_token.get(identity_claim)
            user_name = decoded_token.get(user_name_claim)
            jwt_identity = JWTIdentity(user_id, user_name, decoded_token)
        except AuthenticationError:
            return None
        return jwt_identity


# TODO add middleware checks for authorization claims.
class JWTAuthMiddleware:
    """A middleware that automatically validates that a JWT access token
    is passed within the `Authorization` header or a named cookie of the
    request. This middleware depends on the availability of a `molten.Settings`
    component, a `molten_jwt.JWT` component, and a molten_jwt.JWTIdentity`
    component.

    Use the `molten_jwt.decorators.allow_anonymous` decorator on a handler
    to allow for non-authenticated access to an individual endpoint.

    Use the `JWT_AUTH_WHITELIST` setting to specify a list of handler functions
    that should be excluded from authentication checks.

    Token decode errors and failed validations result in a HTTP 401
    Unauthorized response with the WWW-Authenticate header set to Bearer.
    This means the user should reauthenticate with the application and try
    again. Missing claims in a valid token will result in an HTTP 403 Forbidden
    response and no further requests should be made.
    """

    def __call__(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        def middleware(jwt_identity: JWTIdentity, settings: Settings) -> Any:

            white_list = settings.get("JWT_AUTH_WHITELIST", [])

            if (
                getattr(handler, "allow_anonymous", False)
                or handler.__name__ in white_list
            ):
                return handler()
            # TODO change this error message to something more sensible.
            if jwt_identity is None:
                raise HTTPError(
                    HTTP_401,
                    response="UNAUTHORIZED",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            try:
                jwt_identity.token.validate()
            except TokenValidationError as err:
                raise HTTPError(
                    HTTP_401,
                    response={"status": 401, "error_message": str(err)},
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if hasattr(handler, "claims"):
                claim_errors = [
                    {k: v}
                    for k, v in handler.claims.items()
                    if k not in jwt_identity.token or v != jwt_identity.token.get(k)
                ]
                if claim_errors:
                    raise HTTPError(
                        HTTP_403,
                        response={"status": 403, "error_message": claim_errors},
                    )

            return handler()

        return middleware
