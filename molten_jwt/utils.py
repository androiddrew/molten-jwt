from molten import Header
from molten import Settings

from .token import JWT
from .exceptions import AuthenticationError


def config_jwt_from_settings(settings: Settings) -> JWT:
    """Configures a `molten_jwt.JWT` instance from a `molten.Settings`
    instance.
    """
    pass


def get_token_from_header(authorization: Header, authorization_prefix: str):
    if authorization is None:
        raise AuthenticationError("Authorization header is missing.")
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise AuthenticationError("Could not separate Authorization scheme and token.")
    if scheme.lower() != authorization_prefix:
        raise AuthenticationError("Authorization scheme not supported, try Bearer")
    return token


# TODO create a get_token_from_cookie function
