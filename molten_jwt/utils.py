import os
from molten import Header, Cookies

from .exceptions import AuthenticationError


def read_key_file(path: str = None):
    """Returns a bytes representation of the key file present at the provided path."""
    if not os.path.isfile(path):
        raise ValueError("Provide key file path must be a file.")
    with open(path, mode="rb") as f:
        return f.read()


def get_token_from_cookie(cookies: Cookies, cookie_name: str):
    """Retrieves the JWT token present in the named cookie.

    Note no validation is preformed on the contents of the cookie.
    """
    token = cookies.get(cookie_name)
    if token is None:
        raise AuthenticationError("Authorization cookie missing")
    return token


def get_token_from_header(authorization: Header, authorization_prefix: str):
    """Retrieves the JWT token present in the Authorization header."""
    if authorization is None:
        raise AuthenticationError("Authorization header is missing.")
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise AuthenticationError("Could not separate Authorization scheme and token.")
    if scheme.lower() != authorization_prefix:
        raise AuthenticationError("Authorization scheme not supported, try Bearer")
    return token
