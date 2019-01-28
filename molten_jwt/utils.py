from molten import Header, Cookies

from .exceptions import AuthenticationError


def get_token_from_cookie(cookies: Cookies, cookie_name: str):
    token = cookies.get(cookie_name)
    if token is None:
        raise AuthenticationError("Authorization cookie missing")
    return token


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
