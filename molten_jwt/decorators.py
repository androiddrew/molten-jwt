from typing import Callable, List, Any


def allow_anonymous(handler: Callable[..., Any]) -> Callable[..., Any]:
    """A decorator used to mark a handler as allowing non-authenticated
    users. This in turn is used by the `molten_jwt.JWTAuthMiddleware` to
    determine authentication requirements."""
    setattr(handler, "allow_anonymous", True)
    return handler


class claims_required:
    """A decorator used to mark a handler as requiring certain claims
    to be presented within the JWT token. This in turn is used by the
    `molten_jwt.JWTAuthMiddleware` to determine authorization requirements."""

    def __init__(self, claims: List[str]):
        self.claims = claims

    def __call__(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        setattr(handler, "claims", self.claims)
        return handler
