"""Top-level package for molten-jwt"""

__author__ = """Drew Bednar"""
__email__ = "drew@androiddrew.com"
__version__ = "0.3.0"

from molten_jwt.token import JWT, JWTComponent
from molten_jwt.auth import JWTAuthMiddleware, JWTIdentity, JWTIdentityComponent

__all__ = [
    "JWT",
    "JWTComponent",
    "JWTAuthMiddleware",
    "JWTIdentity",
    "JWTIdentityComponent",
]
