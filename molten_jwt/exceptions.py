from typing import Dict, Any
from molten.errors import MoltenError


class ConfigurationError(MoltenError):
    """Raised when configuration of the `JWT` class fails"""


class AuthenticationError(MoltenError):
    """Raised when JWT Authentication fails"""


class AuthorizationError(MoltenError):
    """Raised when a JWT claims check fails"""


class TokenValidationError(MoltenError):
    """To be raised when a JWTClaims validation check fails"""
    def __init__(self, reasons: Dict[str, Any]) -> None:
        self.reasons = reasons

    def __str__(self) -> str:
        return str(self.reasons)
