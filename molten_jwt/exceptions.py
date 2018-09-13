from molten.errors import MoltenError


class ConfigurationError(MoltenError):
    """Raised when configuration of the `JWT` class fails"""


class AuthenticationError(MoltenError):
    """Raised when JWT Authentication fails"""
