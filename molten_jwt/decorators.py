def allow_anonymous(func):
    """A decorator used to mark a handler as allowing non-authenticated
    users. This in turn is used by the `molten_jwt.JWTMiddleware` to
    determine authentication requirements"""
    setattr(func, "allow_anonymous", True)
    return func
