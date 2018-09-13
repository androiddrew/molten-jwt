def allow_anonymous(func):
    setattr(func, "allow_anonymous", True)
    return func
