# molten-jwt


[![PyPI](https://img.shields.io/pypi/v/molten-jwt.svg)](https://pypi.python.org/project/molten-jwt/)
[![PyPI](https://img.shields.io/pypi/pyversions/molten-jwt.svg)](https://pypi.python.org/project/molten-jwt/)
[![Build Status](https://travis-ci.org/androiddrew/molten-jwt.svg?branch=master)](https://travis-ci.org/androiddrew/molten-jwt)
[![codecov](https://codecov.io/gh/androiddrew/molten-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/androiddrew/molten-jwt)

A JSON Web Token(JWT) library built on top of [Authlib](https://github.com/lepture/authlib) for use in the [Molten](https://github.com/Bogdanp/molten) web framework.

## Usage

### JWT

The `JWT` class provides the core methods to encode and decode JSON Web Tokens in your application or middleware. All tokens produced are signed with a key and algorithm according to the JSON Web Signature(JWS) specification. 

*__Note__: Signing a token does not mean that the token contents are encrypted. This signature is used to prevent tampering. Take care not to expose private information in unencrypted tokens. Also please always use transport level security (TLS)*

```python
from molten_jwt import JWT

jwt = JWT(key='asecretkeyforsigning', alg="HS256")

token = jwt.encode({'sub': 'superman'})

decoded = jwt.decode(token)
```

### JWT with dependency injection

Register the `JWTComponent` with your Molten application and provide a `JWT_SECRET_KEY` in the molten `Settings`. The `SettingsComponent` is utilized to provide the configuration for your `JWT` injectable instance. Now simply annotate your a handler param with the `JWT` type and use it to encode your JSON Web Token. 

```python
from typing import Dict
from molten import (
    App,
    Route,
    Settings,
    SettingsComponent,
    schema,
    field,
    HTTP_403,
    HTTP_500,
)
from molten.errors import HTTPError

from molten_jwt import JWT, JWTComponent

settings = Settings({"JWT_SECRET_KEY": "donotcommittoversioncontrol"})


@schema
class UserData:
    email: str
    password: str = field(request_only=True)


def db_login(data: UserData):
    # DB magic happens here. This is just to have a working example for copy pasta
    setattr(data, "id", 1)
    return data


def login(data: UserData, jwt: JWT) -> Dict:
    # Perform the authentication task with your data layer
    user = db_login(data)
    if not user:
        raise HTTPError(HTTP_403, "Incorrect username or password")

    payload = {"sub": user.id, "name": user.email, "other_data": "12345"}
    try:
        token = jwt.encode(payload)
    except Exception:
        raise HTTPError(HTTP_500, "Internal error encountered")

    return {"token": token}


components = [SettingsComponent(settings), JWTComponent()]

routes = [Route("/login", login, method="POST")]

app = App(routes=routes, components=components)
```

### JWTIdentity

A `JWTIdentity` component can be added to your application to provide a user representation from a decoded access token. By default this library assumes your access token is sent in the `Authorization` header of the request. Alternatively, you can provide a cookie name using `JWT_AUTH_COOKIE` within your settings, however current functionality does not support both methods. Add the `JWTIdentityComponent` to your app's component list then inject the `JWTIdentity` into your handler. In the event that the `Authorization` header / cookie is not found or if an error occurs in the decoding of the token the `JWTIdentityComponent` will return `None`.

```python

...

from molten_jwt import JWT, JWTIdentity, JWTComponent, JWTIdentityComponent

...


def protected_endpoint(jwt_user: JWTIdentity) -> Dict:
    if jwt_user is None:
        raise HTTPError(HTTP_403, "Forbidden")

    return {"user_id": jwt_user.id, "name": jwt_user.user_name, "token": jwt_user.token}


components = [SettingsComponent(settings), JWTComponent(), JWTIdentityComponent()]

routes = [
    Route("/login", login, method="POST"),
    Route("/safe", protected_endpoint, method="GET"),
]

app = App(routes=routes, components=components)


```

### JWTAuthMiddleware

The `JWTAuthMiddleware` can be added to your application to globally validate that a JSON Web Token was passed within the `Authorization` header or a named cookie of the request. This middleware depends on the availability of a `molten.Settings`component, a `molten_jwt.JWT` component, and a `molten_jwt.JWTIdentity` component.

Use the `molten_jwt.decorators.allow_anonymous` decorator to allow for non-authenticated access to endpoints when using this middleware. Alternatively, the `JWT_AUTH_WHITELIST` setting can be used to provided a list of handler names that should skip authentication checks.


```python

from typing import Dict
from molten import (
    App,
    Route,
    Settings,
    SettingsComponent,
    schema,
    field,
    HTTP_403,
    HTTP_500,
    ResponseRendererMiddleware,
)
from molten.errors import HTTPError

from molten_jwt import JWT, JWTIdentity, JWTComponent, JWTIdentityComponent, JWTAuthMiddleware
from molten_jwt.decorators import allow_anonymous

settings = Settings({"JWT_SECRET": "donotcommittoversioncontrol"})


@schema
class UserData:
    email: str
    password: str = field(request_only=True)


def db_login(data: UserData):
    # DB magic happens here this is just to have a working example
    setattr(data, "id", 1)
    return data


@allow_anonymous
def login(data: UserData, jwt: JWT) -> Dict:
    # Perform the authentication task with your data layer
    user = db_login(data)
    if not user:
        raise HTTPError(HTTP_403, "Incorrect username or password")

    payload = {"sub": user.id, "name": user.email, "other_data": "12345"}
    try:
        token = jwt.encode(payload)
    except Exception:
        raise HTTPError(HTTP_500, "Interal error encountered")

    return {"token": token}


def protected_endpoint(jwt_user: JWTIdentity) -> Dict:
    """Will raise a 401 HTTP status if a JWT is not present or is invalid"""
    return {"user_id": jwt_user.id, "name": jwt_user.user_name, "token": jwt_user.token}


@allow_anonymous
def anonymous_ok(jwt_user: JWTIdentity) -> Dict:
    if jwt_user is None:
        return {
            "message": "JWT token not presented or is invalid. Accessing resource as anonymous."
        }
    return {"user_id": jwt_user.id, "name": jwt_user.user_name, "token": jwt_user.token}


components = [SettingsComponent(settings), JWTComponent(), JWTIdentityComponent()]

middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

routes = [
    Route("/login", login, method="POST"),
    Route("/safe", protected_endpoint, method="GET"),
    Route("/anyone", anonymous_ok, method="GET"),
]

app = App(routes=routes, components=components, middleware=middleware)

```

### Attribution

Many thanks to [apistar-jwt](https://github.com/audiolion/apistar-jwt) for providing the inspiration and starting point for this package.
