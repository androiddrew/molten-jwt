# molten-jwt

[![Build Status](https://travis-ci.org/androiddrew/molten-jwt.svg?branch=master)](https://travis-ci.org/androiddrew/molten-jwt)
[![codecov](https://codecov.io/gh/androiddrew/molten-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/androiddrew/molten-jwt)

A JSON Web Token component and middleware for the [Molten](https://github.com/Bogdanp/molten) web framework. Many thanks to [apistar-jwt](https://github.com/audiolion/apistar-jwt) for providing the inspiration and starting point for this package.

## Usage

### JWT

The `JWT` object provides the methods to encode and decode JSON Web Tokens in your application or middleware.

Register the `JWTComponent` with your Molten application and provide a `JWT_SECRET` in the molten `Settings`. The `SettingsComponent` is utilized to provide the configuration for your `JWT` injectable instance. Now simply annotate your a handler param with the `JWT` type and use it to encode your JSON Web Token. 

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

settings = Settings({"JWT_SECRET": "donotcommittoversioncontrol"})


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

### JWTUser

A `JWTUser` component can be added to your application to provide a user representation from the decoded token passed in the request `Authorization` header. Add the `JWTUserComponent` to your app's component list then inject the `JWTUser` into your handler. In the event that the `Authorization` header is not found or if an error occurs in the decoding of the token the `JWTUserComponent` will return `None`. 

```python

...

from molten_jwt import JWT, JWTUser, JWTComponent, JWTUserComponent

...


def protected_endpoint(jwt_user: JWTUser) -> Dict:
    if jwt_user is None:
        raise HTTPError(HTTP_403, "Forbidden")

    return {"user_id": jwt_user.id, "name": jwt_user.user_name, "token": jwt_user.token}


components = [SettingsComponent(settings), JWTComponent(), JWTUserComponent()]

routes = [
    Route("/login", login, method="POST"),
    Route("/safe", protected_endpoint, method="GET"),
]

app = App(routes=routes, components=components)


```

### JWTMiddleware

The `JWTMiddleware` can be added to your application to automatically validate a JWT passed within the `Authorization` header of the request. This middleware depends on the availability of a `molten.Settings`component, a `molten_jwt.JWT` component, and a `molten_jwt.JWTUser` component.

Use the `molten_jwt.decorators.allow_anonymous` decorator to allow, for non-authenticated access to endpoints when using this middleware.


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

from molten_jwt import JWT, JWTUser, JWTComponent, JWTUserComponent, JWTMiddleware
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


def protected_endpoint(jwt_user: JWTUser) -> Dict:
    """Will raise a 401 HTTP status if a JWT is not present or is invalid"""
    return {"user_id": jwt_user.id, "name": jwt_user.user_name, "token": jwt_user.token}


@allow_anonymous
def anonymous_ok(jwt_user: JWTUser) -> Dict:
    if jwt_user is None:
        return {
            "message": "JWT token not presented or is invalid. Accessing resource as anonymous."
        }
    return {"user_id": jwt_user.id, "name": jwt_user.user_name, "token": jwt_user.token}


components = [SettingsComponent(settings), JWTComponent(), JWTUserComponent()]

middleware = [ResponseRendererMiddleware(), JWTMiddleware()]

routes = [
    Route("/login", login, method="POST"),
    Route("/safe", protected_endpoint, method="GET"),
    Route("/anyone", anonymous_ok, method="GET"),
]

app = App(routes=routes, components=components, middleware=middleware)

```