import pytest
import inspect

from molten import (
    App,
    Route,
    Settings,
    SettingsComponent,
    testing,
    ResponseRendererMiddleware,
)
from molten_jwt.token import JWT, JWTComponent, JWTUser, JWTUserComponent, JWTMiddleware
from molten_jwt.exceptions import ConfigurationError
from molten_jwt.decorators import allow_anonymous

secret = "keepthissafe"

settings = Settings({"JWT_SECRET": secret})


def test_JWT_raises_config_error():
    with pytest.raises(ConfigurationError):
        JWT(settings={})


def test_JWT_encode(testing_token):
    jwt = JWT(settings)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    assert testing_token == jwt.encode(payload)


def test_JWT_decode(testing_token):
    jwt = JWT(settings)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    token = jwt.decode(testing_token)
    assert payload.get("sub") == token.get("sub")


def test_JWT_user_factory(testing_token):
    jwt = JWT(settings)
    jwt_user = jwt.jwt_user_factory(testing_token)
    assert type(jwt_user) is JWTUser
    assert "1234567890" == jwt_user.id


def test_JWTComponent_resolve():
    jwt_component = JWTComponent()
    jwt_obj = jwt_component.resolve(settings)
    assert isinstance(jwt_obj, JWT)


def test_JWTComponet_can_handle():
    jwt_component = JWTComponent()

    def test_handler(jwt: JWT, other: str):
        return

    jwt_param = inspect.signature(test_handler).parameters.get("jwt")
    other_param = inspect.signature(test_handler).parameters.get("other")

    assert jwt_component.can_handle_parameter(jwt_param)
    assert not jwt_component.can_handle_parameter(other_param)


def test_middleware_raises_401_error():
    def test_handler():
        return "Handler called"

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings), JWTComponent(), JWTUserComponent()]

    middleware = [ResponseRendererMiddleware(), JWTMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/auth-required")
    assert 401 == response.status_code


def test_middleware_anonymous_user_support():
    @allow_anonymous
    def test_handler():
        return "Handler called"

    routes = [Route("/auth-maybe", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings), JWTComponent(), JWTUserComponent()]

    middleware = [ResponseRendererMiddleware(), JWTMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/auth-maybe")
    assert 200 == response.status_code
    assert "Handler called" in response.data


def test_middleware_validates_token(testing_token):
    def test_handler(jwt_user: JWTUser):
        if jwt_user is None:
            return "No user token present"
        return jwt_user.id

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings), JWTComponent(), JWTUserComponent()]

    middleware = [ResponseRendererMiddleware(), JWTMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/auth-required", headers={"Authorization": f"Bearer {testing_token}"}
    )
    assert 200 == response.status_code
    assert "1234567890" in response.data
