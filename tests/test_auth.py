import pytest
from molten import Route, SettingsComponent, ResponseRendererMiddleware, App, testing


from molten_jwt import (
    JWTComponent,
    JWTIdentityComponent,
    JWTAuthMiddleware,
    JWTIdentity,
)
from molten_jwt.decorators import allow_anonymous, claims_required
from tests.test_token import settings


def test_dynamic_access_of_jwt_identity():
    ident = JWTIdentity(
        1, "superman", {"sub": "1234567890", "name": "superman", "iat": 1516239022}
    )
    assert ident.id == 1
    assert ident.user_name == "superman"
    assert ident.iat == 1516239022
    with pytest.raises(AttributeError):
        ident.dirp


def test_middleware_raises_401_error():
    def test_handler():
        return "Handler called"

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings), JWTComponent(), JWTIdentityComponent()]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/auth-required")
    assert 401 == response.status_code


def test_middleware_anonymous_user_support():
    @allow_anonymous
    def test_handler():
        return "Handler called"

    routes = [Route("/auth-maybe", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings), JWTComponent(), JWTIdentityComponent()]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/auth-maybe")
    assert 200 == response.status_code
    assert "Handler called" in response.data


def test_claims_required():
    @claims_required(["admin"])
    def test_handler():
        return "Handler called"

    routes = [Route("/claims", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings)]

    middleware = [ResponseRendererMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/claims")
    assert 200 == response.status_code
    assert test_handler.claims == ["admin"]
    assert "Handler called" in response.data


def test_middleware_validates_token(testing_token):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [SettingsComponent(settings), JWTComponent(), JWTIdentityComponent()]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/auth-required", headers={"Authorization": f"Bearer {testing_token}"}
    )
    assert 200 == response.status_code
    assert "1234567890" in response.data


def test_middleware_white_listing(testing_token):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    routes = [Route("/whitelisted", method="GET", handler=test_handler)]

    components = [
        SettingsComponent({**settings, "JWT_AUTH_WHITELIST": ["test_handler"]}),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/whitelisted", headers={"Authorization": f"Bearer {testing_token}"}
    )

    unauthenticated = client.get("/whitelisted")
    assert 200 == response.status_code
    assert "1234567890" in response.data
    assert 200 == unauthenticated.status_code
    assert "No user token present" in unauthenticated.data
