import datetime as dt
import pytest
from molten import (
    Route,
    SettingsComponent,
    ResponseRendererMiddleware,
    App,
    testing,
    Response,
    Cookie,
)
from molten.http import HTTP_200

from molten_jwt import (
    JWT,
    JWTComponent,
    JWTIdentityComponent,
    JWTAuthMiddleware,
    JWTIdentity,
)
from molten_jwt.decorators import allow_anonymous, claims_required


def test_dynamic_access_of_jwt_identity():
    ident = JWTIdentity(
        1, "superman", {"sub": "1234567890", "name": "superman", "iat": 1516239022}
    )
    assert ident.id == 1
    assert ident.user_name == "superman"
    assert ident.iat == 1516239022
    with pytest.raises(AttributeError):
        ident.dirp


def test_identity_extract_jwt_from_cookie(app_settings):
    def test_auth(jwt: JWT):
        cookie_name = "molten_auth_cookie"
        cookie_value = jwt.encode({"sub": 123456, "name": "spiderman"})
        auth_response = Response(HTTP_200)
        auth_response.set_cookie(Cookie(cookie_name, cookie_value))
        return auth_response

    def test_cookie(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "Didn't work"
        return f"Hello {jwt_identity.name} your sub id is {jwt_identity.sub}"

    routes = [
        Route("/auth", method="POST", handler=test_auth),
        Route("/cookie", method="GET", handler=test_cookie),
    ]

    components = [
        SettingsComponent(
            {**app_settings, **{"JWT_AUTH_COOKIE": "molten_auth_cookie"}}
        ),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    app = App(routes=routes, components=components)
    client = testing.TestClient(app)

    auth_response = client.post("/auth")
    cookie_value = auth_response.headers.get_all("set-cookie")[0]
    assert "molten_auth_cookie" in cookie_value
    cookie_response = client.get("/cookie", headers={"cookie": cookie_value})
    assert "123456" in cookie_response.data
    assert "spiderman" in cookie_response.data


def test_missing_auth_cookie(app_settings):
    def test_cookie(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "Didn't work"
        return f"Hello {jwt_identity.name} your sub id is {jwt_identity.sub}"

    routes = [Route("/cookie", method="GET", handler=test_cookie)]

    components = [
        SettingsComponent(
            {**app_settings, **{"JWT_AUTH_COOKIE": "molten_auth_cookie"}}
        ),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    app = App(routes=routes, components=components)
    client = testing.TestClient(app)

    cookie_response = client.get("/cookie")
    assert "Didn't work" in cookie_response.data


def test_middleware_raises_401_error(app_settings):
    def test_handler():
        return "Handler called"

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(app_settings),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/auth-required")
    assert 401 == response.status_code


def test_middleware_anonymous_user_support(app_settings):
    @allow_anonymous
    def test_handler():
        return "Handler called"

    routes = [Route("/auth-maybe", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(app_settings),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/auth-maybe")
    assert 200 == response.status_code
    assert "Handler called" in response.data


def test_claims_required_attaches_values(app_settings):
    @claims_required({"admin": True})
    def test_handler():
        return "Handler called"

    routes = [Route("/claims", method="GET", handler=test_handler)]

    components = [SettingsComponent(app_settings)]

    middleware = [ResponseRendererMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get("/claims")
    assert 200 == response.status_code
    assert "admin" in test_handler.claims
    assert test_handler.claims.get("admin") is True
    assert "Handler called" in response.data


def test_claims_required_raises_error(app_settings, testing_token):
    @claims_required({"admin": True})
    def test_handler():
        return "Handler called"

    routes = [Route("/claims", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(app_settings),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/claims", headers={"Authorization": f"Bearer {testing_token}"}
    )
    assert 403 == response.status_code


def test_middleware_token_validation_passes(app_settings, testing_token):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(app_settings),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/auth-required", headers={"Authorization": f"Bearer {testing_token}"}
    )
    assert 200 == response.status_code
    assert "1234567890" in response.data


def test_middleware_token_validation_raises_error_on_token_exp(app_settings):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    jwt = JWT(key="keepthissafe", alg="HS256")
    iat = dt.datetime.now() + dt.timedelta(seconds=-10)
    exp = iat + dt.timedelta(seconds=5)
    payload = {"sub": "1234567890", "name": "John Doe", "iat": iat, "exp": exp}
    token = jwt.encode(payload)

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(app_settings),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/auth-required", headers={"Authorization": f"Bearer {token}"}
    )
    assert 401 == response.status_code
    content = response.json()
    assert "error_message" in content
    assert content.get("status") == 401


def test_middleware_token_validation_raises_error_on_token_nbf(app_settings):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    jwt = JWT(key="keepthissafe", alg="HS256")
    iat = dt.datetime.now()
    exp = iat + dt.timedelta(seconds=1000)
    nbf = iat + dt.timedelta(seconds=500)
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": iat,
        "exp": exp,
        "nbf": nbf,
    }
    token = jwt.encode(payload)

    routes = [Route("/auth-required", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(app_settings),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    response = client.get(
        "/auth-required", headers={"Authorization": f"Bearer {token}"}
    )
    assert 401 == response.status_code
    content = response.json()
    assert "error_message" in content
    assert content.get("status") == 401


def test_middleware_white_listing(app_settings, testing_token):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    routes = [Route("/whitelisted", method="GET", handler=test_handler)]

    components = [
        SettingsComponent({**app_settings, "JWT_AUTH_WHITELIST": ["test_handler"]}),
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


def test_JWT_claims_options_raises_error(app_settings, testing_token):
    def test_handler(jwt_identity: JWTIdentity):
        if jwt_identity is None:
            return "No user token present"
        return jwt_identity.id

    jwt = JWT(key=app_settings.get("JWT_SECRET_KEY"), alg="HS256")
    mod_token = jwt.encode(
        {**jwt.decode(testing_token), **{"iss": "https://molten.com"}}
    )

    routes = [Route("/claim_options", method="GET", handler=test_handler)]

    components = [
        SettingsComponent(
            {
                **app_settings,
                "JWT_CLAIMS_OPTIONS": {
                    "iss": {
                        "essential": True,
                        "values": ["https://example.com", "https://example.org"],
                    }
                },
            }
        ),
        JWTComponent(),
        JWTIdentityComponent(),
    ]

    middleware = [ResponseRendererMiddleware(), JWTAuthMiddleware()]

    app = App(routes=routes, components=components, middleware=middleware)
    client = testing.TestClient(app)

    missing_claim_response = client.get(
        "/claim_options", headers={"Authorization": f"Bearer {testing_token}"}
    )
    wrong_claim_value_response = client.get(
        "/claim_options", headers={"Authorization": f"Bearer {mod_token}"}
    )
    assert 401 == missing_claim_response.status_code
    assert 401 == wrong_claim_value_response.status_code
