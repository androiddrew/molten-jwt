# History

### 0.3.0 Change / Added / Fixed

* `JWTAuthMiddleware` now validates JWT claims using the `required_claims` decorator and the standard `Authlib` validation mechanism. `Authlib` claim options can be passed to the component using the `JWT_CLAIMS_OPTIONS` setting.
* `JWTAuthMiddleware` now raises an HTTP 403 error if `required_claims` check fails.
* `JWT_ALGORITHM` is now a required setting when using `JWTComponent`. HS256 is no longer a default and will raise a `ConfigurationError` if None.
* `JWT_PRIVATE_KEY_FILE` and `JWT_PUBLIC_KEY_FILE` are now options in settings and are required for RS*, ES*, and PS* algorithms.


### 0.2.1 Change / Fixed

* Fixed README.md code examples
* Pinned Authlib version due to API changes in Authlib 0.11

### 0.2.0 Change / Added / Fixed

* `JWTUser` is now known as `JWTIdentity`
* `JWTIdentity` now has dynamic attribute access to its token claims via standard dot notation
* Authentication code and components have been relocated to `molten_jwt.auth`
* `JWT` is now a simple wrapper around `authlib.jwt` with no dependencies on the `molten.Settings`.
* `JWTComponent` will return a single JWT instance configured from the settings passed in the `molten.Settings`
* `JWTIdentityComponent` now has a setting to extract a JWTdentity from a json web token passed in a named cookie.
* `JWTAuthMiddleware` now has new settings to control authentication checking, including a whitelist of handlers.

### 0.1.1 Added / Fixed

* Updated documentation before push to Pypi
* Fixed bumpversion replacement string

### 0.1.0 Change

Switched from using PyJWT to Authlib for JWT support
