# History

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
