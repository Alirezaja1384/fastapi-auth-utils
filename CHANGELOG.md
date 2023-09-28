# Change log

## Version 1.1.0

### Added:
 - auth_required(): `user_class` parameter added which ensures the authenticated user is an instance of given type.
 - Mixed auth example implemented.


## Version 1.0.0

### Added:
 - `APIKeyAuthBackend` and `AuthBackendsWrapper` auth backends implemented.
 - APIKey authentication example added.

### Modified:
 - JWTAuthBackend: `get_user` option added for handling more complex authentication.
 - `auth_required()`'s default security dependency removed.

### Breaking changes:
 - `auth_required()` will not enable swagger's authorize button by itself anymore. You can set security dependencies as app/router dependencies instead.
