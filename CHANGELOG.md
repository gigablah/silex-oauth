## 2015-06-22 v1.0.0 ##

* Introduced the `user_callback` parameter in the `oauth.services` configuration array. This is used to specify a custom callback to populate the user token with user information retrieved from the `user_endpoint`. Note that in the near future this entire mechanism may be replaced with a more robust solution (e.g. a third party library).
* Each array key in `oauth.services` should now be capitalized in the same manner as the underlying OAuth service class (e.g. `GitHub` instead of `github`). This removes the need for the workaround of providing the full classname in the `class` parameter. The service name will still be normalized to lowercase in URLs.
* A convenience function, `oauth.login_paths`, returns an array of entrypoint URLs for all configured services.
* Please refer to the updated example in the README for all the above changes.

## 2014-02-16 v0.1.1 ##

* Copied over new `TokenStorageInterface` methods to `SymfonySession`.

## 2013-10-05 v0.1.0 ##

* Failures during the callback process will now properly redirect back to `failure_path`. Specifically, `$app['oauth.controller']` has been removed and the logic rolled into `OAuthAuthenticationListener`. The default callback path of `/login/{service}/callback` has changed to `/auth/{service}/callback`, so make sure to update the configuration at your OAuth provider.
* `SymfonySession` is temporarily copied over from `lusitanian/oauth` to minimize disruption when it is removed in v0.5.
