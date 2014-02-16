## 2014-02-16 ##

* Copied over new `TokenStorageInterface` methods to `SymfonySession`.

## 2013-10-05 v0.1.0 ##

* Failures during the callback process will now properly redirect back to `failure_path`. Specifically, `$app['oauth.controller']` has been removed and the logic rolled into `OAuthAuthenticationListener`. The default callback path of `/login/{service}/callback` has changed to `/auth/{service}/callback`, so make sure to update the configuration at your OAuth provider.
* `SymfonySession` is temporarily copied over from `lusitanian/oauth` to minimize disruption when it is removed in v0.5.
