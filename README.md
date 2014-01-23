OAuthServiceProvider
====================

The OAuthServiceProvider integrates the [lusitanian/oauth][1] library with the [Security][2] component to provide social logins for the [Silex][3] microframework.

This library only provides the authentication system. You would have to supply your own user provider, or you can make use of the in-memory provider for testing.

Features
--------

* Supports most popular providers such as Facebook, Twitter, Google and GitHub
* Extensible via event hooks so you can plug in your own listeners and user providers
* Supports default CSRF protection mechanism

Installation
------------

Use [Composer][4] to install the gigablah/silex-oauth library by adding it to your `composer.json`.

```json
{
    "require": {
        "silex/silex": "~1.0",
        "symfony/form": "~2.3",
        "symfony/security": "~2.3",
        "gigablah/silex-oauth": "~0.1"
    }
}
```

Usage
-----

First, you need to register the service provider and configure it with the application keys, secrets, scopes and user API endpoints for each OAuth provider you wish to support. Some examples are shown below:

```php
$app->register(new Gigablah\Silex\OAuth\OAuthServiceProvider(), array(
    'oauth.services' => array(
        'facebook' => array(
            'key' => FACEBOOK_API_KEY,
            'secret' => FACEBOOK_API_SECRET,
            'scope' => array('email'),
            'user_endpoint' => 'https://graph.facebook.com/me'
        ),
        'twitter' => array(
            'key' => TWITTER_API_KEY,
            'secret' => TWITTER_API_SECRET,
            'scope' => array(),
            'user_endpoint' => 'https://api.twitter.com/1.1/account/verify_credentials.json'
        ),
        'google' => array(
            'key' => GOOGLE_API_KEY,
            'secret' => GOOGLE_API_SECRET,
            'scope' => array(
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ),
            'user_endpoint' => 'https://www.googleapis.com/oauth2/v1/userinfo'
        ),
        'github' => array(
            'key' => GITHUB_API_KEY,
            'secret' => GITHUB_API_SECRET,
            'scope' => array('user:email'),
            'user_endpoint' => 'https://api.github.com/user'
        )
    )
));
```

Next, register the `oauth` authentication provider in your firewall.

```php
// Provides URL generation
$app->register(new Silex\Provider\UrlGeneratorServiceProvider());

// Provides CSRF token generation
$app->register(new Silex\Provider\FormServiceProvider());

// Provides session storage
$app->register(new Silex\Provider\SessionServiceProvider(), array(
    'session.storage.save_path' => '/path/to/sessions'
))

$app->register(new Silex\Provider\SecurityServiceProvider(), array(
    'security.firewalls' => array(
        'default' => array(
            'pattern' => '^/',
            'anonymous' => true,
            'oauth' => array(
                //'login_path' => '/auth/{service}',
                //'callback_path' => '/auth/{service}/callback',
                //'check_path' => '/auth/{service}/check',
                'failure_path' => '/login',
                'with_csrf' => true
            ),
            'logout' => array(
                'logout_path' => '/logout',
                'with_csrf' => true
            ),
            'users' => new Gigablah\Silex\OAuth\Security\User\Provider\OAuthInMemoryUserProvider()
        )
    ),
    'security.access_rules' => array(
        array('^/auth', 'ROLE_USER')
    )
));
```

Note that the library assumes the default login, callback and check paths to be prefixed with `/auth`, so this path needs to be secured. You can uncomment the path options and change the defaults.

You will need to configure each of your OAuth providers with the correct absolute `callback_path`. For example, the default callback for Facebook would be `http://your.domain/auth/facebook/callback`.

Finally, you can provide a login/logout interface. This example assumes usage of the [Twig][5] templating engine:

```php
// Provides Twig template engine
$app->register(new Silex\Provider\TwigServiceProvider(), array(
    'twig.path' => '/path/to/templates'
));

$app->before(function (Symfony\Component\HttpFoundation\Request $request) use ($app) {
    $token = $app['security']->getToken();
    $app['user'] = null;

    if ($token && !$app['security.trust_resolver']->isAnonymous($token)) {
        $app['user'] = $token->getUser();
    }
});

$app->get('/login', function () use ($app) {
    $services = array_keys($app['oauth.services']);

    return $app['twig']->render('index.twig', array(
        'login_paths' => array_map(function ($service) use ($app) {
            return $app['url_generator']->generate('_auth_service', array(
                'service' => $service,
                '_csrf_token' => $app['form.csrf_provider']->generateCsrfToken('oauth')
            ));
        }, array_combine($services, $services)),
        'logout_path' => $app['url_generator']->generate('logout', array(
            '_csrf_token' => $app['form.csrf_provider']->generateCsrfToken('logout')
        ))
    ));
});

$app->match('/logout', function () {})->bind('logout');
```

The template itself:

```
<div>
  {% if app.user %}
    <p>Hello {{ app.user.username }}! Your email is {{ app.user.email }}</p>
    <a href="{{ logout_path }}">Logout</a>
  {% else %}
    <ul>
      <li><a href="{{ login_paths.facebook }}">Login with Facebook</a></li>
      <li><a href="{{ login_paths.twitter }}">Login with Twitter</a></li>
      <li><a href="{{ login_paths.google }}">Login with Google</a></li>
      <li><a href="{{ login_paths.github }}">Login with GitHub</a></li>
    </ul>
  {% endif %}
</div>
```

Custom Event Handlers
---------------------

Two default event listeners are registered by default:

* `UserInfoListener` executes right after an OAuth access token is successfully generated. The security token is then populated with user profile information from the configured API endpoint.
* `UserProviderListener` executes at the point where the authentication provider queries for a user object from the user provider.

Depending on your application, you might want to automatically register OAuth users who do not already have an existing user account. This can be done by overriding `UserProviderListener` and placing your registration code in the listener function, or by simply registering a separate listener in the chain.

Custom Services
---------------

You can register your own services or override existing ones by manually specifying the class to instantiate:

```php
$app->register(new Gigablah\Silex\OAuth\OAuthServiceProvider(), array(
    'oauth.services' => array(
        'my_service' => array(
            'class' => 'My\\Custom\\Namespace\\MyOAuthService',
            'key' => MY_API_KEY,
            'secret' => MY_API_SECRET,
            'scope' => array(),
            'user_endpoint' => 'https://my.domain/userinfo'
        ),
        // ...
    )
));
```

License
-------

Released under the MIT license. See the LICENSE file for details.

[1]: https://github.com/Lusitanian/PHPoAuthLib
[2]: http://silex.sensiolabs.org/doc/providers/security.html
[3]: http://silex.sensiolabs.org
[4]: http://getcomposer.org
[5]: http://twig.sensiolabs.org/
