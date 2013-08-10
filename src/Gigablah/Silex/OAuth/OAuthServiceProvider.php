<?php

namespace Gigablah\Silex\OAuth;

use Gigablah\Silex\OAuth\Security\Firewall\OAuthAuthenticationListener;
use Gigablah\Silex\OAuth\Security\Authentication\Provider\OAuthAuthenticationProvider;
use Gigablah\Silex\OAuth\EventListener\UserInfoListener;
use Gigablah\Silex\OAuth\EventListener\UserProviderListener;
use Silex\Application;
use Silex\ServiceProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use OAuth\ServiceFactory;
use OAuth\Common\Storage\SymfonySession;
use OAuth\OAuth1\Service\ServiceInterface as OAuth1ServiceInterface;

/**
 * OAuth client authentication library.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthServiceProvider implements ServiceProviderInterface
{
    protected $routes;

    public function register(Application $app)
    {
        // used to register routes for oauth entry point and callbacks
        $this->routes = array();

        $that = $this;

        $app['oauth.login_route'] = '_auth_service';
        $app['oauth.callback_route'] = '_auth_service_callback';
        $app['oauth.check_route'] = '_auth_service_check';

        $app['oauth.services'] = array();

        $app['oauth.factory'] = $app->share(function ($app) {
            return new ServiceFactory();
        });

        $app['oauth.storage'] = $app->share(function ($app) {
            return new SymfonySession($app['session']);
        });

        $app['oauth'] = $app->share(function ($app) {
            return new OAuthServiceRegistry(
                $app['oauth.factory'],
                $app['oauth.storage'],
                $app['url_generator'],
                $app['oauth.services'],
                array('callback_route' => $app['oauth.callback_route'])
            );
        });

        $app['oauth.user_info_listener'] = $app->share(function ($app) {
            return new UserInfoListener($app['oauth'], $app['oauth.services']);
        });

        $app['oauth.user_provider_listener'] = $app->share(function ($app) {
            return new UserProviderListener();
        });

        $app['oauth.controller'] = $app->protect(function (Request $request, $service) use ($app) {
            try {
                $oauthService = $app['oauth']->getService($service);
            } catch (\Exception $e) {
                throw new NotFoundHttpException();
            }

            if ($oauthService instanceof OAuth1ServiceInterface) {
                $token = $oauthService->getStorage()->retrieveAccessToken(OAuthServiceRegistry::getServiceName($oauthService));
                $oauthService->requestAccessToken(
                    $request->query->get('oauth_token'),
                    $request->query->get('oauth_verifier'),
                    $token->getRequestTokenSecret()
                );
            } else {
                $oauthService->requestAccessToken(
                    $request->query->get('code')
                );
            }

            // the access token is now stored in the session, redirect back to check_path
            return new RedirectResponse($app['url_generator']->generate($app['oauth.check_route'], array(
                'service' => $service
            ), true), 302);
        });

        $app['security.authentication_listener.factory.oauth'] = $app->protect(function ($name, $options) use ($app) {
            if (!isset($app['security.authentication_listener.'.$name.'.oauth'])) {
                $app['security.authentication_listener.'.$name.'.oauth'] = $app['security.authentication_listener.oauth._proto']($name, $options);
            }

            if (!isset($app['security.authentication_provider.'.$name.'.oauth'])) {
                $app['security.authentication_provider.'.$name.'.oauth'] = $app['security.authentication_provider.oauth._proto']($name);
            }
            return array(
                'security.authentication_provider.'.$name.'.oauth',
                'security.authentication_listener.'.$name.'.oauth',
                null,
                'pre_auth'
            );
        });

        $app['security.authentication_listener.oauth._proto'] = $app->protect(function ($name, $options) use ($app, $that) {
            return $app->share(function () use ($app, $name, $options, $that) {
                $that->addRoute(
                    'match',
                    isset($options['login_path']) ? $options['login_path'] : '/auth/{service}',
                    function () {},
                    $options['login_route'] = $app['oauth.login_route']
                );
                $that->addRoute(
                    'get',
                    isset($options['callback_path']) ? $options['callback_path'] : '/login/{service}/callback',
                    $app['oauth.controller'],
                    $options['callback_route'] = $app['oauth.callback_route']
                );
                $that->addRoute(
                    'get',
                    isset($options['check_path']) ? $options['check_path'] : '/auth/{service}/check',
                    function () {},
                    $options['check_route'] = $app['oauth.check_route']
                );

                if (!isset($app['security.authentication.success_handler.'.$name.'.oauth'])) {
                    $app['security.authentication.success_handler.'.$name.'.oauth'] = $app['security.authentication.success_handler._proto']($name, $options);
                }

                if (!isset($app['security.authentication.failure_handler.'.$name.'.oauth'])) {
                    $app['security.authentication.failure_handler.'.$name.'.oauth'] = $app['security.authentication.failure_handler._proto']($name, $options);
                }

                $oauthServiceRegistry = $app['oauth'];

                return new OAuthAuthenticationListener(
                    $app['security'],
                    $app['security.authentication_manager'],
                    $app['security.session_strategy'],
                    $app['security.http_utils'],
                    $name,
                    $oauthServiceRegistry,
                    $app['security.authentication.success_handler.'.$name.'.oauth'],
                    $app['security.authentication.failure_handler.'.$name.'.oauth'],
                    $options,
                    $app['logger'],
                    $app['dispatcher'],
                    isset($options['with_csrf']) && $options['with_csrf'] && isset($app['form.csrf_provider']) ? $app['form.csrf_provider'] : null
                );
            });
        });

        $app['security.authentication_provider.oauth._proto'] = $app->protect(function ($name) use ($app) {
            return $app->share(function () use ($app, $name) {
                return new OAuthAuthenticationProvider(
                    $app['security.user_provider.'.$name],
                    $app['security.user_checker'],
                    $name,
                    $app['dispatcher']
                );
            });
        });
    }

    public function boot(Application $app)
    {
        foreach ($this->routes as $route) {
            list($method, $pattern, $callback, $name) = $route;

            $app->$method($pattern, $callback)->bind($name);
        }

        $app['dispatcher']->addSubscriber($app['oauth.user_info_listener']);
        $app['dispatcher']->addSubscriber($app['oauth.user_provider_listener']);
    }

    protected function addRoute($method, $pattern, $callback, $name)
    {
        $this->routes[] = array($method, $pattern, $callback, $name);
    }
}
