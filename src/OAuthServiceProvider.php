<?php

namespace Gigablah\Silex\OAuth;

use Gigablah\Silex\OAuth\Security\Firewall\OAuthAuthenticationListener;
use Gigablah\Silex\OAuth\Security\Authentication\Provider\OAuthAuthenticationProvider;
use Gigablah\Silex\OAuth\Storage\SymfonySession;
use Gigablah\Silex\OAuth\EventListener\UserInfoListener;
use Gigablah\Silex\OAuth\EventListener\UserProviderListener;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Application;
use Silex\Api\EventListenerProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use OAuth\ServiceFactory;
use OAuth\Common\Http\Client\CurlClient;

/**
 * OAuth client authentication library.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthServiceProvider implements ServiceProviderInterface, EventListenerProviderInterface
{
    public function register(Container $app)
    {
        $app['oauth.login_route'] = '_auth_service';
        $app['oauth.callback_route'] = '_auth_service_callback';
        $app['oauth.check_route'] = '_auth_service_check';

        $app['oauth.register_routes'] = true;

        $app['oauth.services'] = array();

        $app['oauth.http_client'] = function ($app) {
            return new CurlClient();
        };

        $app['oauth.factory'] = function ($app) {
            $factory = new ServiceFactory();
            $factory->setHttpClient($app['oauth.http_client']);

            return $factory;
        };

        $app['oauth.storage'] = function ($app) {
            return new SymfonySession($app['session']);
        };

        $app['oauth.url_generator'] = function ($app) {
            return $app['url_generator'];
        };

        $app['oauth.csrf_token'] = $app->protect(function ($intention) use ($app) {
            if (!isset($app['form.csrf_provider'])) {
                return null;
            }

            $tokenManagerInterface = 'Symfony\Component\Security\Csrf\CsrfTokenManagerInterface';
            if ($app['form.csrf_provider'] instanceof $tokenManagerInterface) {
                return strval($app['form.csrf_provider']->getToken($intention));
            }

            return $app['form.csrf_provider']->generateCsrfToken($intention);
        });

        $app['oauth'] = function ($app) {
            return new OAuthServiceRegistry(
                $app['oauth.factory'],
                $app['oauth.storage'],
                $app['oauth.url_generator'],
                $app['oauth.services'],
                array('callback_route' => $app['oauth.callback_route'])
            );
        };

        $app['oauth.login_paths'] = function ($app) {
            $services = array_map('strtolower', array_keys($app['oauth.services']));
            $token = $app['oauth.csrf_token']('oauth');
            return array_map(function ($service) use ($app, $token) {
                return $app['url_generator']->generate($app['oauth.login_route'], array(
                    'service' => $service,
                    '_csrf_token' => $token
                ));
            }, array_combine($services, $services));
        };

        $app['oauth.user_info_listener'] = function ($app) {
            return new UserInfoListener($app['oauth'], $app['oauth.services']);
        };

        $app['oauth.user_provider_listener'] = function ($app) {
            return new UserProviderListener();
        };

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

        $app['security.authentication_listener.oauth._proto'] = $app->protect(function ($name, $options) use ($app) {
            return function () use ($app, $name, $options) {
                $options['login_route'] = $app['oauth.login_route'];
                $options['callback_route'] = $app['oauth.callback_route'];
                $options['check_route'] = $app['oauth.check_route'];

                if ($app['oauth.register_routes']) {
                    $app->match(
                        isset($options['login_path']) ? $options['login_path'] : '/auth/{service}',
                        function () {}
                    )->bind($options['login_route']);

                    $app->get(
                        isset($options['callback_path']) ? $options['callback_path'] : '/auth/{service}/callback',
                        function () {}
                    )->bind($options['callback_route']);

                    $app->get(
                        isset($options['check_path']) ? $options['check_path'] : '/auth/{service}/check',
                        function () {}
                    )->bind($options['check_route']);
                }

                if (!isset($app['security.authentication.success_handler.'.$name.'.oauth'])) {
                    $app['security.authentication.success_handler.'.$name.'.oauth'] = $app['security.authentication.success_handler._proto']($name, $options);
                }

                if (!isset($app['security.authentication.failure_handler.'.$name.'.oauth'])) {
                    $app['security.authentication.failure_handler.'.$name.'.oauth'] = $app['security.authentication.failure_handler._proto']($name, $options);
                }

                return new OAuthAuthenticationListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    $app['security.session_strategy'],
                    $app['security.http_utils'],
                    $name,
                    $app['oauth'],
                    $app['security.authentication.success_handler.'.$name.'.oauth'],
                    $app['security.authentication.failure_handler.'.$name.'.oauth'],
                    $options,
                    $app['logger'],
                    $app['dispatcher'],
                    isset($options['with_csrf']) && $options['with_csrf'] && isset($app['form.csrf_provider']) ? $app['form.csrf_provider'] : null
                );
            };
        });

        $app['security.authentication_provider.oauth._proto'] = $app->protect(function ($name) use ($app) {
            return function () use ($app, $name) {
                return new OAuthAuthenticationProvider(
                    $app['security.user_provider.'.$name],
                    $app['security.user_checker'],
                    $name,
                    $app['dispatcher']
                );
            };
        });
    }

    public function subscribe(Container $app, EventDispatcherInterface $dispatcher)
    {
        $app['dispatcher']->addSubscriber($app['oauth.user_info_listener']);
        $app['dispatcher']->addSubscriber($app['oauth.user_provider_listener']);
    }
}
