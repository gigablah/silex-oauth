<?php

namespace atphp\silex\oauth;

use atphp\silex\oauth\event_listener\UserInfoListener;
use atphp\silex\oauth\event_listener\UserProviderListener;
use atphp\silex\oauth\security\authentication\provider\OAuthAuthenticationProvider;
use atphp\silex\oauth\security\firewall\OAuthAuthenticationListener;
use atphp\silex\oauth\storage\SymfonySession;
use OAuth\Common\Http\Client\CurlClient;
use OAuth\ServiceFactory;
use Pimple\Container;
use Pimple\ServiceProviderInterface;

/**
 * OAuth client authentication library.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthServiceProvider implements ServiceProviderInterface
{

    public function register(Container $c)
    {
        $c['oauth.login_route'] = '_auth_service';
        $c['oauth.callback_route'] = '_auth_service_callback';
        $c['oauth.check_route'] = '_auth_service_check';
        $c['oauth.register_routes'] = true;
        $c['oauth.services'] = array();

        $c['oauth.http_client'] = function ($c) {
            return new CurlClient();
        };

        $c['oauth.factory'] = function ($c) {
            $factory = new ServiceFactory();
            $factory->setHttpClient($c['oauth.http_client']);
            return $factory;
        };

        $c['oauth.storage'] = function ($c) {
            return new SymfonySession($c['session']);
        };

        $c['oauth.url_generator'] = function ($c) {
            return $c['url_generator'];
        };

        $c['oauth'] = function ($c) {
            return new OAuthServiceRegistry(
                $c['oauth.factory'],
                $c['oauth.storage'],
                $c['oauth.url_generator'],
                $c['oauth.services'],
                array('callback_route' => $c['oauth.callback_route'])
            );
        };

        $c['oauth.user_info_listener'] = function ($c) {
            return new UserInfoListener($c['oauth'], $c['oauth.services']);
        };

        $c['oauth.user_provider_listener'] = function ($c) {
            return new UserProviderListener();
        };

        $c['security.authentication_listener.factory.oauth'] = $c->protect(function ($name, $options) use ($c) {
            if (!isset($c['security.authentication_listener.' . $name . '.oauth'])) {
                $c['security.authentication_listener.' . $name . '.oauth'] = $c['security.authentication_listener.oauth._proto']($name, $options);
            }

            if (!isset($c['security.authentication_provider.' . $name . '.oauth'])) {
                $c['security.authentication_provider.' . $name . '.oauth'] = $c['security.authentication_provider.oauth._proto']($name);
            }
            return array(
                'security.authentication_provider.' . $name . '.oauth',
                'security.authentication_listener.' . $name . '.oauth',
                null,
                'pre_auth'
            );
        });

        $c['security.authentication_listener.oauth._proto'] = $c->protect(function ($name, $options) use ($c) {
            return function () use ($c, $name, $options) {
                $options['login_route'] = $c['oauth.login_route'];
                $options['callback_route'] = $c['oauth.callback_route'];
                $options['check_route'] = $c['oauth.check_route'];

                if ($c['oauth.register_routes']) {
                    $c->match(
                        isset($options['login_path']) ? $options['login_path'] : '/auth/{service}',
                        function () {
                        }
                    )->bind($options['login_route']);

                    $c->get(
                        isset($options['callback_path']) ? $options['callback_path'] : '/auth/{service}/callback',
                        function () {
                        }
                    )->bind($options['callback_route']);

                    $c->get(
                        isset($options['check_path']) ? $options['check_path'] : '/auth/{service}/check',
                        function () {
                        }
                    )->bind($options['check_route']);
                }

                if (!isset($c['security.authentication.success_handler.' . $name . '.oauth'])) {
                    $c['security.authentication.success_handler.' . $name . '.oauth'] = $c['security.authentication.success_handler._proto']($name, $options);
                }

                if (!isset($c['security.authentication.failure_handler.' . $name . '.oauth'])) {
                    $c['security.authentication.failure_handler.' . $name . '.oauth'] = $c['security.authentication.failure_handler._proto']($name, $options);
                }

                $c['dispatcher']->addSubscriber($c['oauth.user_info_listener']);
                $c['dispatcher']->addSubscriber($c['oauth.user_provider_listener']);

                return new OAuthAuthenticationListener(
                    $c['security.token_storage'],
                    $c['security.authentication_manager'],
                    $c['security.session_strategy'],
                    $c['security.http_utils'],
                    $name,
                    $c['oauth'],
                    $c['security.authentication.success_handler.' . $name . '.oauth'],
                    $c['security.authentication.failure_handler.' . $name . '.oauth'],
                    $options,
                    $c['logger'],
                    $c['dispatcher'],
                    isset($options['with_csrf']) && $options['with_csrf'] && isset($c['form.csrf_provider']) ? $c['form.csrf_provider'] : null
                );
            };
        });

        $c['security.authentication_provider.oauth._proto'] = $c->protect(function ($name) use ($c) {
            return function () use ($c, $name) {
                return new OAuthAuthenticationProvider(
                    $c['security.user_provider.' . $name],
                    $c['security.user_checker'],
                    $name,
                    $c['dispatcher']
                );
            };
        });
    }

}
