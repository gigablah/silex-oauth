<?php

namespace Gigablah\Silex\OAuth;

use Gigablah\Silex\OAuth\Security\Http\Firewall\OAuthAuthenticationListener;
use Gigablah\Silex\OAuth\Security\Core\Authentication\Provider\OAuthAuthenticationProvider;
use Silex\Application;
use Silex\ServiceProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use OAuth\ServiceFactory;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Storage\SymfonySession;
use OAuth\OAuth1\Service\ServiceInterface as OAuth1ServiceInterface;

/**
 * OAuth client authentication library.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class OAuthServiceProvider implements ServiceProviderInterface
{
    /**
     * {@inheritDoc}
     */
    public function register(Application $app)
    {
        $app['oauth.factory'] = $app->share(function ($app) {
            return new ServiceFactory();
        });

        $app['oauth.storage'] = $app->share(function ($app) {
            return new SymfonySession($app['session']);
        });

        $app['oauth'] = $app->protect(function ($strategy) use ($app) {
            if (!isset($app['oauth.credentials']) || !isset($app['oauth.credentials'][$strategy])) {
                throw new \InvalidArgumentException(sprintf('OAuth credentials not defined for the "%s" service.', $strategy));
            }

            $credentials = new Credentials(
                $app['oauth.credentials'][$strategy]['key'],
                $app['oauth.credentials'][$strategy]['secret'],
                $app['oauth.credentials'][$strategy]['callback']
            );

            $scope = isset($app['oauth.credentials'][$strategy]['scope'])
                ? $app['oauth.credentials'][$strategy]['scope']
                : array();

            $service = $app['oauth.factory']->createService($strategy, $credentials, $app['oauth.storage'], $scope);

            return $service;
        });

        $app['oauth.controller'] = $app->protect(function (Request $request, $strategy, $callback) use ($app) {
            try {
                $oauthService = $app['oauth']($strategy);
            } catch (\Exception $e) {
                throw new NotFoundHttpException();
            }

            if ($oauthService instanceof OAuth1ServiceInterface) {
                $token = $oauthService->getStorage()->retrieveAccessToken();
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
            return new RedirectResponse($app['router']->generate('_auth_strategy_callback', array(
                'strategy' => $strategy
            )), 302);
        });

        $app['oauth.userinfo'] = array();

        // generate the authentication factories
        foreach (array('facebook', 'google', 'twitter') as $type) {
            $app['security.authentication_listener.factory.oauth.'.$type] = $app->protect(function($name, $options) use ($type, $app) {
                if (!isset($app['security.authentication_listener.'.$name.'.oauth.'.$type])) {
                    $app['security.authentication_listener.'.$name.'.oauth.'.$type] = $app['security.authentication_listener.oauth._proto']($name, $type, $options);
                }

                if (!isset($app['security.authentication_provider.'.$name.'.oauth'])) {
                    $app['security.authentication_provider.'.$name.'.oauth'] = $app['security.authentication_provider.oauth._proto']($name);
                }
                return array(
                    'security.authentication_provider.'.$name.'.oauth',
                    'security.authentication_listener.'.$name.'.oauth.'.$type,
                    null,
                    'pre_auth'
                );
            });
        }

        $app['security.authentication_listener.oauth._proto'] = $app->protect(function ($providerKey, $provider, $options) use ($app) {
            return $app->share(function () use ($app, $providerKey, $provider, $options) {
                if (!isset($app['security.authentication.success_handler.'.$providerKey.'.oauth.'.$provider])) {
                    $app['security.authentication.success_handler.'.$providerKey.'.oauth.'.$provider] = $app['security.authentication.success_handler._proto']($providerKey, $options);
                }

                if (!isset($app['security.authentication.failure_handler.'.$providerKey.'.oauth.'.$provider])) {
                    $app['security.authentication.failure_handler.'.$providerKey.'.oauth.'.$provider] = $app['security.authentication.failure_handler._proto']($providerKey, $options);
                }

                $options['userinfo'] = $app['oauth.userinfo'][$provider];
                $options['provider'] = $provider;

                return new OAuthAuthenticationListener(
                    $app['security'],
                    $app['security.authentication_manager'],
                    $app['security.session_strategy'],
                    $app['security.http_utils'],
                    $providerKey,
                    $app['oauth']($provider),
                    $app['security.trust_resolver'],
                    $app['security.authentication.success_handler.'.$providerKey.'.oauth.'.$provider],
                    $app['security.authentication.failure_handler.'.$providerKey.'.oauth.'.$provider],
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
                    $app['security.user_provider.' . $app['oauth.firewall_name']],
                    $app['security.user_checker'],
                    $name
                );
            });
        });
    }

    /**
     * {@inheritDoc}
     */
    public function boot(Application $app)
    {
    }
}
