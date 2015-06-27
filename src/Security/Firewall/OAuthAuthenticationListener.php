<?php

namespace Gigablah\Silex\OAuth\Security\Firewall;

use Gigablah\Silex\OAuth\OAuthServiceRegistry;
use Gigablah\Silex\OAuth\OAuthEvents;
use Gigablah\Silex\OAuth\Event\FilterTokenEvent;
use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthToken;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderAdapter;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use OAuth\Common\Storage\Exception\StorageException;
use OAuth\Common\Service\ServiceInterface as OAuthServiceInterface;
use OAuth\OAuth1\Service\ServiceInterface as OAuth1ServiceInterface;

/**
 * Authentication listener handling OAuth Authentication responses.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthAuthenticationListener extends AbstractAuthenticationListener
{
    protected $oauthServiceFactory;
    protected $csrfTokenManager;

    private $dispatcher;

    /**
     * Constructor.
     *
     * @param TokenStorageInterface                  $tokenStorage
     * @param AuthenticationManagerInterface         $authenticationManager
     * @param SessionAuthenticationStrategyInterface $sessionStrategy
     * @param HttpUtils                              $httpUtils
     * @param string                                 $providerKey
     * @param OAuthServiceRegistry                   $registry
     * @param AuthenticationSuccessHandlerInterface  $successHandler
     * @param AuthenticationFailureHandlerInterface  $failureHandler
     * @param array                                  $options
     * @param LoggerInterface                        $logger
     * @param EventDispatcherInterface               $dispatcher
     * @param mixed                                  $csrfTokenManager
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, OAuthServiceRegistry $registry, AuthenticationSuccessHandlerInterface $successHandler = null, AuthenticationFailureHandlerInterface $failureHandler = null, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, $csrfTokenManager = null)
    {
        if ($csrfTokenManager instanceof CsrfProviderInterface) {
            $csrfTokenManager = new CsrfProviderAdapter($csrfTokenManager);
        } elseif (null !== $csrfTokenManager && !$csrfTokenManager instanceof CsrfTokenManagerInterface) {
            throw new InvalidArgumentException('The CSRF token manager should be an instance of CsrfProviderInterface or CsrfTokenManagerInterface.');
        }

        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
            'login_route'    => '_auth_service',
            'check_route'    => '_auth_service_check',
            'csrf_parameter' => '_csrf_token',
            'intention'      => 'oauth',
            'post_only'      => false,
        ), $options), $logger, $dispatcher);
        $this->registry         = $registry;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->dispatcher       = $dispatcher;
    }

    /**
     * {@inheritDoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->httpUtils->checkRequestPath($request, $this->options['login_route'])) {
            if ($this->options['post_only'] && !$request->isMethod('post')) {
                return false;
            }

            return true;
        }

        if ($this->httpUtils->checkRequestPath($request, $this->options['callback_route'])) {
            return true;
        }

        if ($this->httpUtils->checkRequestPath($request, $this->options['check_route'])) {
            return true;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        $service = $request->attributes->get('service');
        $oauthService = $this->registry->getService($service);

        // redirect to auth provider if initiating
        if ($this->httpUtils->checkRequestPath($request, $this->options['login_route'])) {
            if ($this->options['post_only'] && !$request->isMethod('post')) {
                if (null !== $this->logger) {
                    $this->logger->debug(sprintf('Authentication method not supported: %s.', $request->getMethod()));
                }

                return null;
            }
            // CSRF checking only upon login
            if (null !== $this->csrfTokenManager) {
                $csrfToken = $request->get($this->options['csrf_parameter'], null, true);

                if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['intention'], $csrfToken))) {
                    throw new InvalidCsrfTokenException('Invalid CSRF token.');
                }
            }

            $authorizationParameters = array();
            if ($oauthService instanceof OAuth1ServiceInterface) {
                $token = $oauthService->requestRequestToken();
                $authorizationParameters = array(
                    'oauth_token' => $token->getRequestToken()
                );
            }
            $authorizationUri = $oauthService->getAuthorizationUri($authorizationParameters);

            return $this->httpUtils->createRedirectResponse($request, $authorizationUri->getAbsoluteUri());
        }

        // request access token upon callback
        if ($this->httpUtils->checkRequestPath($request, $this->options['callback_route'])) {
            if ($request->query->has('error')) {
                throw new AuthenticationException($request->query->get('error_description', $request->query->get('error')));
            }

            if ($oauthService instanceof OAuth1ServiceInterface) {
                try {
                    $serviceName = OAuthServiceRegistry::getServiceName($oauthService);
                    $token = $oauthService->getStorage()->retrieveAccessToken($serviceName);
                } catch (StorageException $exception) {
                    throw new AuthenticationException('Could not retrieve access token.', null, $exception);
                }

                if (!$request->query->has('oauth_token') || !$request->query->has('oauth_verifier')) {
                    throw new AuthenticationException('Token parameters missing.');
                }

                $oauthService->requestAccessToken(
                    $request->query->get('oauth_token'),
                    $request->query->get('oauth_verifier'),
                    $token->getRequestTokenSecret()
                );
            } else {
                if (!$request->query->has('code')) {
                    throw new AuthenticationException('Token parameters missing.');
                }

                $oauthService->requestAccessToken(
                    $request->query->get('code')
                );
            }

            // the access token is now stored in the session, redirect back to check_path
            return $this->httpUtils->createRedirectResponse(
                $request,
                $this->options['check_route']
            );
        }

        $authToken = new OAuthToken($this->providerKey);
        $authToken->setService($this->registry->mapServiceName($service));

        if (null !== $this->dispatcher) {
            $this->dispatcher->dispatch(OAuthEvents::TOKEN, new FilterTokenEvent($authToken));
        }

        return $this->authenticationManager->authenticate($authToken);
    }
}
