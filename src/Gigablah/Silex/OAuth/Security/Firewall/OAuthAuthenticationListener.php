<?php

namespace Gigablah\Silex\OAuth\Security\Firewall;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthToken;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
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
    protected $csrfProvider;
    protected $trustResolver;
    protected $token;
    protected $httpUtils;

    /**
     * {@inheritdoc}
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, \Closure $oauthServiceFactory, AuthenticationTrustResolverInterface $trustResolver, AuthenticationSuccessHandlerInterface $successHandler = null, AuthenticationFailureHandlerInterface $failureHandler = null, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfProviderInterface $csrfProvider = null)
    {
        parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
            'login_route'    => '_auth_service',
            'check_route'    => '_auth_service_check',
            'csrf_parameter' => '_csrf_token',
            'intention'      => 'oauth',
            'post_only'      => false,
        ), $options), $logger, $dispatcher);
        $this->oauthServiceFactory = $oauthServiceFactory;
        $this->csrfProvider        = $csrfProvider;
        $this->trustResolver       = $trustResolver;
        $this->token               = $securityContext->getToken();
        $this->httpUtils           = $httpUtils;
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
        $oauthServiceFactory = $this->oauthServiceFactory;
        $service = $request->attributes->get('service');
        $oauthService = $oauthServiceFactory($service);

        // redirect to auth provider if initiating
        if ($this->httpUtils->checkRequestPath($request, $this->options['login_route'])) {
            if ($this->options['post_only'] && !$request->isMethod('post')) {
                if (null !== $this->logger) {
                    $this->logger->debug(sprintf('Authentication method not supported: %s.', $request->getMethod()));
                }

                return null;
            }
            // CSRF checking only upon login
            if (null !== $this->csrfProvider) {
                $csrfToken = $request->get($this->options['csrf_parameter'], null, true);

                if (false === $this->csrfProvider->isCsrfTokenValid($this->options['intention'], $csrfToken)) {
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

        $accessToken = $oauthService->getStorage()->retrieveAccessToken(preg_replace('/^.*\\\\/', '', get_class($oauthService)));

        if (false === $rawUserInfo = json_decode($oauthService->request($this->options['services'][$service]['user_endpoint']), true)) {
            throw new AuthenticationException('User information could not be retrieved.');
        }

        $userInfo = array();
        $fieldMap = array(
            'id' => array('id', null),
            'name' => array('name', 'username', 'screen_name', null),
            'email' => array('email', function ($data, $service) {
                if ('twitter' === $service) {
                    return $data['screen_name'] . '@twitter.com';
                }
            })
        );

        foreach ($fieldMap as $key => $fields) {
            $userInfo[$key] = null;
            foreach ($fields as $field) {
                if (is_callable($field)) {
                    $userInfo[$key] = $field($rawUserInfo, $service);
                    break;
                }
                if (isset($rawUserInfo[$field])) {
                    $userInfo[$key] = $rawUserInfo[$field];
                    break;
                }
            }
        }

        $authToken = new OAuthToken($this->providerKey);
        $authToken->setUser($userInfo['name']);
        $authToken->setAccessToken($accessToken);
        $authToken->setService($service);
        $authToken->setUid($userInfo['id']);

        try {
            return $this->authenticationManager->authenticate($authToken);
        } catch (BadCredentialsException $e) {
            $user = $this->token && !$this->trustResolver->isAnonymous($token) ? $this->token->getUser() : null;

            // @todo: use dispatcher to dispatch process user event
            // $user = $this->userManipulator->createOrFindByEmail($info['name'], $info['email']);
            // $this->userManipulator->addAuthProvider($user, $authToken->getProvider(), $authToken->getProviderId());

            return $this->authenticationManager->authenticate($authToken);
        }
    }
}
