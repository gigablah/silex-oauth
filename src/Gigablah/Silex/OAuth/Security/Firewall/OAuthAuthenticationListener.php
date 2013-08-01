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
 * @author Gigablah <gigablah@vgmdb.net>
 */
class OAuthAuthenticationListener extends AbstractAuthenticationListener
{
    private $oauthService;
    private $csrfProvider;
    private $trustResolver;
    private $token;
    protected $httpUtils;

    /**
     * {@inheritdoc}
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, OAuthServiceInterface $oauthService, AuthenticationTrustResolverInterface $trustResolver, AuthenticationSuccessHandlerInterface $successHandler = null, AuthenticationFailureHandlerInterface $failureHandler = null, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfProviderInterface $csrfProvider = null)
    {
        parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
            'csrf_parameter' => '_csrf_token',
            'intention'      => 'oauth',
            'post_only'      => false,
        ), $options), $logger, $dispatcher);
        $this->oauthService    = $oauthService;
        $this->csrfProvider    = $csrfProvider;
        $this->trustResolver   = $trustResolver;
        $this->token           = $securityContext->getToken();
        $this->httpUtils       = $httpUtils;
    }

    /**
     * {@inheritDoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->httpUtils->checkRequestPath($request, $this->options['login_path'])) {
            if ($this->options['post_only'] && !$request->isMethod('post')) {
                return false;
            }
            return true;
        }

        return parent::requiresAuthentication($request);
    }

    /**
     * {@inheritDoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        // redirect to auth provider
        if ($this->httpUtils->checkRequestPath($request, $this->options['login_path'])) {
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
            if ($this->oauthService instanceof OAuth1ServiceInterface) {
                $token = $this->oauthService->requestRequestToken();
                $authorizationParameters = array(
                    'oauth_token' => $token->getRequestToken()
                );
            }
            $authorizationUri = $this->oauthService->getAuthorizationUri($authorizationParameters);

            return $this->httpUtils->createRedirectResponse($request, $authorizationUri->getAbsoluteUri());
        }

        $accessToken = $this->oauthService->getStorage()->retrieveAccessToken($this->oauthService->service());

        if (false === $rawUserInfo = json_decode($this->oauthService->request($this->options['userinfo']['uri']), true)) {
            throw new AuthenticationException('User information could not be retrieved.');
        }

        $userInfo = array();
        foreach ($this->options['userinfo']['fields'] as $key => $field) {
            $userInfo[$key] = isset($rawUserInfo[$field]) ? $rawUserInfo[$field] : null;
        }

        if (!$userInfo['name']) {
            $userInfo['name'] = $userInfo['id'];
        }
        if (!$userInfo['email']) {
            $userInfo['email'] = str_replace(' ', '', $userInfo['name']) . '@' . $this->options['provider'] . '.com';
        }

        $authToken = new OAuthToken($this->providerKey);
        $authToken->setUser($userInfo['name']);
        $authToken->setAccessToken($accessToken);
        $authToken->setProvider($this->options['provider']);
        $authToken->setProviderId($userInfo['id']);

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
