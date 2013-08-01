<?php

namespace Gigablah\Silex\OAuth\Security\Authentication\Provider;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthToken;
use Gigablah\Silex\OAuth\Security\User\Provider\OAuthUserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Authentication provider handling OAuth Authentication responses.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class OAuthAuthenticationProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $userChecker;
    private $providerKey;

    public function __construct(OAuthUserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->providerKey  = $providerKey;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        $user = $this->userProvider->loadUserByOAuthCredentials($token->getProvider(), $token->getProviderId());

        if (!$user) {
            throw new BadCredentialsException('No user found for given credentials.');
        }

        $this->userChecker->checkPostAuth($user);

        $authenticatedToken = new OAuthToken($this->providerKey, $user->getRoles());
        $authenticatedToken->setAuthenticated(true);
        $authenticatedToken->setUser($user);

        return $authenticatedToken;
    }

    /**
     * {@inheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken && $this->providerKey === $token->getProviderKey();
    }
}
