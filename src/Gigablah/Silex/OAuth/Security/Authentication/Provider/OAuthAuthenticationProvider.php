<?php

namespace Gigablah\Silex\OAuth\Security\Authentication\Provider;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthToken;
use Gigablah\Silex\OAuth\OAuthEvents;
use Gigablah\Silex\OAuth\Event\GetUserForTokenEvent;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Authentication provider handling OAuth Authentication responses.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthAuthenticationProvider implements AuthenticationProviderInterface
{
    private $dispatcher;
    private $userProvider;
    private $userChecker;
    private $providerKey;

    /**
     * Constructor.
     *
     * @param UserProviderInterface    $userProvider
     * @param UserCheckerInterface     $userChecker
     * @param string                   $providerKey
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, EventDispatcherInterface $dispatcher = null)
    {
        $this->userProvider = $userProvider;
        $this->userChecker  = $userChecker;
        $this->providerKey  = $providerKey;
        $this->dispatcher   = $dispatcher;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        $user = $token->getUser();

        if (!$user instanceof UserInterface && null !== $this->dispatcher) {
            $event = new GetUserForTokenEvent($token);
            $event->setUserProvider($this->userProvider);
            $this->dispatcher->dispatch(OAuthEvents::USER, $event);

            $user = $event->getToken()->getUser();
        }

        if (!$user instanceof UserInterface) {
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
