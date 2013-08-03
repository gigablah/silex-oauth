<?php

namespace Gigablah\Silex\OAuth\Security\User\Provider;

use Gigablah\Silex\OAuth\Security\User\StubOAuthUser;
use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * OAuth in-memory stub user provider.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthInMemoryUserProvider implements OAuthUserProviderInterface
{
    private $users;

    /**
     * Constructor.
     *
     * @param array $users An array of users
     */
    public function __construct(array $users = array())
    {
        foreach ($users as $username => $attributes) {
            $this->users[$username] = new StubOAuthUser($username, '', (array) $attributes['roles'], true, true, true, true);
            $this->users[$username]->setOAuthCredentials($attributes['credentials']);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        if (isset($this->users[$username])) {
            $user = $this->users[$username];
        } else {
            $user = new StubOAuthUser($username, '', array('ROLE_USER'), true, true, true, true);
        }

        return new StubOAuthUser($user->getUsername(), $user->getPassword(), $user->getRoles(), $user->isEnabled(), $user->isAccountNonExpired(), $user->isCredentialsNonExpired(), $user->isAccountNonLocked());
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByOAuthCredentials(OAuthTokenInterface $token)
    {
        $credentials = array(
            'service' => $token->getService(),
            'uid' => $token->getUid()
        );

        foreach ($this->users as $user) {
            if ($user->hasOAuthCredentials($credentials)) {
                return $user;
            }
        }

        $user = new StubOAuthUser($token->getUsername(), '', array('ROLE_USER'), true, true, true, true);
        $user->setOAuthCredentials(array($credentials));

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof StubOAuthUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function supportsClass($class)
    {
        return $class === 'Gigablah\\Silex\\OAuth\\Security\\User\\StubOAuthUser';
    }
}
