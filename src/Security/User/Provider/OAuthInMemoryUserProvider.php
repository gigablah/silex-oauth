<?php

namespace atphp\silex\oauth\security\User\Provider;

use atphp\silex\oauth\security\authentication\token\OAuthTokenInterface;
use atphp\silex\oauth\security\User\StubUser;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * OAuth in-memory stub user provider.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthInMemoryUserProvider implements UserProviderInterface, OAuthUserProviderInterface
{

    private $users;
    private $credentials;

    /**
     * Constructor.
     *
     * @param array $users       An array of users
     * @param array $credentials A map of usernames with
     */
    public function __construct(array $users = array(), array $credentials = array())
    {
        foreach ($users as $username => $attributes) {
            $password = isset($attributes['password']) ? $attributes['password'] : null;
            $email = isset($attributes['email']) ? $attributes['email'] : null;
            $enabled = isset($attributes['enabled']) ? $attributes['enabled'] : true;
            $roles = isset($attributes['roles']) ? (array) $attributes['roles'] : array();
            $user = new StubUser($username, $password, $email, $roles, $enabled, true, true, true);
            $this->createUser($user);
        }

        $this->credentials = $credentials;
    }

    public function createUser(UserInterface $user)
    {
        if (isset($this->users[strtolower($user->getUsername())])) {
            throw new \LogicException('Another user with the same username already exist.');
        }

        $this->users[strtolower($user->getUsername())] = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        if (isset($this->users[strtolower($username)])) {
            $user = $this->users[strtolower($username)];
        }
        else {
            $user = new StubUser($username, '', $username . '@example.org', array('ROLE_USER'), true, true, true, true);
            $this->createUser($user);
        }

        return new StubUser($user->getUsername(), $user->getPassword(), $user->getEmail(), $user->getRoles(), $user->isEnabled(), $user->isAccountNonExpired(), $user->isCredentialsNonExpired(), $user->isAccountNonLocked());
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByOAuthCredentials(OAuthTokenInterface $token)
    {
        foreach ($this->credentials as $username => $credentials) {
            foreach ($credentials as $credential) {
                if ($credential['service'] == $token->getService() && $credential['uid'] == $token->getUid()) {
                    return $this->loadUserByUsername($username);
                }
            }
        }

        $user = new StubUser($token->getUsername(), '', $token->getEmail(), array('ROLE_USER'), true, true, true, true);
        $this->createUser($user);

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof StubUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function supportsClass($class)
    {
        return $class === 'Gigablah\\Silex\\OAuth\\Security\\User\\StubUser';
    }
}
