<?php

namespace Gigablah\Silex\OAuth\Security\User\Provider;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * OAuth user provider interface.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
interface OAuthUserProviderInterface extends UserProviderInterface
{
    /**
     * Loads a user based on OAuth credentials.
     *
     * @param OAuthTokenInterface $token
     *
     * @return UserInterface|null
     */
    public function loadUserByOAuthCredentials(OAuthTokenInterface $token);
}
