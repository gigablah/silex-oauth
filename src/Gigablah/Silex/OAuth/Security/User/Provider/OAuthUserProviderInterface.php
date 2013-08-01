<?php

namespace Gigablah\Silex\OAuth\Security\User\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * OAuth user provider interface.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
interface OAuthUserProviderInterface extends UserProviderInterface
{
    /**
     * Loads a user based on OAuth provider and uid.
     *
     * @param string $provider
     * @param string $providerId
     *
     * @return UserInterface|null
     */
    public function loadUserByOAuthCredentials($provider, $providerId);
}
