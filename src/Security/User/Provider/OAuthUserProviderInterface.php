<?php

namespace atphp\silex\oauth\security\User\Provider;

use atphp\silex\oauth\security\authentication\token\OAuthTokenInterface;

/**
 * OAuth user provider interface.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
interface OAuthUserProviderInterface
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
