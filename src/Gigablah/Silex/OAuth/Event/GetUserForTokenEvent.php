<?php

namespace Gigablah\Silex\OAuth\Event;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Allows retrieval of a user based on OAuth token credentials.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class GetUserForTokenEvent extends Event
{
    private $token;
    private $user;

    public function __construct(OAuthTokenInterface $token)
    {
        $this->setToken($token);
    }

    public function setToken(OAuthTokenInterface $token)
    {
        $this->token = $token;
    }

    public function getToken()
    {
        return $this->token;
    }

    public function setUser(UserInterface $user)
    {
        $this->user = $user;
    }

    public function getUser()
    {
        return $this->user;
    }
}
