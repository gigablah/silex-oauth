<?php

namespace atphp\silex\oauth\Event;

use atphp\silex\oauth\Security\Authentication\Token\OAuthTokenInterface;
use Symfony\Component\EventDispatcher\Event;

/**
 * Allows filtering of an OAuth token.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class FilterTokenEvent extends Event
{
    private $token;

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
}
