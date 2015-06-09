<?php

namespace atphp\silex\oauth\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Extends TokenInterface for OAuth usage.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
interface OAuthTokenInterface extends TokenInterface
{

    /**
     * Returns the OAuth service name.
     *
     * @return string The service name
     */
    public function getService();

    /**
     * Sets the OAuth service name.
     *
     * @param string $service The service name
     */
    public function setService($service);

    /**
     * Returns the OAuth uid.
     *
     * @return string The uid
     */
    public function getUid();

    /**
     * Sets the OAuth uid.
     *
     * @param string $uid The uid
     */
    public function setUid($uid);
}
