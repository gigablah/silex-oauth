<?php

namespace atphp\silex\oauth;

/**
 * Events thrown by the OAuth authentication process.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
final class OAuthEvents
{

    /**
     * The TOKEN event occurs when the security token is created.
     *
     * This event allows you to populate the token with additional
     * information, such as user details from the service provider API.
     * The event listener method receives a FilterTokenEvent instance.
     *
     * @var string
     */
    const TOKEN = 'oauth.token';

    /**
     * The USER event occurs when the token could not be matched to a user.
     *
     * The event listener method receives a GetUserForTokenEvent instance.
     *
     * @var string
     */
    const USER = 'oauth.user';
}
