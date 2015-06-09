<?php

namespace atphp\silex\oauth\EventListener;

use atphp\silex\oauth\Event\GetUserForTokenEvent;
use atphp\silex\oauth\OAuthEvents;
use atphp\silex\oauth\Security\User\Provider\OAuthUserProviderInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Listener to match OAuth user with the local user provider.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class UserProviderListener implements EventSubscriberInterface
{

    /**
     * Populate the security token with a user from the local database.
     *
     * @param GetUserForTokenEvent $event
     */
    public function onGetUser(GetUserForTokenEvent $event)
    {
        $userProvider = $event->getUserProvider();

        if (!$userProvider instanceof OAuthUserProviderInterface) {
            return;
        }

        $token = $event->getToken();

        if ($user = $userProvider->loadUserByOAuthCredentials($token)) {
            $token->setUser($user);
        }
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents()
    {
        return array(
            OAuthEvents::USER => 'onGetUser'
        );
    }
}
