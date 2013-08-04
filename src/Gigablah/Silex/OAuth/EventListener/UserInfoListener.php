<?php

namespace Gigablah\Silex\OAuth\EventListener;

use Gigablah\Silex\OAuth\OAuthServiceRegistry;
use Gigablah\Silex\OAuth\OAuthEvents;
use Gigablah\Silex\OAuth\Event\FilterTokenEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Listener to retrieve user information from the OAuth service provider.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class UserInfoListener implements EventSubscriberInterface
{
    private $registry;
    private $config;

    public function __construct(OAuthServiceRegistry $registry, array $config = array())
    {
        $this->registry = $registry;
        $this->config = $config;
    }

    public function onFilterToken(FilterTokenEvent $event)
    {
        $token = $event->getToken();
        $oauthService = $this->registry->getService($token->getService());

        $accessToken = $oauthService->getStorage()->retrieveAccessToken(preg_replace('/^.*\\\\/', '', get_class($oauthService)));

        if (false === $rawUserInfo = json_decode($oauthService->request($this->config[$token->getService()]['user_endpoint']), true)) {
            return;
        }

        $userInfo = array();
        $fieldMap = array(
            'id' => array('id', null),
            'name' => array('name', 'username', 'screen_name', null),
            'email' => array('email', function ($data, $service) {
                if ('twitter' === $service) {
                    return $data['screen_name'] . '@twitter.com';
                }
            })
        );

        foreach ($fieldMap as $key => $fields) {
            $userInfo[$key] = null;
            foreach ($fields as $field) {
                if (is_callable($field)) {
                    $userInfo[$key] = $field($rawUserInfo, $token->getService());
                    break;
                }
                if (isset($rawUserInfo[$field])) {
                    $userInfo[$key] = $rawUserInfo[$field];
                    break;
                }
            }
        }

        $token->setUser($userInfo['name']);
        $token->setAccessToken($accessToken);
        $token->setUid($userInfo['id']);
    }

    public static function getSubscribedEvents()
    {
        return array(
            OAuthEvents::TOKEN => 'onFilterToken'
        );
    }
}
