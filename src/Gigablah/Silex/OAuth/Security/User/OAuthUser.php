<?php

namespace Gigablah\Silex\OAuth\Security\User;

use Symfony\Component\Security\Core\User\User;

/**
 * Sample OAuth user class.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class StubOAuthUser extends User
{
    protected $oauthCredentials = array();

    public function setOAuthCredentials(array $oauthCredentials)
    {
        $this->oauthCredentials = $oauthCredentials;
    }

    public function addOAuthCredentials(array $oauthCredentials)
    {
        $this->oauthCredentials = array_merge($this->oauthCredentials, $oauthCredentials);
    }

    public function hasOAuthCredentials($provider, $providerId)
    {
        foreach ($this->oauthCredentials as $credentials) {
            if ($credentials['provider'] == $provider && $credentials['providerId'] == $providerId) {
                return true;
            }
        }

        return false;
    }
}
