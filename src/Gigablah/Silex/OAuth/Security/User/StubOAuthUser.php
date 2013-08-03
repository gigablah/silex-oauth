<?php

namespace Gigablah\Silex\OAuth\Security\User;

use Symfony\Component\Security\Core\User\AdvancedUserInterface;

/**
 * Stub OAuth user class for testing.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class StubOAuthUser implements AdvancedUserInterface
{
    private $username;
    private $password;
    private $enabled;
    private $accountNonExpired;
    private $credentialsNonExpired;
    private $accountNonLocked;
    private $roles;
    private $oauthCredentials;

    public function __construct($username, $password, array $roles = array(), $enabled = true, $userNonExpired = true, $credentialsNonExpired = true, $userNonLocked = true)
    {
        if (empty($username)) {
            throw new \InvalidArgumentException('The username cannot be empty.');
        }

        $this->username = $username;
        $this->password = $password;
        $this->enabled = $enabled;
        $this->accountNonExpired = $userNonExpired;
        $this->credentialsNonExpired = $credentialsNonExpired;
        $this->accountNonLocked = $userNonLocked;
        $this->roles = $roles;
        $this->oauthCredentials = array();
    }

    public function setOAuthCredentials(array $oauthCredentials)
    {
        $this->oauthCredentials = $oauthCredentials;
    }

    public function addOAuthCredentials(array $oauthCredentials)
    {
        $this->oauthCredentials = array_merge($this->oauthCredentials, $oauthCredentials);
    }

    public function hasOAuthCredentials(array $oauthCredentials)
    {
        foreach ($this->oauthCredentials as $credentials) {
            if ($credentials == $oauthCredentials) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * {@inheritdoc}
     */
    public function isAccountNonExpired()
    {
        return $this->accountNonExpired;
    }

    /**
     * {@inheritdoc}
     */
    public function isAccountNonLocked()
    {
        return $this->accountNonLocked;
    }

    /**
     * {@inheritdoc}
     */
    public function isCredentialsNonExpired()
    {
        return $this->credentialsNonExpired;
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled()
    {
        return $this->enabled;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
    }
}
