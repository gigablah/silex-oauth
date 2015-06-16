<?php

namespace atphp\silex\oauth\security\authentication\token;

use OAuth\Common\Token\TokenInterface as AccessTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * Token for OAuth Authentication responses.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthToken extends AbstractToken implements OAuthTokenInterface
{

    protected $service;
    protected $uid;
    protected $email;
    protected $accessToken;
    protected $providerKey;

    /**
     * Constructor.
     *
     * @param string $providerKey
     * @param array  $roles
     */
    public function __construct($providerKey, $roles = array())
    {
        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->providerKey = $providerKey;

        parent::__construct($roles);

        if ($roles) {
            $this->setAuthenticated(true);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return $this->accessToken->getAccessToken();
    }

    /**
     * {@inheritdoc}
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * {@inheritdoc}
     */
    public function setService($service)
    {
        $this->service = $service;
    }

    /**
     * {@inheritdoc}
     */
    public function getUid()
    {
        return $this->uid;
    }

    /**
     * {@inheritdoc}
     */
    public function setUid($uid)
    {
        $this->uid = $uid;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function setEmail($email)
    {
        $this->email = $email;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function setAccessToken(AccessTokenInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    public function getProviderKey()
    {
        return $this->providerKey;
    }

    public function serialize()
    {
        return serialize(array($this->service, $this->uid, $this->accessToken, $this->providerKey, parent::serialize()));
    }

    public function unserialize($str)
    {
        list($this->service, $this->uid, $this->accessToken, $this->providerKey, $parentStr) = unserialize($str);

        parent::unserialize($parentStr);
    }
}
