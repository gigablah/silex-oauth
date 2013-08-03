<?php

namespace Gigablah\Silex\OAuth\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use OAuth\Common\Token\TokenInterface as AccessTokenInterface;

/**
 * Token for OAuth Authentication responses.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthToken extends AbstractToken implements OAuthTokenInterface
{
    protected $service;
    protected $uid;
    protected $accessToken;
    protected $providerKey;

    public function __construct($providerKey, array $roles = array())
    {
        parent::__construct($roles);

        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->providerKey = $providerKey;

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
