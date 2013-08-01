<?php

namespace Gigablah\Silex\OAuth\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use OAuth\Common\Token\TokenInterface;

/**
 * Token for OAuth Authentication responses.
 *
 * @author Gigablah <gigablah@vgmdb.net>
 */
class OAuthToken extends AbstractToken
{
    protected $provider;
    protected $providerId;
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

    public function getCredentials()
    {
        return $this->accessToken->getAccessToken();
    }

    public function getProvider()
    {
        return $this->provider;
    }

    public function setProvider($provider)
    {
        $this->provider = $provider;
    }

    public function getProviderId()
    {
        return $this->providerId;
    }

    public function setProviderId($providerId)
    {
        $this->providerId = $providerId;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function setAccessToken(TokenInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    public function getProviderKey()
    {
        return $this->providerKey;
    }

    public function serialize()
    {
        return serialize(array($this->provider, $this->providerId, $this->accessToken, $this->providerKey, parent::serialize()));
    }

    public function unserialize($str)
    {
        list($this->provider, $this->providerId, $this->accessToken, $this->providerKey, $parentStr) = unserialize($str);

        parent::unserialize($parentStr);
    }
}
