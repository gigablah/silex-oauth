<?php

namespace Gigablah\Silex\OAuth;

use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use OAuth\ServiceFactory;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Service\ServiceInterface;
use OAuth\Common\Storage\TokenStorageInterface;

/**
 * Registry for instantiating and memoizing OAuth service providers.
 *
 * @author Chris Heng <bigblah@gmail.com>
 */
class OAuthServiceRegistry
{
    protected $services;
    protected $config;
    protected $options;
    protected $oauthServiceFactory;
    protected $oauthStorage;
    protected $urlGenerator;

    /**
     * Constructor.
     *
     * @param ServiceFactory        $oauthServiceFactory
     * @param TokenStorageInterface $oauthStorage
     * @param UrlGeneratorInterface $urlGenerator
     * @param array                 $config
     * @param array                 $options
     */
    public function __construct(ServiceFactory $oauthServiceFactory, TokenStorageInterface $oauthStorage, UrlGeneratorInterface $urlGenerator, array $config = array(), array $options = array())
    {
        $this->services = array();
        $this->config = $config;
        $this->options = $options;
        $this->oauthServiceFactory = $oauthServiceFactory;
        $this->oauthStorage = $oauthStorage;
        $this->urlGenerator = $urlGenerator;
    }

    /**
     * Retrieve a service by name.
     *
     * @param string $service
     *
     * @return ServiceInterface
     */
    public function getService($service)
    {
        if (isset($this->services[$service])) {
            return $this->services[$service];
        }

        return $this->services[$service] = $this->createService($service);
    }

    /**
     * Retrieve the name from a service instance.
     *
     * @param ServiceInterface $oauthService
     *
     * @return string
     */
    public static function getServiceName(ServiceInterface $oauthService)
    {
        return preg_replace('/^.*\\\\/', '', get_class($oauthService));
    }

    /**
     * Instantiate a service by name.
     *
     * @param string $service
     *
     * @return ServiceInterface
     */
    protected function createService($service)
    {
        if (!isset($this->config[$service])) {
            throw new \InvalidArgumentException(sprintf('OAuth configuration not defined for the "%s" service.', $service));
        }

        $credentials = new Credentials(
            $this->config[$service]['key'],
            $this->config[$service]['secret'],
            $this->urlGenerator->generate($this->options['callback_route'], array(
                'service' => $service
            ), true)
        );

        $scope = isset($this->config[$service]['scope']) ? $this->config[$service]['scope'] : array();
        $uri = isset($this->config[$service]['uri']) ? new Uri($this->config[$service]['uri']) : null;

        if (isset($this->config[$service]['class'])) {
            $this->oauthServiceFactory->registerService($service, $this->config[$service]['class']);
            unset($this->config[$service]['class']);
        }

        return $this->oauthServiceFactory->createService(
            $service,
            $credentials,
            $this->oauthStorage,
            $scope,
            $uri
        );
    }
}
