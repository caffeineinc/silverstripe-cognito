<?php

namespace App\Cognito;

use Exception;
use GuzzleHttp\Client;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Cookie;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Control\RequestHandler;

use Aws\CognitoIdentity\CognitoIdentityProvider;
use Aws\CognitoIdentity\CognitoIdentityClient;
use SilverStripe\Security\Security;
use SilverStripe\Security\SecurityToken;


/**
 * Authenticate a member
 */
class CognitoAuthenticationHandler implements AuthenticationHandler
{
    /**
     * @param HTTPRequest $request
     * @return Member
     *
     * @throws Exception
     */
    public function authenticateRequest(HTTPRequest $request)
    {

    }

    public function logIn(Member $member, $persistent = false, HTTPRequest $request = null)
    {
        // TODO: Implement logIn() method.
    }

    /**
     * @param HTTPRequest $request
     */
    public function logOut(HTTPRequest $request = null)
    {
        $request = $request ?: Controller::curr()->getRequest();
        $request->getSession()->restart($request);
    }

    /**
     * Returns the services supported by this authenticator
     *
     * The number should be a bitwise-OR of 1 or more of the following constants:
     * Authenticator::LOGIN, Authenticator::LOGOUT, Authenticator::CHANGE_PASSWORD,
     * Authenticator::RESET_PASSWORD, or Authenticator::CMS_LOGIN
     *
     * @return int
     */
    public function supportedServices()
    {
        return Authenticator::LOGIN || Authenticator::LOGOUT;
    }
}
