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
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;

use Aws\CognitoIdentity\CognitoIdentityProvider;
use Aws\CognitoIdentity\CognitoIdentityClient;


/**
 * Authenticate a member
 */
class CognitoAuthenticationHandler implements AuthenticationHandler
{
    /**
     * @param HTTPRequest $request
     * @return Member
     */
    public function authenticateRequest(HTTPRequest $request)
    {
        $code = $request->getVar('code');
        if (!is_null($code)) {
            // move to factory
            $options = [
                'base_uri' => Environment::getEnv("AWS_COGNITO_DOMAIN"),
                'timeout' => 20,
                'connect_timeout' => 5,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'auth' => [
                    Environment::getEnv('AWS_APP_CLIENT_ID'),
                    Environment::getEnv('AWS_APP_CLIENT_SECRET')
                ]
            ];

            $client = new Client($options);
            $body = [
                "grant_type" => "authorization_code",
                "client_id" => Environment::getEnv('AWS_APP_CLIENT_ID'),
                "code" => $code,
                "redirect_uri" => Director::absoluteBaseURL() . "Security/login",
            ];

            $response = $client->post("/oauth2/token", ["form_params" => $body]);
            $body = \GuzzleHttp\json_decode($response->getBody()->getContents());

            // @todo still need to verify the JWT
            // https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
            list($headb64, $bodyb64, $cryptob64) = explode(".", $body->access_token);

            $payload = base64_decode($bodyb64);
            $claims = json_decode($payload);

            $memberList = Member::get()->where(["username" => $claims->username]);
            if (1 === $memberList->count()) {
                /**
                 * @var $member Member
                 */
                $member = $memberList->first();
                return $member;
            }

            throw new Exception("Member not authorised");

        }
    }

    /**
     * @param Member $member
     * @param bool $persistent
     * @param HTTPRequest $request
     */
    public function logIn(Member $member, $persistent = false, HTTPRequest $request = null)
    {
        // store user to session do we need to?
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
