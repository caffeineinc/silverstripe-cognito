<?php

namespace App\Cognito;

use Exception;
use GuzzleHttp\Client;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Cookie;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Control\RequestHandler;

use Aws\CognitoIdentity\CognitoIdentityProvider;
use Aws\CognitoIdentity\CognitoIdentityClient;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;
use SilverStripe\Security\Security;
use SilverStripe\Security\SecurityToken;

/**
 * Authenticate a member
 */
class CognitoLoginHandler extends RequestHandler implements Authenticator
{
    /**
     * Applicable exceptions from the Cognito token response
     * @see https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
     */
    const ERR_INVALID_REQUEST = "invalid_request";
    const ERR_INVALID_CLIENT = "invalid_client";
    const ERR_INVALID_GRANT = "invalid_grant";
    const ERR_INVALID_UNAUTHORIZED_CLIENT = "unauthorized_client";
    const ERR_INVALID_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

    public function __construct($message = "", $code = 0, Throwable $previous = null) {
        // get the correct code, and grant from
        list($httpCode, $cognitoMessage) = $this->getErrorMessage($message);

        parent::__construct($cognitoMessage, $httpCode, $previous);
    }

    private function getErrorMessage($message = null){
        switch ($message){
            default:
                return [400, "Unknown error, could not login user"];

            case self::ERR_INVALID_GRANT:
                return [400, "Authorization code has been consumed already or does not exist"];

            case self::ERR_INVALID_CLIENT:
                return [500, "The request is missing a required parameter, includes an unsupported parameter value"];

            case self::ERR_INVALID_REQUEST:
                return [500, "The authentication request is missing a required parameter, or otherwise malformed"];

            case self::ERR_INVALID_UNAUTHORIZED_CLIENT:
                return [500, "The app client has not been authorised for refreshing tokens"];

            case self::ERR_INVALID_UNSUPPORTED_GRANT_TYPE:
                return [500, "grant_type is not authorization_code or refresh_token"];
        }
    }

    /**
     * @var array
     */
    private static $url_handlers = [
        '' => 'login',
        'login' => 'login',
    ];

    /**
     * @var array
     */
    private static $allowed_actions = [
        'login',
        'logout',
        'doLogIn',
    ];

    /**
     * Log in
     */
    public function login($request)
    {
        $code = $request->getVar('code');
        if (!is_null($code)) {
            return $this->auth($request);
        }

        $member = Security::getCurrentUser();
        if (!$member && !SecurityToken::inst()->checkRequest($this->getRequest())) {
            return [
                'Form' => $this->loginForm()
            ];
        }

        return $this->doLogIn($request);
    }

    public function logout($request)
    {

     $request = $request ?: Controller::curr()->getRequest();
        $request->getSession()->restart($request);
    }

    /**
     */
    public function loginForm()
    {
        return CognitoLoginForm::create($this);
    }

    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        // TODO: Implement authenticate() method.
    }

    public function auth($request)
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
                "redirect_uri" => Director::absoluteBaseURL() . "Security/login"
            ];

            try {
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
                    $this->performLogin($member, $request);
                    return $this->redirectBack();
                }

            } catch (Exception $exception) {
                $response = \GuzzleHttp\json_decode($exception->getResponse()->getBody()->getContents());
                list($code, $error) = $this->getErrorMessage($response->error);

                if (400 === $exception->getCode()) {
                    $form = CognitoLoginForm::create();
                    $form->setMessage($error, 'bad');
                    return $form->getRequestHandler()->redirectBackToForm();
                }

                throw new Exception($error, $code, $exception);
            }
        }

        throw new Exception($this->getErrorMessage(), $code);
    }

    public function doLogIn($request)
    {
        $redirectUrl = Environment::getEnv("AWS_COGNITO_DOMAIN") . "/login?";

        $params = [
            "response_type" => "code",
            "client_id" => Environment::getEnv('AWS_APP_CLIENT_ID')
        ];

        $redirectUrl .= http_build_query($params) . "&redirect_uri=" . Director::absoluteBaseURL() . "Security/login";
        return $this->redirect($redirectUrl);
    }

    public function performLogin($member, $request){
        /** IdentityStore */
        $rememberMe = (isset($data['Remember']) && Security::config()->get('autologin_enabled'));
        /** @var IdentityStore $identityStore */
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logIn($member, $rememberMe, $request);

        return $member;
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
        return Authenticator::LOGIN | Authenticator::LOGOUT;
    }

    public function getLoginHandler($link){
        return new self();
    }

    public function checkPassword(Member $member, $password, ValidationResult &$result = null)
    {
        // TODO: Implement checkPassword() method.
    }

    public function getLogOutHandler($link)
    {
        return new LogoutHandler();
    }

    public function getChangePasswordHandler($link){

    }
    public function getLostPasswordHandler($link){

    }
}
