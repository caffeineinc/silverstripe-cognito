<?php

namespace App\Cognito;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Security\LoginForm as BaseLoginForm;
use SilverStripe\Security\Security;

/**
 * Log-in form for the "member" authentication method.
 *
 * Available extension points:
 * - "authenticationFailed": Called when login was not successful.
 *    Arguments: $data containing the form submission
 * - "forgotPassword": Called before forgot password logic kicks in,
 *    allowing extensions to "veto" execution by returning FALSE.
 *    Arguments: $member containing the detected Member record
 */
class CognitoLoginForm extends BaseLoginForm
{
    /**
     * Constructor
     *
     * @skipUpgrade
     * @param RequestHandler $controller The parent controller, necessary to
     *                               create the appropriate form action tag.
     * @param string $authenticatorClass Authenticator for this LoginForm
     * @param string $name The method on the controller that will return this
     *                     form object.
     * @param FieldList $fields All of the fields in the form - a
     *                                   {@link FieldList} of {@link FormField}
     *                                   objects.
     * @param FieldList|FormAction $actions All of the action buttons in the
     *                                     form - a {@link FieldList} of
     *                                     {@link FormAction} objects
     * @param bool $checkCurrentUser If set to TRUE, it will be checked if a
     *                               the user is currently logged in, and if
     *                               so, only a logout button will be rendered
     */
    public function __construct() {
        if (Security::getCurrentUser()) {
            // @todo find a more elegant way to handle this
            $logoutAction = Security::logout_url();
            $fields = FieldList::create(
                HiddenField::create('AuthenticationMethod', null, $this->authenticator_class, $this)
            );
            $actions = FieldList::create(
                FormAction::create('logout', _t(
                    'SilverStripe\\Security\\Member.BUTTONLOGINOTHER',
                    'Log in as someone else'
                ))
            );

        } else {
            $fields = $this->getFormFields();
            $actions = $this->getFormActions();
        }

        parent::__construct(null, get_class($this), $fields, $actions);

        if (isset($logoutAction)) {
            $this->setFormAction($logoutAction);
        }
    }

    /**
     * Build the FieldList for the login form
     *
     * @skipUpgrade
     * @return FieldList
     */
    protected function getFormFields()
    {
        $fields = FieldList::create(
            HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this)
        );

        $request = $this->getRequest();
        if ($request->getVar('BackURL')) {
            $backURL = $request->getVar('BackURL');
        } else {
            $backURL = $request->getSession()->get('BackURL');
        }

        if (isset($backURL)) {
            $fields->push(HiddenField::create('BackURL', 'BackURL', $backURL));
        }

        return $fields;
    }

    /**
     * Build default login form action FieldList
     *
     * @return FieldList
     */
    protected function getFormActions()
    {
        $actions = FieldList::create(
            FormAction::create('doLogin', _t('SilverStripe\\Security\\Member.BUTTONLOGIN', "Log in")),
            LiteralField::create(
                'forgotPassword',
                '<p id="ForgotPassword"><a href="' . Security::lost_password_url() . '">'
                . _t('SilverStripe\\Security\\Member.BUTTONLOSTPASSWORD', "I've lost my password") . '</a></p>'
            )
        );

        return $actions;
    }

    /**
     * The name of this login form, to display in the frontend
     * Replaces Authenticator::get_name()
     *
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(self::class . '.AUTHENTICATORNAME', "E-mail & Password");
    }
}
