<?php


namespace App\Cognito;

use SilverStripe\ORM\DataExtension;

class CognitoMemberExtension extends DataExtension
{
    // define additional properties
    private static $db = [
        "username" =>  "Varchar(50)"
    ];
}
