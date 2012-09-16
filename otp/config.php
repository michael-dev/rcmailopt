<?php

global $dbuser, $dbpass, $dbdsn, $salt, $dbdsnsms, $dbdsnrcmail, $rcmailurl;

$dbdsn  = "mysql:host=localhost;dbname=otp"; # database otp use for otp management
$dbdsnsms = "mysql:host=localhost;dbname=gammu"; # database gammu used for sms sending
$dbdsnrcmail = "mysql:host=localhost;dbname=roundcubemail"; # database roundcubemail used for rcmail-plugin
$dbuser = "GIVE DB USER HERE";
$dbpass = "GIVE DB PASSWORD HERE";
$salt   = "INSERT RANDOM STRING HERE";
$rcmailurl = "https://webmail.example.com";

?>
