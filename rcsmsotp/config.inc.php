<?php

$rcmail_config['otpinfo'] = <<<EOT
<div style="margin-left:auto;margin-right:auto;margin-top:4%;width:380px;border-radius:10px;padding:10px;-moz-border-radius:10px;background-color:lightgrey;text-align:center;color:red;">
Von fremden oder nicht vertrauenswürdigen Rechnern bitte <a href="https://{$_SERVER["SERVER_NAME"]}/otp">Einmalpasswörter</a> für den Zugang verwenden.
</div>
EOT;

$rcmail_config['otp_salt'] = "rcotp";
$rcmail_config['otp_whiteliste'] = Array(); /* subnet-masks, dns names

