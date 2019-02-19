# rcmailopt

RoundCubeMail with SMS-based OTP

## setup

1. install and configure gammu-smsd, for example with an UTMS USB stick, on the server, to use the mysql database gammu
2. install otp into apache2, adopt .htaccess so that admin.php can only be accessed by valid users
3. add and enable roundcubemail plugins rcsmsotp `$rcmail_config['plugins'] = array("rcsmsotp");`
4. configure plugin, see config.inc.php.

## new users

They visit otp/admin.php and set a PIN and a mobile telephone number.

## existing users

They visit otp/index.php to request a RC-Mail OTP.

## Licence

If not mentioned otherwise in a file, this project
is licenced under GNU/GPL v3.
 (C) 2012 Michael Braun <michael-dev@fami-braun.de>

http://www.gnu.de/documents/gpl.de.html


