<?php

class rcsmsotp extends rcube_plugin
{
  public $noajax = true;
  public $noframe = true;
  public $task = 'login|logout|settings';

  function init()
  {
    $this->add_hook('template_object_loginform', array($this, 'add_otp_info'));
    $this->add_hook('authenticate', array($this, 'authenticate'));
  }

  public function add_otp_info($arg)
  {
    $rcmail = rcmail::get_instance();
    $this->load_config();
    $msg = $rcmail->config->get('otpinfo');
    if ($msg)
      $rcmail->output->add_header( $msg );

    return $arg;
  }

  public function authenticate($args) {
    $rcmail = rcmail::get_instance();
    $otpSuccess = $this->authOtp($rcmail, $args);

    /** Ideas
     * a) require confirmed browser as in pre-used, whitelisted ip or otp done
     * b) add first device (not yet implemented)
     * c) add all devices (notify-only)
     * d) disabled
     */
    // null or 0: disabled, 1: report-only, 2: required for login
    $doAuthBrowser = $rcmail->config->get('otp_auth_browser', 0);
    if ($doAuthBrowser) {
      $browserSuccess = $this->authBrowser($rcmail, $args, $otpSuccess);
      $needConfirmedBrowser = ($doAuthBrowser == 2);
      if ($browserSuccess === false && $needConfirmedBrowser) {
        $args["abort"] = true;
        $args["error"] = "Browser unbekannt";
      }
    }
    return $args;
  }

  /** return false on non-otp credentials and true on correct otp credentials */ 
  private function authOtp(&$rcmail, &$args) {
    $res = $rcmail->db->query("SELECT imappass FROM roundcubemail.otp WHERE otp.username = ? AND otp.rcube_otp = ? AND otp.validUntil > ?", $args['user'], $args['pass'], time());
    $dbpass = $rcmail->db->fetch_assoc($res);
    $ret = false;

    // Valid one time password?
    if($dbpass) {
        $rcmail->db->query("DELETE FROM roundcubemail.otp WHERE otp.username = ? AND otp.rcube_otp = ?", array($args['user'], $args['pass']));
        $args['pass'] = $dbpass['imappass'];
        $ret = true;
    }
    $rcmail->db->query("DELETE FROM roundcubemail.otp WHERE otp.validUntil < ?", time());
    return $ret;
  }

  /** return
   * a) true on known or confirmed browser
   * b) false else
   */
  private function authBrowser(&$rcmail, &$args, $trustedLoginSuccess) {
    // static salt + salt from browser + username -> cookieName
    // get cookie to identify browser for this user but avoid trackable names
    $cookieSalt = $rcmail->config->get('otp_salt', "otp");

    $cookieNameSalt = "rcmail_otp_salt";
    if (isset($_COOKIES[$cookieNameSalt])) {
      $cookieNameSaltValue = (string) $_COOKIES[$cookieNameSalt];
    } else {
      $cookieNameSaltValue = bin2hex(random_bytes(4));
      rcube_utils::setcookie($cookieNameSalt, $cookieNameSaltValue, time() + 100 * 365 * 24 * 3600);
    }
    $cookieSalt .= "#".substr($cookieNameSaltValue,0,8);

    $cookieName = "rcmail_otp_".hash_hmac("sha256", $args["user"], $cookieSalt);

    // check if this is a known browser
    if (isset($_COOKIES[$cookieName])) {
      $cookieValue = $_COOKIES[$cookieName];
      $dbValue = hash_hmac("sha256", $cookieValue, $cookieSalt);

      $res = $rcmail->db->query("SELECT * FROM roundcubemail.otp_browser
                                 WHERE otp_browser.username = ? AND otp_browser.cookie = ?",
                                array($args["user"], $dbValue));
      $dbres = $rcmail->db->fetch_assoc($res);
    } else {
      $dbres = false;
    }

    // check if this is trusted
    if ($dbres && $dbres["confirmed"]) {
      $trusted = true;
    } else {
      // check ip against whitelist (like, 172.16.0.0/16, 192.168.0.0/16, some DNS names)
      $whitelist = $rcmail->config->get('otp_whitelist', Array());
      $trusted = false;
      $ip = rcube_utils::remote_addr();
      foreach ($whiteliste as $wi) {
        if (self::cidr_match($ip, $wi)) {
          $trusted = true;
          break;
        }
      }
      $trusted = $trusted || $optSuccess;
    }

    if (!$dbres) {
      // this is a new browser, so generate a cookie
      $cookieValue = bin2hex(random_bytes(30));
      $dbValue = hash_hmac("sha256", $cookieValue, $cookieSalt);
      $browserName = $_SERVER['HTTP_USER_AGENT']; // FIXME ask user -> link to portal?, GeoIP2

      // if login is going to fail anyway, do not bother to register and send back cookie to hide this
      $registerBrowser = $otpSuccess || $rcmail->login($args['user'], $args['pass'], $args['host'], $args['cookiecheck']);
      if ($registerBrowser) {
        $rcmail->db->query("INSERT INTO roundcubemail.otp_browser (username, cookie, name, createdAt, lastUsed, confirmed) VALUES (?, ?, ?, ?, ?)",
          array($args["user"], $dbValue, $browserName, time(), time(), ($trusted ? 1 : 0)));
        $dbres = [ "confirmed" => ($trusted ? 1 : 0) ];
        // send notification
        if (!$trusted)
          $this->notifyNewBrowser($rcmail, $browserName);
      }
    } else {
      $rcmail->db->query("UPDATE roundcubemail.otp_browser WHERE otp_browser.username = ? AND otp_browser.cookie = ? SET lastUsed = ?, confirmed => ?",
                         array($args["user"], $dbValue, time(), $trusted ? 1 : 0));
    }
    rcube_utils::setcookie($cookieName, $cookieValue, time() + 100 * 365 * 24 * 3600);

    return $trusted;
  }

  private function notifyNewBrowser(&$rcmail, $browserName) {
    $identity_arr = $rcmail->user->get_identity();
    $from         = $identity_arr['email'];
    $from_string  = format_email_recipient($identity_arr['email'], $identity_arr['name']);
    $mailto       = $from;
    $subject      = "Ein neues Gerät wurde mit Roundcubemail verwendet";
    $message_text = 'Hallo '.$identity_arr["name"].',

es wurde ein neuer Browser mit Roundcubemail verwendet.

Browser : '.$browserName.'
IP      : '.$_SERVER["REMOTE_ADDR"].'
Standort: '.'

Du kannst deine Geräte in den Einstellungen von RoundCubeMail ändern.

https://webmail.fami-braun.de';

    $OUTPUT   = $this->rcube->output;
    $SENDMAIL = new rcmail_sendmail(null, array(
      'sendmail' => true,
      'from' => $from,
      'mailto' => $mailto,
      'dsn_enabled' => false,
      'charset' => 'UTF-8',
      'error_handler' => function() use ($OUTPUT) {
         call_user_func_array(array($OUTPUT, 'show_message'), func_get_args());
         $OUTPUT->send();
       }
    ));
    $headers = array(
      'Date' => $rcmail->user_date(),
      'From' => $from_string,
      'To' => $mailto,
      'Subject' => $subject,
      'User-Agent' => $rcmail->config->get('useragent'),
      'Message-ID' => $rcmail->gen_message_id($from),
      'X-Sender' => $from
    );
    // create message
    $MAIL_MIME = $SENDMAIL->create_message($headers, $message_text, false, array());
    $SENDMAIL->deliver_message($MAIL_MIME);
  }

  private static function maskIp($ip, $ipNumBytes, $mask) {
    $ip = inet_pton($ip);
    $ip = current(unpack("A".$ipNumBytes, $ip));

    for ($i = 0; $i < $ipNumBytes; $i++, $mask -= 8) {
      if ($mask >= 8) continue;
      // trim some bits
      $l_mask = 0;
      if ($mask > 0)
        $l_mask = 255 << (8-$mask);
      $ip[$i] = chr(ord($ip[$i]) & $l_mask);
    }

    return current(unpack("H".($ipNumBytes*2), $ip));
  }

  /**
   * Check the client IP against a value in CIDR notation.
   */
  private static function cidr_match($ip, $cidr)
  {
    if (strpos($cidr, '/') === false) {
        $cidr .= '/';
    }
    list($subnet, $bits) = explode('/', $cidr,2);

    if (filter_var($subnet, FILTER_VALIDATE_IP)) {
      $subnets = [ $subnet ];
    } else if (filter_var($subnet, FILTER_VALIDATE_DOMAIN,  FILTER_FLAG_HOSTNAME )) {
      $records = dns_get_record($subnet, DNS_A + DNS_AAAA);
      if ($records === false)
        return false;
      $subnets = [];
      foreach ($records as $record) {
        if ($records["type"] == "A")
          $subnets[] = $records["ip"];
        elseif ($records["type"] == "AAAA")
          $subnets[] = $records["ipv6"];
      }
      $bits = false;
    } else {
      return false;
    }

    $ipIsIPv4 = !!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    foreach ($subnets as $subnet) {
      $subnetIsIPv4 = !!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
      if ($subnetIsIPv4 != $ipIsIPv4) continue;
      if ($bits === false || $bits === "" || $bits >= 32)
        $mask = 128;
      else
        $mask = $bits;
      $maskedIp = self::maskIp($ip, ($ipIsIPv4 ? 4 : 16), $mask);
      $maskedSubnet = self::maskIp($subnet, ($subnetIsIPv4 ? 4 : 16), $mask);

      if ($maskedIp == $maskedSubnet)
        return true; # matched
    }

    return false;
  }

}

// vim: set tabstop=2 expandtab shiftwidth=2:
