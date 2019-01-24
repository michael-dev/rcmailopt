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

    if ($this->authBrowser($rcmail, $args, $otpSuccess) === false) {
      $args["abort"] = true;
      $args["error"] = "Browser unbekannt";
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

  /** return false on blocked login, true on known browser and null if login is not blocked but new browser */
  private function authBrowser(&$rcmail, &$args, $trustedLoginSuccess) {
    // get cookie to identify browser for this user
    $cookieSalt = $rcmail->config->get('otp_salt', "otp");
    $cookieName = "rcmail_otp_".sha1($cookieSalt."#".$args["user"]);
    $doAuthBrowser = $rcmail->config->get('otp_auth_browser'); // null or 0: disabled, 1: optional, 2: required for login

    if (!$doAuthBrowser)
      return NULL; // feature disabled
    $needConfirmed = ($doAuthBrowser == 2);

    // check if this is a known browser
    if (isset($_COOKIES[$cookieName])) {
      $cookieValue = $_COOKIES[$cookieName];
      $dbValue = sha1($cookieSalt."#".$cookieValue);

      // FIXME add maxAge check?
      $res = $rcmail->db->query("SELECT * FROM roundcubemail.otp_browser
                                  WHERE otp_browser.username = ? AND otp_browser.cookie = ?".($needConfirmed ? " AND otp_browser.confirmed" : ""),
                                array($args["user"], $dbValue));
      $dbres = $rcmail->db->fetch_assoc($res);
      if ($dbres) {
        $rcmail->db->query("UPDATE roundcubemail.otp_browser WHERE otp_browser.username = ? AND otp_browser.cookie = ? SET lastUsed = ?",
                           array($args["user"], $dbValue, time()));
        return true;
      }
    }

    // this is a new browser, so generate a cookie
    $cookieValue = bin2hex(random_bytes(30));
    $dbValue = sha1($cookieSalt."#".$cookieValue);
    $browserName = $_SERVER['HTTP_USER_AGENT']; // FIXME ask user -> link to portal?, GeoIP2

    // check ip against whitelist (like, 172.16.0.0/16, 192.168.0.0/16, dynamic.fami-braun.de, ilmenau.fami-braun.de, jena.fami-braun.de, luebeck.fami-braun.de
    $whitelist = $rcmail->config->get('otp_whitelist', Array());
    $trustedRemoteAddr = false;
    $ip = rcube_utils::remote_addr();
    foreach ($whiteliste as $wi) {
      $trustedRemoteAddr = false;
    }

    // if login is going to fail anyway, do not bother to register and send back cookie to hide this
    $registerBrowser = $otpSuccess || $rcmail->login($args['user'], $args['pass'], $args['host'], $args['cookiecheck']);
    if ($registerBrowser) {
      $rcmail->db->query("INSERT INTO roundcubemail.otp_browser (username, cookie, name, createdAt, lastUsed, confirmed) VALUES (?, ?, ?, ?, ?)",
                         array($args["user"], $dbValue, $browserName, time(), time(), $trustedLoginSuccess ? 1 : 0));
      // send notification
      if (!$trustedLoginSuccess)
        $this->notifyNewBrowser($rcmail, $browserName);
    }

    rcube_utils::setcookie($cookieName, $cookieValue, time() + 100 * 365 * 24 * 3600);

    return NULL; 
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

  /**
   * Check the client IP against a value in CIDR notation.
   */
  private static function cidr_match($ip, $cidr)
  {
      if (strpos($cidr, '/') === false) {
          $cidr .= '/';
      }
      list($subnet, $bits) = explode('/', $cidr,2);
// handle multiple ips for dns name

      if (!filter_var($subnet, FILTER_VALIDATE_IP) && filter_var($subnet, FILTER_VALIDATE_DOMAIN,  FILTER_FLAG_HOSTNAME ))
        $subnet=gethostbyname($subnet);
          && !filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))

      $ip = ip2long($ip);
      $subnet = ip2long($subnet);
      $mask = -1 << (32 - $bits);
      $subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
      return ($ip & $mask) == $subnet;
  }

}

