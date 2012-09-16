<?php

class rcsmsotp extends rcube_plugin
{
  public $noajax = true;
  public $noframe = true;
  public $task = 'login|logout';

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

    $res = $rcmail->db->query("SELECT imappass FROM roundcubemail.otp WHERE otp.username = ? AND otp.rcube_otp = ? AND otp.validUntil > ?", $args['user'], $args['pass'], time());
    $dbpass = $rcmail->db->fetch_assoc($res);

    // Valid one time password?
    if($dbpass) {
        $rcmail->db->query("DELETE FROM roundcubemail.otp WHERE otp.username = ? AND otp.rcube_otp = ?", array($args['user'], $args['pass']));
        $args['pass'] = $dbpass['imappass'];
    }
    $rcmail->db->query("DELETE FROM roundcubemail.otp WHERE otp.validUntil < ?", time());
    return $args;
  }
}

