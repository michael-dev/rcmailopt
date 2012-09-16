<?php

require "class.cryptastic.php";
require "sms_inject.php";
require "config.php";

global $dbuser, $dbpass, $dbdsn, $pdo;
$pdo = new PDO($dbdsn,$dbuser,$dbpass);

function addotp($username, $pwPlain, $code) {
  global $dbdsnrcmail, $dbuser, $dbpass;
  $pdoRCMAIL = new PDO($dbdsnrcmail,$dbuser,$dbpass);
  $validUntil = time() + 3600;
  $addotpstm = $pdoRCMAIL->prepare("INSERT INTO otp (username, rcube_otp , imappass, validUntil) VALUES (:username, :code, :imappass, :validUntil)");
  $addotpstm->execute(array("username" => $username, "code" => $code, "imappass" => $pwPlain, "validUntil" => $validUntil)) or die ("Datenbankfehler: ".print_r($addotpstm->errorInfo(),true));
}

function conv2iso($str) {
  $str2 = iconv("UTF-8","iso-8859-1",$str);
  if ($str2 !== false) return $str2;
  return $str;
}
function conv2utf8($str) {
  $str2 = iconv("iso-8859-1","utf-8",$str);
  if ($str2 !== false) return $str2;
  return $str;
}

function text2sms($text) {
 $text = trim($text);
 if (substr($text,0,-1) == "\n") $text = substr($text,0,strlen($text)-1);
 $text = trim($text);
 return conv2iso($text);
}

function send_sms($to, $text) {
  global $dbuser, $dbpass, $dbdsnsms;
  $pdoSMS = new PDO($dbdsnsms,$dbuser,$dbpass);
  $sms=new sms_inject($pdoSMS);
  $sms->send_sms(text2sms($text),$to);
}

function encrypt_password($pin, $password) {
  global $salt;
  $cryptastic = new cryptastic;
  $key = $cryptastic->pbkdf2($pin, $salt, 1000, 32) or die("Failed to generate secret key.");
  $ciphertext = $cryptastic->encrypt($password, $key, true) or die("Failed to complete encryption.");
  return $ciphertext;
}

function decrypt_password($pin, $password) {
  global $salt;
  $cryptastic = new cryptastic;
  $key = $cryptastic->pbkdf2($pin, $salt, 1000, 32) or die("Failed to generate secret key.");
  $plaintext = $cryptastic->decrypt($password, $key, true) or die("Failed to complete decryption.");
  return $plaintext;
}

function make_rand(){
  mt_srand((double)microtime()*1000000);
  $salt = pack("CCCCCC", mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand(), mt_rand());
  return base64_encode($salt);
}

function make_ssha_password($password){
  mt_srand((double)microtime()*1000000);
  $salt = pack("CCCC", mt_rand(), mt_rand(), mt_rand(), mt_rand());
  $hash = "{SSHA}" . base64_encode(pack("H*", sha1($password . $salt)) . $salt);
  return $hash;
}
 
function ssha_password_verify($hash, $password){
  // Verify SSHA hash
  $ohash = base64_decode(substr($hash, 6));
  $osalt = substr($ohash, 20);
  $ohash = substr($ohash, 0, 20);
  $nhash = pack("H*", sha1($password . $osalt));
  if ($ohash == $nhash) {
    return True;
  } else {
    return False;
  }
}

?>
