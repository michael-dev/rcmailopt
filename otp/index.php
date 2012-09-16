<html>
 <head>
  <title>SMS OTP Verwaltung</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/> 
 </head>
 <body>
<h2>Willkommen bei SMS OTP</h2>

Diese Anwendung funktioniert, indem das "echte" Passwort mit einer PIN verschlüsselt in einer Datenbank gespeichert wird. Beim Zugriff auf <a href="index.php">die Oberfläche</a> kann man sich dann mit seiner PIN ein temporäres Password an sein Handy schicken lassen, welches einmalig zur Authentifizierung z.B. im WebMail verwendet werden kann.

<?php

session_start();
require "lib.php";
global $pdo;

if (isset($_REQUEST["action"]) && $_REQUEST["action"] == "login") {
  $getuserstm = $pdo->prepare("SELECT * FROM users WHERE username = :username");
  $getuserstm->execute(array("username" => $_REQUEST["username"])) or die ("Datenbankfehler: ".print_r($getuserstm->errorInfo(),true));
  $users = $getuserstm->fetchAll();
  if (count($users) > 0) {
    if (ssha_password_verify($users[0]["pin"], $_REQUEST["password"])) {
      $_SESSION["login"] = $_REQUEST["username"];
      $_SESSION["password"] = $_REQUEST["password"];
    } 
  }
  unset($_REQUEST["action"]);
}

if (isset($_REQUEST["action"]) && $_REQUEST["action"] == "logoff") {
  unset($_SESSION["login"]);
  unset($_SESSION["password"]);
  unset($_REQUEST["action"]);
  if (isset($_REQUEST["url"])) {
    header("Location: ".$_REQUEST["url"]);
    echo "<a href=\"".$_REQUEST["url"]."\">weiter</a>";
    exit;
  }
}

if (!$_SESSION["login"]) {
?>
<form action="index.php" method="POST">
<input type="hidden" name="action" value="login"/>
<table border="0">
<tr><td>Nutzername:</td><td><input type="text" name="username"/></td></tr>
<tr><td>PIN:</td><td><input type="password" name="password"/></td></tr>
<tr><td colspan="2"><input type="submit" value="Anmelden"/></td></tr>
</table>
</form>

<a href="admin.php">Verwaltung und Registrierung</a>

<?
exit;
} else {
?>
<a href="index.php?action=logoff">Abmelden</a>
<hr/>
<?
}

$getuserstm = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$getuserstm->execute(array("username" => $_SESSION["login"])) or die ("Datenbankfehler: ".print_r($getuserstm->errorInfo(),true));
$users = $getuserstm->fetchAll();

if (count($users) == 0) die("Benutzer unbekannt.");

$getphonestm = $pdo->prepare("SELECT * FROM phones WHERE user_id = :user_id");
$getphonestm->execute(array("user_id" => $users[0]["id"])) or die ("Datenbankfehler: ".print_r($getphonestm->errorInfo(),true));
$phones = $getphonestm->fetchAll();

if (count($phones) == 0):
?> Es wurde noch kein Telefon eintragen. Bitte verwenden Sie für das erste Telefon die Verwaltungsoberfläche. <?
endif;

if (isset($_REQUEST["action"])) {

  if (isset($_REQUEST["valphone"])) {
    $found = false;
    foreach ($phones as $phone) {
      $found = $found || ($phone["phonenumber"] == $_REQUEST["valphone"]);
    }
    if (!$found) die("Ungültige Telefonnummer");
  }

  $auth = false;
  if (isset($_REQUEST["code"])) {
    $action = $_REQUEST["action"];
    $request = $_REQUEST["request"]; 
    $valphone = $_REQUEST["valphone"]; 
    $code = str_replace(".", "", $_REQUEST["code"]); # common mistake due to SMS text 
    $verify = $_REQUEST["verify"];
    $validuntil = $_REQUEST["validuntil"]; 
    if (ssha_password_verify($verify, $salt."|".$validuntil."|".$code."|".$valphone."|".$request) && ($validuntil >= time())) {
      $auth = true;
    }
    if ($action == "addphone") {
      if (!ssha_password_verify($_REQUEST["verify2"], $salt."|".$validuntil."|".$_REQUEST["code2"]."|".$valphone."|".$request) && ($validuntil >= time())) {
        $auth = false;
      }
    }
    $_REQUEST = unserialize(base64_decode($request));
    $_REQUEST["action"] = $action;
  }

  if ($_REQUEST["action"] == "setpin") {
    if ($_REQUEST["pin"] != $_REQUEST["pin2"]) {
      die("<b>PINs verschieden</b>");
    }
    if (!ssha_password_verify($users[0]["pin"], $_REQUEST["opin"])) {
      die("Falsche alte PIN");
    }
  }
  if ($_REQUEST["action"] == "otp.rcmail") {
    $auth = true; # no auth required
  }

  if ($auth) {
    switch ($_REQUEST["action"]):
    case "otp.rcmail":
      $code = make_rand();
      $pwPlain = decrypt_password($_SESSION["password"], $users[0]["encryptedPassword"]);
      addotp($_SESSION["login"], $pwPlain, $code);
      send_sms($_REQUEST["valphone"], "Ihr temporäres Passwort für Roundcubemail: $code");
    ?>
    <h3>Temporäres Passwort für Roundcubemail</h3>
    Es wurde nun ein Code an ihr Telefon verschickt, der zum einmaligem Login auf <a href="index.php?action=logoff&amp;url=<?=urlencode($rcmailurl);?>"><?=htmlentities($rcmailurl)?></a> verwendet werden kann.<br/>
    <a href="index.php">zurück</a>
    <?
      exit;
    break;
    case "setpin":
      $pwPlain = decrypt_password($_REQUEST["opin"], $users[0]["encryptedPassword"]);
      $pwEnc = encrypt_password($_REQUEST["pin"], $pwPlain);
      $upduserstm = $pdo->prepare("UPDATE users SET pin = :pin, encryptedPassword = :encryptedPassword WHERE username = :username");
      $upduserstm->execute(array("username" => $_SESSION["login"], "pin" => make_ssha_password($_REQUEST["pin"]), "encryptedPassword" => $pwEnc)) or die ("Datenbankfehler: ".print_r($udpuserstm->errorInfo(),true));
    break;
    case "delphone":
      $delphonestm = $pdo->prepare("DELETE FROM phones WHERE user_id = :user_id AND phonenumber = :phonenumber");
      $delphonestm->execute(array("user_id" => $users[0]["id"], "phonenumber" => $_REQUEST["phone"])) or die ("Datenbankfehler: ".print_r($delphonestm->errorInfo(),true));
    break;
    case "addphone":
      $addphonestm = $pdo->prepare("INSERT INTO phones (user_id, phonenumber, name) VALUES (:user_id, :phone, :name)");
      $addphonestm->execute(array("user_id" => $users[0]["id"], "phone" => $_REQUEST["phone"], "name" => $_REQUEST["name"])) or die ("Datenbankfehler: ".print_r($addphonestm->errorInfo(),true));
    break;
    case "setphone":
      $setphonestm = $pdo->prepare("UPDATE phones SET name = :name WHERE user_id = :user_id AND phonenumber = :phone");
      $setphonestm->execute(array("user_id" => $users[0]["id"], "phone" => $_REQUEST["phone"], "name" => $_REQUEST["name"])) or die ("Datenbankfehler: ".print_r($setphonestm->errorInfo(),true));
    break;
    endswitch;
    header("Location: index.php");
    exit;
  } else {
    unset($verifycode2);
    if (!isset($_REQUEST["request"])) {
      $code = make_rand();
      $validuntil = time() + 3600;
      $request = base64_encode(serialize($_REQUEST));
      $verifycode = make_ssha_password($salt."|".$validuntil."|".$code."|".$_REQUEST["valphone"]."|".$request);
      $details = $_REQUEST; unset($details["pin"]); unset($details["pin2"]); unset($details["opin"]); unset($details["valphone"]); unset($details["action"]);
      send_sms($_REQUEST["valphone"], "Sie wollen die Aktion ".$_REQUEST["action"]." ausführen. Details: ".json_encode($details).". Der Code lautet $code.");
      if ($_REQUEST["action"] == "addphone") {
        $code2 = make_rand();
        send_sms($_REQUEST["phone"], "Sie wollen diese Telefon hinzufügen. Der II Code lautet $code2.");
        $verifycode2 = make_ssha_password($salt."|".$validuntil."|".$code2."|".$_REQUEST["valphone"]."|".$request);
      }
    } else {
      $validuntil = $_REQUEST["validuntil"];
      $request = $_REQUEST["request"];
      $verifycode = $_REQUEST["verify"];
      if (isset($_REQUEST["verify2"])) {
        $verifycode2 = $_REQUEST["verify2"];
      }
    }
    ?>
    <h3>Aktion <?=$_REQUEST["action"]?>, Schritt 2 von 2</h3>
    Es wurde nun ein Code an ihr Telefon <?=$_REQUEST["valphone"];?> verschickt, den sie bitte zur Bestätigung der Aktion eingeben.<br/>
    <? if (isset($verifycode2)): ?>
    Es wurde nun ein Code II an ihr neues Telefon <?=$_REQUEST["phone"];?> verschickt, den sie bitte ebenfalls zur Bestätigung der Aktion eingeben.<br/>
    <? endif; ?>
    <? if (isset($_REQUEST["request"])): ?>
    <b>Der eingegebene Code war nicht korrekt.</b>
    <? endif; ?>

    <form action="index.php" method="POST">
     <input type="hidden" name="action" value="<?=$_REQUEST["action"];?>">
     <input type="hidden" name="verify" value="<?=$verifycode;?>">
     <? if (isset($verifycode2)): ?>
     <input type="hidden" name="verify2" value="<?=$verifycode2;?>">
     <? endif; ?>
     <input type="hidden" name="validuntil" value="<?=$validuntil;?>">
     <input type="hidden" name="request" value="<?=$request;?>">
     <label for="valphone">Telefonnummer</label>: <input type="text" name="valphone" readonly="readonly" value="<?=$_REQUEST["valphone"];?>"><br/>
     <label for="code"></label>Telefon-Code: <input type="text" name="code"><br/>
     <? if (isset($verifycode2)): ?>
     <label for="code2"></label>Telefon-Code II (neues Telefon): <input type="text" name="code2"><br/>
     <? endif; ?>
     <input type="submit" value="Telefonnummer hinzufügen">
    </form>
    <?
    exit;
  }
}
?>

<h3>Temporäres Passwort für Roundcubemail anfordern</h3>

<form action="index.php" method="POST">
 <input type="hidden" name="action" value="otp.rcmail">
<table border="0">
<tr><td><label for="valphone">Telefonnummer zur Bestätigung</label>:</td><td><select name="valphone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select></td></tr>
<tr><td colspan="2"><input type="submit" value="Temporäres Passwort anfordern"></td></tr>
</table>
</form>

<h3>PIN ändern</h3>

Dies ist erforderlich, wenn die PIN geändert werden soll. Wurde das Passwort geändert, muss die PIN über die <a href="admin.php">Verwaltungsseite</a> geändert werden.

<form action="index.php" method="POST">
 <input type="hidden" name="action" value="setpin">
<table border="0">
<tr><td><label for="pin">(neue) PIN</label>:</td><td><input type="password" name="pin"></td></tr>
<tr><td><label for="pin2">(neue) PIN (Wiederholung)</label>:</td><td><input type="password" name="pin2"></td></tr>
<tr><td><label for="opin">(alte) PIN</label>:</td><td><input type="password" name="opin"></td></tr>
<tr><td><label for="valphone">Telefonnummer zur Bestätigung</label>:</td><td><select name="valphone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select></td></tr>
<tr><td colspan="2"><input type="submit" value="PIN ändern"></td></tr>
</table>
</form>

<h3>Telefonnummer hinzufügen</h3>

<form action="index.php" method="POST">
 <input type="hidden" name="action" value="addphone">
 <label for="phone">(neue) Telefonnummer</label>: <input type="text" name="phone"><br/>
 <label for="name">Bezeichnung</label>: <input type="text" name="name"><br/>
 <label for="valphone">Telefonnummer zur Bestätigung</label>: <select name="valphone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select></br/>
 <input type="submit" value="Telefonnummer hinzufügen">
</form>
<?

?>
<h3>Telefonnummer entfernen</h3>
<?


if (count($phones) == 0) {
?>
<b>Keine Telefone eintragen.</b>
<?
} else {
?>
<ul>
<?
foreach ($phones as $phone) {
?>
<li><?=$phone["phonenumber"];?> (<?=$phone["name"];?>)</li>
<?
}
?>
</ul>
<form action="index.php" method="POST">
 <input type="hidden" name="action" value="delphone">
 <label for="phone">Telefonnummer zum Entfernen</label>: <select name="phone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select><br/>
 <label for="valphone">Telefonnummer zur Bestätigung</label>: <select name="valphone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select></br/>
 <input type="submit" value="Telefonnummer entfernen">
</form>
<?
};
?>
<h3>Bezeichnung der Telefonnummer ändern</h3>
<form action="index.php" method="POST">
 <input type="hidden" name="action" value="setphone">
 <label for="phone">Telefonnummer zur Änderung</label>: <select name="phone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select><br/>
 <label for="name">Bezeichnung</label>: <input type="text" name="name"><br/>
 <label for="valphone">Telefonnummer zur Bestätigung</label>: <select name="valphone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select></br/>
 <input type="submit" value="Bezeichnung ändern">
</form>
 </body>
</html>
