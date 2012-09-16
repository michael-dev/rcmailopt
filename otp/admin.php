<html>
 <head>
  <title>SMS OTP Verwaltung</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/> 
 </head>
 <body>
<h2>Willkommen bei SMS OTP im Bereich Verwaltung</h2>
<?php

require "lib.php";
global $pdo;

$getuserstm = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$getuserstm->execute(array("username" => $_SERVER['PHP_AUTH_USER'])) or die ("Datenbankfehler: ".print_r($getuserstm->errorInfo(),true));
$users = $getuserstm->fetchAll();

if (isset($_REQUEST["action"])) {
  switch ($_REQUEST["action"]):
  case "setpin":
    if ($_REQUEST["pin"] != $_REQUEST["pin2"]) {
      die("PINs verschieden");
    }
    $pwEnc = encrypt_password($_REQUEST["pin"], $_SERVER['PHP_AUTH_PW']); 
    if (count($users) == 0) {
      $adduserstm = $pdo->prepare("INSERT INTO users (username, pin, encryptedPassword) VALUES (:username, :pin, :encryptedPassword)");
      $adduserstm->execute(array("username" => $_SERVER['PHP_AUTH_USER'], "pin" => make_ssha_password($_REQUEST["pin"]), "encryptedPassword" => $pwEnc)) or die ("Datenbankfehler: ".print_r($adduserstm->errorInfo(),true));
    } else {
      $upduserstm = $pdo->prepare("UPDATE users SET pin = :pin, encryptedPassword = :encryptedPassword WHERE username = :username");
      $upduserstm->execute(array("username" => $_SERVER['PHP_AUTH_USER'], "pin" => make_ssha_password($_REQUEST["pin"]), "encryptedPassword" => $pwEnc)) or die ("Datenbankfehler: ".print_r($upduserstm->errorInfo(),true));
    }
  break;
  case "delphone":
    if (count($users) > 0) {
      $delphonestm = $pdo->prepare("DELETE FROM phones WHERE user_id = :user_id AND phonenumber = :phonenumber");
      $delphonestm->execute(array("user_id" => $users[0]["id"], "phonenumber" => $_REQUEST["phone"])) or die ("Datenbankfehler: ".print_r($delphonestm->errorInfo(),true));
    }
  break;
  case "setphone":
    $setphonestm = $pdo->prepare("UPDATE phones SET name = :name WHERE user_id = :user_id AND phonenumber = :phone");
    $setphonestm->execute(array("user_id" => $users[0]["id"], "phone" => $_REQUEST["phone"], "name" => $_REQUEST["name"])) or die ("Datenbankfehler: ".print_r($setphonestm->errorInfo(),true));
  break;
  case "addphone":
    if (count($users) == 0) { exit; }
    $code = make_rand();
    $validuntil = time() + 3600;
    $verifycode = make_ssha_password($salt."|".$validuntil."|".$code."|".$_REQUEST["phone"]."|".$_REQUEST["name"]);
    send_sms($_REQUEST["phone"], "Sie wollen dieses Telefon hinzufügen. Der Code lautet $code.");
    header("Location: admin.php?action=addphone.form&code=$code&verify=$verifycode&validuntil=$validuntil&phone=".htmlentities($_REQUEST["phone"])."&name=".htmlentities($_REQUEST["name"]));
    exit;
  break;
  case "addphone.form":
    ?>
    <h3>Telefonnummer hinzufügen, Schritt 2 von 2</h3>
    Es wurde nun ein Code an ihr Telefon verschickt, den sie bitte zur Überprüfung der Telefonnummer eingeben.<br/>
    <? if (isset($_REQUEST["retry"])): ?>
    <b>Der eingebene Code war nicht korrekt.</b>
    <? endif; ?>
    <form action="admin.php" method="POST">
     <input type="hidden" name="action" value="addphone.real">
     <input type="hidden" name="verify" value="<?=$_REQUEST["verify"];?>">
     <input type="hidden" name="name" value="<?=htmlentities($_REQUEST["name"]);?>">
     <input type="hidden" name="validuntil" value="<?=$_REQUEST["validuntil"];?>">
     <label for="phone">Telefonnummer</label>: <input type="text" name="phone" readonly="readonly" value="<?=$_REQUEST["phone"];?>"><br/>
     <label for="code"></label>Telefon-Code: <input type="text" name="code"><br/>
     <input type="submit" value="Telefonnummer hinzufügen">
    </form>
    </body></html>
    <?
    exit;
  case "addphone.real":
    if (count($users) == 0) { exit; }
    $phone = $_REQUEST["phone"]; 
    $code = str_replace(".", "", $_REQUEST["code"]); # common mistake due to SMS text 
    $verify = $_REQUEST["verify"];
    $validuntil = $_REQUEST["validuntil"]; 
    if (ssha_password_verify($verify, $salt."|".$validuntil."|".$code."|".$phone."|".$_REQUEST["name"]) && ($validuntil >= time())) {
      $addphonestm = $pdo->prepare("INSERT INTO phones (user_id, phonenumber, name) VALUES (:user_id, :phone, :name)");
      $addphonestm->execute(array("user_id" => $users[0]["id"], "phone" => $phone, "name" => $_REQUEST["name"])) or die ("Datenbankfehler: ".print_r($addphonestm->errorInfo(),true));
    } else {
      header("Location: admin.php?action=addphone.form&retry=1&code=$code&verify=$verify&validuntil=$validuntil&phone=".htmlentities($phone)."&name=".htmlentities($_REQUEST["name"]));
      exit;
    }
  break;
  endswitch;
  header("Location: admin.php");
  exit;
}
?>

Diese Anwendung funktioniert, indem das "echte" Passwort mit einer PIN verschlüsselt in einer Datenbank gespeichert wird. Beim Zugriff auf <a href="index.php">die Oberfläche</a> kann man sich dann mit seiner PIN ein temporäres Password an sein Handy schicken lassen, welches einmalig zur Authentifizierung z.B. im WebMail verwendet werden kann.

<h3>PIN festlegen</h3>

Dies ist erforderlich, wenn die PIN geändert werden soll oder das Passwort geändert wurde.

<form action="admin.php" method="POST">
 <input type="hidden" name="action" value="setpin">
 <label for="pin">PIN</label>: <input type="password" name="pin"><br/>
 <label for="pin2">PIN (Wiederholung)</label>: <input type="password" name="pin2"><br/>
 <input type="submit" value="PIN festlegen">
</form>

<?
if (count($users) > 0) {

?>
<h3>Telefonnummer hinzufügen</h3>

<form action="admin.php" method="POST">
 <input type="hidden" name="action" value="addphone">
 <label for="phone">Telefonnummer</label>: <input type="text" name="phone"><br/>
 <label for="name">Bezeichnung</label>: <input type="text" name="name"><br/>
 <input type="submit" value="Telefonnummer hinzufügen">
</form>
<?

?>
<h3>Telefonnummer entfernen</h3>
<?

$getphonestm = $pdo->prepare("SELECT * FROM phones WHERE user_id = :user_id");
$getphonestm->execute(array("user_id" => $users[0]["id"])) or die ("Datenbankfehler: ".print_r($getphonestm->errorInfo(),true));
$phones = $getphonestm->fetchAll();

if (count($phones) == 0) {
?>
<b>Keine Telefone eintragen.</b>
<?
} else {
?>
<table border="0">
<tr><th colspan="2">Telefonnummer</th></tr>
<?
foreach ($phones as $phone) {
?>
<tr><td>
<form action="admin.php" method="POST">
 <input type="hidden" name="action" value="delphone">
 <input type="hidden" name="phone" value="<?=$phone["phonenumber"];?>">
 <input type="submit" value="Telefonnummer entfernen">
</form>
</td><td><?=$phone["phonenumber"];?> (<?=$phone["name"];?>)</td></tr>
<?
}
?>
</table>
<?
}
?>
<h3>Bezeichnung der Telefonnummer ändern</h3>
<form action="admin.php" method="POST">
 <input type="hidden" name="action" value="setphone">
 <label for="phone">Telefonnummer</label>: <select name="phone" size="1"><?foreach ($phones as $phone) echo "<option value=\"".$phone["phonenumber"]."\">".$phone["phonenumber"]." (".$phone["name"].")</option>";?></select><br/>
 <label for="name">Bezeichnung</label>: <input type="text" name="name"><br/>
 <input type="submit" value="Bezeichnung ändern">
</form>
<?
 }
?>
 </body>
</html>
