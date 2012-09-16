USE roundcubemail;

CREATE TABLE IF NOT EXISTS "otp" (
  "id" int(11) unsigned NOT NULL AUTO_INCREMENT,
  "username" tinytext NOT NULL,
  "rcube_otp" tinytext NOT NULL,
  "imappass" tinytext NOT NULL,
  "validUntil" int(11) NOT NULL,
  PRIMARY KEY ("id")
) AUTO_INCREMENT=14 ;

USE otp;

CREATE TABLE IF NOT EXISTS "phones" (
  "id" int(11) NOT NULL AUTO_INCREMENT,
  "user_id" int(11) NOT NULL,
  "phonenumber" varchar(64) NOT NULL,
  "name" varchar(60) NOT NULL,
  PRIMARY KEY ("id"),
  KEY "user_id" ("user_id")
) AUTO_INCREMENT=9 ;

CREATE TABLE IF NOT EXISTS "users" (
  "id" int(11) NOT NULL AUTO_INCREMENT,
  "username" varchar(64) NOT NULL,
  "pin" varchar(64) NOT NULL,
  "encryptedPassword" text NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "username" ("username")
) AUTO_INCREMENT=3 ;

USE gammu;

-- see example sql shipped with gammu

