USE roundcubemail;

CREATE TABLE IF NOT EXISTS "otp" (
  "id" int(11) unsigned NOT NULL AUTO_INCREMENT,
  "username" tinytext NOT NULL,
  "rcube_otp" tinytext NOT NULL,
  "imappass" tinytext NOT NULL,
  "validUntil" int(11) NOT NULL,
  PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "otp_browser" (
  "id" int(11) unsigned NOT NULL AUTO_INCREMENT,
  "username" tinytext NOT NULL,
  "cookie" varchar(64) NOT NULL, -- maybe replace with webcrypto + indexdb pubkey, but needs client-side JS support
  "name" varchar(60) NOT NULL,
  "createdAt" int(11) NOT NULL,
  "lastUsed" int(11) NOT NULL,
  "confirmed" tinyint(1) NOT NULL, -- set to false for autoreg devices without otp
  PRIMARY KEY ("id"),
  KEY "username" ("username"),
  UNIQUE KEY "username_cookie" ("username", "cookie")
);


USE otp;

CREATE TABLE IF NOT EXISTS "users" (
  "id" int(11) NOT NULL AUTO_INCREMENT,
  "username" varchar(64) NOT NULL,
  "pin" varchar(64) NOT NULL,
  "encryptedPassword" text NOT NULL,
  PRIMARY KEY ("id"),
  UNIQUE KEY "username" ("username")
);

CREATE TABLE IF NOT EXISTS "phones" (
  "id" int(11) NOT NULL AUTO_INCREMENT,
  "user_id" int(11) NOT NULL,
  "phonenumber" varchar(64) NOT NULL,
  "name" varchar(60) NOT NULL,
  PRIMARY KEY ("id"),
  KEY "user_id" ("user_id")
);

USE gammu;

-- see example sql shipped with gammu

