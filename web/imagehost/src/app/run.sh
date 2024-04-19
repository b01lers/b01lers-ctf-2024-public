#!/bin/sh
FLAG_FILENAME="$(python3 -c 'import uuid;print(uuid.uuid4())').png"
mv /flag.png "/uploads/$FLAG_FILENAME"
mariadbd -umysql &
sleep 3
mariadb <<HERE
CREATE DATABASE ctf;
USE ctf;
CREATE USER 'ctf'@localhost IDENTIFIED BY '$DB_PASSWORD';
CREATE TABLE users (
	id INT NOT NULL AUTO_INCREMENT,
	user TEXT,
	password TEXT,
	admin BOOL,
	PRIMARY KEY(id),
	UNIQUE(user)
);

CREATE TABLE images (
	id INT NOT NULL AUTO_INCREMENT,
	filename TEXT,
	user_id INT,
	PRIMARY KEY(id)
);
INSERT INTO users (user, password, admin) VALUES ('admin', '$ADMIN_PASSWORD', TRUE);
INSERT INTO images (filename, user_id) VALUES ('$FLAG_FILENAME', 1);
GRANT ALL PRIVILEGES ON *.* TO 'ctf'@localhost;
FLUSH PRIVILEGES;
HERE
exec /start.sh