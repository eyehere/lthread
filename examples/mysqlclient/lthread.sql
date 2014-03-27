
DROP DATABASE lthread;
CREATE DATABASE lthread CHARACTER SET utf8 COLLATE utf8_general_ci;
USE lthread;

CREATE TABLE IF NOT EXISTS testing (
  `id`                INTEGER PRIMARY KEY AUTO_INCREMENT NOT NULL,
  `entry`             CHAR(32) DEFAULT NULL
);

INSERT INTO testing SET entry="entry foo";
INSERT INTO testing SET entry="entry bar";
INSERT INTO testing SET entry="entry zing";
INSERT INTO testing SET entry="entry zang";

GRANT ALL on lthread.* to lthreaduser identified by 'lthreadpassword';
