-- Demo backend roles. mysql-proxy speaks mysql_native_password to backend,
-- so both accounts must be provisioned with that plugin.
--
-- This script runs once per fresh data dir (docker-entrypoint-initdb.d
-- contract). After `docker compose down -v` wipes the backend volume the
-- next `up` re-executes it; persisted state across `restart` is untouched.
-- That is why the INSERT below is unconditional — it cannot duplicate.

ALTER USER 'app'@'%' IDENTIFIED WITH mysql_native_password BY 'app-pass';

CREATE USER IF NOT EXISTS 'dba'@'%' IDENTIFIED WITH mysql_native_password BY 'dba-pass';
GRANT ALL PRIVILEGES ON demo.* TO 'dba'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON demo.* TO 'app'@'%';
FLUSH PRIVILEGES;

USE demo;
CREATE TABLE IF NOT EXISTS hello (id INT AUTO_INCREMENT PRIMARY KEY, msg VARCHAR(128));
INSERT INTO hello (msg) VALUES ('mysql demo row');
