-- Demo backend roles. postgres-proxy speaks SCRAM-SHA-256 both ways by
-- default; postgres 14+ already uses SCRAM as the default encryption.
--
-- This script runs once per fresh data dir (docker-entrypoint-initdb.d
-- contract). Unconditional INSERT below cannot duplicate because the
-- script doesn't re-run on `restart`.

CREATE ROLE app LOGIN PASSWORD 'app-pass';
CREATE ROLE dba LOGIN PASSWORD 'dba-pass' SUPERUSER;

GRANT CONNECT ON DATABASE demo TO app;
\c demo
GRANT USAGE, CREATE ON SCHEMA public TO app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app;

CREATE TABLE IF NOT EXISTS hello (id SERIAL PRIMARY KEY, msg TEXT);
INSERT INTO hello (msg) VALUES ('postgres demo row');
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE hello TO app;
GRANT USAGE, SELECT ON SEQUENCE hello_id_seq TO app;
