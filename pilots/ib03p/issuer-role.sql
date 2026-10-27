-- IB-03P: read-only minimum privilege for independent issuer process.
BEGIN;
CREATE ROLE gflo_issuer_reader_lab LOGIN PASSWORD 'lab-issuer-reader-only' NOINHERIT;
GRANT USAGE ON SCHEMA ib03n TO gflo_issuer_reader_lab;
GRANT EXECUTE ON FUNCTION ib03n.read_context(text) TO gflo_issuer_reader_lab;
COMMIT;
