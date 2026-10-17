-- ONLY in a freshly created disposable test database. Do NOT run against Supabase.
\set ON_ERROR_STOP on
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE gflo_rt_ingest NOLOGIN;
CREATE ROLE gflo_rt_worker NOLOGIN;
