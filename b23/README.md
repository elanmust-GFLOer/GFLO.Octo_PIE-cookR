# OctoPass Backend-2 B2.3 — experimental PostgreSQL security subgate
Not a production Supabase integration. An isolated simulated session table is used to demonstrate same-transaction suspension + audit. The caller-provided user/session IDs are NOT authenticated by SQL: only a verified server layer may derive them. The function is not granted to browser roles. No activation, SIWE, independent consent, real session revocation or recovery is implemented.
**BLOCKING:** Supabase Auth serialization, true session token binding, role/ownership model and universal auditing. Treat a green CI as narrow local DB test evidence only.
See b23/docs/CODEX_REVIEW.md for the independent review checklist.
