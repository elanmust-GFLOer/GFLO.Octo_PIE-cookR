# Minimum safe developer audit pilot

Use only a disposable Linux workspace, job-local PostgreSQL and loopback HTTP.
Synthetic UUIDs A/B and ephemeral random JWT keys are generated locally. No
Supabase credentials, real login, wallet connection or production sign-out.

1. Pin/verify source, dependency hashes, Action commits and PostgreSQL digest.
2. Run the original 28 named Python tests and all SQL gates in separate fresh
   baseline/transition databases. Apply R5 last. Prove exact RPC ACL denial with
   existing A/B fixtures and no restored grant.
3. Run the 39 gateway cases, 12 real loopback HTTP cases and 3 manifest cases.
   Require all 82 exact names, zero skips/errors/expected failures.
4. Observe invalid/expired/foreign JWTs, A/B substitution, REVOKED/UNKNOWN,
   timeout/partial failure/recovery and stale generation. No protected data may
   appear on authority or audit failure.
5. Observe both final delivery/revocation orders, final policy/session changes,
   fence release after transport failure, digest conflicts and fresh retries.
6. Inject delayed adapter side effects; prove worker death, no late write,
   bounded completion and subsequent worker availability.
7. Verify observer counts/redaction; every sensitive operation remains
   non-executing. Recheck R5 EXECUTE/DML/membership matrix after overlay.

Acceptance evidence: exact checkout/tree/parents, separate database OIDs,
per-test JSON ledger, raw SQL/test logs, dependencies/engine versions, source
hashes and downloadable archive SHA-256. A failed or unexecuted case is never
PASS. Destroy the disposable environment; rollback synthetic fixture transactions.
Real account session-expiration/sign-out, production authority outages, SIWE,
consent, recovery and live permissions remain NOT TESTED/BLOCKED.
