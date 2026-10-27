# GFLO IB-03F — End-to-End Admission & Database Privilege Gate
**RELEASE BLOCK. Disposable PostgreSQL-only CI; no production Supabase grants/migration.**

This gate uses **real EIP-191 cryptographic EOA signature checking** in the IB-03E admission orchestrator, with a psql-backed adapter against real PostgreSQL 16 D2/D3 SQL functions, not the former mock ledger. A separate SQL facade owned by the isolated test superuser has explicit EXECUTE grants only to an admission-server test role; browser test role receives no schema access. SQL injection safety and production deployment patterns are NOT established by this test adapter's string escaping.

Trust boundaries still open:
- SECURITY DEFINER database owner has broad power, DB policies for service identity and real Supabase remain unreviewed; the credentials in this repository are **throwaway CI credentials, never use in any other environment**.
- Service role can call `ib03f.issue_session` supplying a digest without having personally verified a signature. A compromised service or bypass endpoint could issue a session. The privilege test excludes browser use, but does not prove a non-bypassable cryptographic DB admission gate.
- Production challenge creation, request origin, replay-safe issuance, verified session cookie secrecy, CSPRNG server-issued session ID, and distributed revocation/disclosure gate are NOT implemented.
- D1 constrained SIWE parser is not fully EIP-4361 ABNF compliant; real ERC-1271 call remains mocked.
- This test sends no real wallet transaction, touches no existing DB and has no deployment.

Policy: lab PASS is never permission to mark production VERIFIED. PR #20 stays DRAFT.
