# Codex red-team review handoff — GFLO OctoPass B2.3
Status: experimental simulated Auth; NOT deployable.
Review PR #9 against these questions:
1. Are p_user/p_session caller-supplied? Demonstrate why this function MUST NOT be exposed to untrusted roles or via service role with user-controlled arguments.
2. Can Supabase Auth session revocation truly be serialized with binding transactions via the same PostgreSQL database and row? Look for deletion/signout behavior, privileges, races and cross-system lag.
3. Does SECURITY DEFINER privilege escalate from public/authenticated through search_path, function grants, nested calls or alternative DML?
4. Can table owner/DB superuser mutate wallet_bindings without audit? Answer yes today; treat mandatory audit claim as BLOCKED.
5. Test concurrent session revoke vs suspension on independent connections, foreign profile isolation, epoch overflow, challenge invalidation and rollback.
6. Test denial when auth session lookup fails; do not infer session validity from unexpired JWT alone.
7. Confirm SIWE, consent, recovery, contract-wallet checks, PIE grants and failover tests are OUT OF SCOPE, not PASSED.
8. Recommend concrete fixes with exact file:line, severity, suggested tests and a release gate decision.

No direct deployments or production schema modifications. Do not merge until critical blockers are addressed. 
