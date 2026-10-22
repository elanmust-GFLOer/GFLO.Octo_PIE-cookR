# R6A: isolated fail-closed quarantine decision gateway

Starting anchor: `2362ce622daf896248265a03efca00d6ef72a9a7`.
This package has no production adapter, database connection, mutation dispatcher,
wallet integration or account enrollment. All five sensitive operations terminate
with DENY or QUARANTINE. R5 SQL is unchanged. QUARANTINE never creates a queue.

## Architecture and boundaries

Loopback HTTP -> strict request parser -> injected JWT verifier -> fresh user
observer -> **independent** session authority -> operation policy -> canonical
request/digest ledger -> primary generation fence -> audit approval -> fresh
session and policy checks -> expiry/generation check -> observer sink commit ->
synchronous data delivery while the primary fence is held.

Verified identity is created exclusively by the trusted verifier. HTTP accepts
operation/request_id/payload, never AuthContext, principal, epoch or nonce validity.
The offline verifier uses ephemeral test-only HS256 keys, fixed issuer/audience/
project and mandatory subject/session/generation/expiry claims. It is not a
Supabase verifier. Missing adapters fail closed. The default CLI has no adapters:
only public health works. No cookie authentication or permissive CORS.

Injected interfaces live in contracts.py. Session observations ACTIVE/REVOKED/
UNKNOWN are independent of getClaims/getUser. The latter cannot establish current
session liveness. Reads require all proofs, explicit observer policy and an
available audit sink. Unknown/malformed local states also fail closed.

Adapters execute in spawned, killable processes, with 400 ms stage limits and a
2-second operation deadline, followed by at most 200 ms termination/reaping grace.
The response frame is bounded and atomic within PIPE_BUF; poll cannot accept a
partially written, indefinitely stalled frame. Every worker is terminated/reaped
before reuse, including successful workers. An unreapable worker seals the
supervisor against further adapter work. Eight protected requests and sixteen
HTTP workers bound admission; sockets have a 2-second inactivity timeout. These
are laboratory Linux bounds, not hard real-time guarantees. Trusted adapters are
read-only and receive no domain credentials. Killing a process cannot undo an
external mutation already committed: such adapters are expressly prohibited.

Only GET /healthz (minimal status) and GET /v1/audit/summary (synthetic counts)
release data. POST /v1/decisions returns a decision, never protected data.
Bodies/headers are bounded; duplicate JSON keys, cookies, foreign Host/Origin
and unsupported HTTP methods are rejected. Bearer tokens are test fixtures only.
Run: `python3 -m b23r6a.http_server --port 8766`.

## Threat model and guarantees

Attackers control HTTP data, bearer tokens and request IDs, but not injected
Python code or process configuration. Signature, issuer, audience, project,
subject/session ownership, independent liveness, local generation and policy
must all agree. Caller target IDs never establish authority. An ALLOW object is
not a reusable capability: protected data is accessible only to the trusted
synchronous delivery callback under the fence. Transport failures are not retried.

Local revocation and release serialize on the same primary-simulator lock.
Revocation committed first prevents release; a read ordered first completes its
bounded synchronous write before local revocation commits. Bytes already sent
cannot be recalled. Repeated external observations reduce, but do not eliminate,
cross-system TOCTOU: **there is no immediate Supabase sign-out guarantee**.
The simulator is not a PostgreSQL primary fence or multi-replica authorization
proof. A future primary adapter must hold the actual controller/generation row
lock through its defined release boundary and specify timeout/cancellation.

Request digests are server-computed canonical JSON hashes. The process-local,
bounded 10-minute ledger rejects digest conflicts and never caches ALLOW.
Every retry performs fresh verification. Persistent/distributed idempotency still
belongs to future audited PostgreSQL functions. No domain writes exist here.

## Verification and evidence

test-manifest.json pins every class/method identity: B22 6, R2 7, R3 6, R4 3,
R5 6, gateway 39, HTTP 12, manifest 3 = **82 Python tests**, plus SQL gates.
No skips or expected failures are accepted. The old 28 tests run unchanged
before the R5 overlay; exact A/B fixture and ACL denial checks then run after it.
The unsafe laboratory positive tests prove only their explicitly limited scope.

The combined script requires fresh localhost disposable databases and explicit
acks; it refuses preexisting database names by CREATE DATABASE failure.
Baseline and transition databases have distinct OIDs recorded in evidence.
Offline/HTTP subprocesses receive no PG environment credentials. Never point
these scripts at a real service. A GitHub job-local PostgreSQL container is
destroyed after the run.

The combined workflow pins all Actions to commits, PostgreSQL to a digest and
all wheels (including transitive typing-extensions) to versions/SHA-256. It
verifies checkout/PR merge parents/tree, unchanged R5 SQL, exact manifest,
Python minor and installed versions; uploads per-test ledgers, SQL logs,
source hashes and SHA256SUMS even on failure. Hosted Ubuntu/kernel and the
preinstalled Python patch remain recorded platform inputs, not a hermetic OS
rebuild. A successful run's downloadable archive must be inspected separately.

## Remaining gates

Production remains BLOCKED: authoritative Supabase revocation/consistency,
production issuer/JWKS validation, primary-database read fencing, durable audit/
idempotency, SIWE, independently signed consent, recovery authorization,
issuer-first activation lifecycle, replicas, privileged administrator auditing
and deployment controls are not implemented. The R3 owner/mutator bypass
requires external administrator controls; R5 only quarantines operational roles.
gfloDEVaccount is NOT VERIFIED. No XP, Tier, minting, transfer or governance
authority exists. No automatic R6B or production progression.
