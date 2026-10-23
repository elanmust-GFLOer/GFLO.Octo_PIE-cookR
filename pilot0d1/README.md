# Pilot 0D-1 — Localhost Identity Explorer

Starting anchor: `44d077f4f0d8a0a978fb18ad18190ee361cc9608`, draft PR #17.
This is a separate synthetic frontend and loopback transport. The Hungarian
architecture, evidence and residual-gate review is in [SECURITY-REVIEW.hu.md](SECURITY-REVIEW.hu.md). The published
OctoGFLO/Lovable project is unchanged. Production wallet-binding remains BLOCKED.

## Architecture and authority

Test-controller EIP-1193 provider -> browser adapter -> exact localhost SIWE ->
separate EIP-712 consent -> Pilot 0C cryptographic verifier -> independent
synthetic session authority and generation controller -> mandatory audit approval
and final release checks -> read-only result -> local Identity Explorer.

The server binds **only 127.0.0.1:43817**. Its verified origin is exactly
`http://127.0.0.1:43817`; alternative localhost names, ports, Host/Origin values,
cross-site Fetch Metadata, cookies, query-string credentials and caller AuthContext
are not accepted. Loopback itself is not authentication. Sensitive POSTs require
an unpredictable, memory-only synthetic Bearer capability plus independent CSRF
token, pre-provisioned by trusted test setup. Neither value is a real JWT.
Principal/profile/session handles are owned by the server's independent authority,
not chosen by a request body. There is no login-as-profile, signing, admin,
recovery, binding activation or debug-control HTTP endpoint.

The test controller provisions A/B sessions out of band and attaches a page-scoped
fixture bridge. Server capabilities go only to browser memory, never storage or
URLs. Ephemeral wallet keys stay in **separate, bounded signer-worker process**;
the browser, test-controller and proof server receive only public addresses/signing payloads/
signatures. `fixtures.cjs` is never imported by the server or served as a frontend
asset. A real injected wallet is not discovered or called. Actual extension-wallet
interaction requires the separate 0D-2 gate below.

Only static `/`, `/app.mjs`, `/wallet.mjs`, `/policy.mjs`, `/style.css`, public `/healthz` and
protected POST `/api/challenges`, `/api/verify` exist. Static assets reveal no
identity or credentials. The CLI starts without fixture wallet/session enrollment;
it can show the disabled UI, not enable a real wallet. No private key, seed phrase
or production credential input is provided or requested.

## Cryptographic and state boundaries

Pilot 0C gains a branded, fixed localhost
realm (domain/URI/project/typed-consent salt), and an optional server-supplied
deadline/AbortSignal which can only shorten its original one-second budget.
A trusted synchronous, one-shot handoff checks the exact in-memory proof result
again for consent revocation/expiry, session and generation after final audit.
Serialized/cloned observations cannot invoke it, and a failed handoff never retries.
Arbitrary realm objects deny; no header/body/SQL setting creates a realm or
AuthContext. The original realm remains the default. All inherited **303 test
identities, assertions, test files, SQL gates and cryptographic bundle** are
unchanged. Only `pilot0c/proof.cjs` and its declaration file are extended.

Address discovery is labeled DISCOVERED, NOT VERIFIED. Both actual secp256k1 EOA
signatures must verify. SIWE and consent use separate explicit buttons and separate
confirmation prompts. The exact message, readable consent, scope and typed fields
are visible before signing. A fixed frontend signing policy rejects altered scopes,
contract domains, schemas or origin/identity contexts **before any signing RPC**. The sole scope is `id-entity.proof.read`; there is no
binding, recovery, XP or protocol privilege. Wallet/chain changes cancel pending
fetches and invalidate signatures/results; version checks discard late responses. Checkbox withdrawal and declined re-signing
clear prior signatures; expired observations are removed from the UI. This local
withdrawal is not a persistent backend consent-revocation service.

Per-principal transport serialization, single-use challenge consumption and final
authority/generation/consent checks operate in one Node event loop. Release checks
run **again after audit and JSON preparation**, immediately before initial HTTP
data handoff. A pure test gate exercises races without providing an admin route.
Timeout, abort, unknown/revoked authority and audit failure release no result.
Consumed/lost-response proofs are never automatically replayed or returned from
a result cache. There is no persistent/distributed binding or replay guarantee.

Authorization begins at the request handler after HTTP header parsing, before
body intake, and lasts at most one second including lock wait, crypto, audit,
serialization and initial protected write. The core receives the remaining
deadline and cancellation signal. A separate three-second connection lifetime,
bounded headers/body, four protected slots and sixteen sockets bound admission.
Health bypasses protected slots. This is sampled application ordering, not a hard
real-time network receipt or process scheduling guarantee. No arbitrary async
external adapter, unbounded queue, automatic retry or deferred mutation exists.

PIE records are synthetic, read-only values. `demoXp` is explicitly DEMO_FIXTURE;
`canonicalXp` and `historicalTier` are null. A legacy source reference stays
LEGACY_UNTRUSTED_XP and points only to the incomplete historical source record.
No deployed contract read, canonical XP/Tier, mint/burn, token approval/transfer
or governance operation is invoked. Wallet control does not prove humanity or
contribution eligibility. The UI rejects privilege/canonical-XP promotion and
identity/source mismatches even in a tampered response.

## Browser/package security

CSP permits only same-origin modules/styles/connections; no inline script, eval,
object, frame embedding or form submission. Trusted Types restrictions, nosniff,
no-store, no-referrer, CORP/COOP and restrictive Permissions-Policy are applied.
Rendering uses textContent, never HTML insertion. Cookies are never authority;
fetch uses credentials:omit, same-origin mode and redirect:error. No sensitive
material is stored in localStorage/sessionStorage, a URL or browser traces/HAR.
Audit events use allowlisted reasons, trace/request IDs and per-instance HMAC
pseudonyms, never bodies, signatures, capabilities, wallet addresses or keys.

Client code imports only its EIP-1193 adapter and fixed public signing policy. Server code imports only the
cryptographic verifier, never the test signer. `contracts.d.ts`, the Pilot 0C
declarations and negative type assertions are compiled with strict TypeScript
5.9.3, including checkJs. The OctoGFLO interface reference is the frozen
`pilot0a-frozen/evidence/sources/octogflo/src/domain/octopass-adapters.ts` at
inspected commit `157b15c0315644a16d22df17b9453bfc1c5b8deb`. Its future
CanonicalPieReader requires a number and cannot represent this untrusted/null
state, so the pilot deliberately does not implement that production interface.
It adds no consumer of XP or protocol privileges.

## Reproduction and evidence

Local CPU-only tests: `node pilot0d1/unit-tests.cjs` (22 named cases).
Inherited crypto: `node pilot0c/tests.cjs` (96 unchanged cases).
Install test tooling: `npm ci --prefix pilot0d1 --ignore-scripts --omit=optional`.
Type check: `pilot0d1/node_modules/.bin/tsc -p pilot0d1/tsconfig.json`.
Browser/HTTP: `node pilot0d1/browser-tests.cjs` in the pinned disposable image.
The current browser manifest has **50** exact cases. Full acceptance is
**303 inherited + 22 unit + 50 browser/HTTP = 375**, plus unchanged SQL gates and
strict type checks. No skip or weakened assertion is accepted.

`GFLO_DISPOSABLE_LOCALHOST=YES python3 pilot0d1/frozen-diagnostics.py` separately
observes three predetermined executions of the unchanged frozen concurrency case.
It preserves source fingerprints, assertions and deadlines and records no args,
tokens or payloads. These are diagnostic repetitions, not extra unique tests or
a substitute for the 59-case inherited gate. Any failure remains a failure.

The combined CI uses separate inherited-PostgreSQL and browser jobs. The former
creates distinct fresh localhost databases. Browser tests run in a digest-pinned,
read-only, cap-dropped Docker container with **network:none**, private loopback,
resource limits, temporary browser state and an evidence-only writable mount.
No PG/production credential is passed to it. Signer RPCs have bounded deadlines;
timeout retires, terminates and reaps the key worker before returning an error.
There is no private-key export command and no worker reuse after timeout. npm SRI pins are independently
compared with registry metadata before script-free installation; package versions,
Chromium revision/version and image RepoDigests are checked/recorded. See
`dependencies.json` for seed references and exact pins. No browser binary or
platform hermetic-rebuild claim is made beyond the immutable image boundary.

For an optional **manual synthetic** UI demo on an authorized local display, run
`GFLO_DISPOSABLE_LOCALHOST=YES node pilot0d1/demo.cjs` after installing the pinned
tools/browser. It launches a fresh browser without extensions, a separate
ephemeral key worker, and the fixture-only session bridge. It performs no clicks
or automatic signing; close the browser to destroy the fixture. This is not a
real-wallet acceptance test.

Artifacts contain named ledgers, provenance, type-check results, logs, hashes and
two synthetic UX screenshots. These are automated, genuinely rendered Chromium
demonstrations, not evidence of an authorized real-wallet interaction. Local
socket/Chromium restrictions may require CI-only execution; final delivery must
state exactly which suites ran locally. The browser's default CI sandbox mode
is not a certification of a production browser/host sandbox.

## Residual gates and Pilot 0D-2 proposal

Production stays BLOCKED: synthetic capabilities are not Supabase Auth; local
locks/audit/replay are not PostgreSQL transactions or replicas; source manifests,
SIWE/consent production UX, recovery, privileged operational controls and real
wallet-type evidence remain separate gates. Existing historical audit and
JavaScript secret-zeroization limitations from Pilot 0C remain. gfloDEVaccount
remains NOT VERIFIED. Local privileged processes or compromised browser extensions
are outside this pilot's isolation guarantee; HTTP loopback is not TLS/host trust.

0D-2 may proceed only with separate owner authorization naming the browser,
extension/version, exact localhost origin, dedicated disposable EOA wallet and
permitted manual signing steps. The wallet must contain no real assets and have
no production account/seed reuse. The application must never request its key or
seed; the extension keeps it. First inspect personal_sign bytes and EIP-712 domain,
principal/profile/source/scope/expiry and verify there are **no transaction or
approval RPCs**. Repeat cancellation, switching, origin/chain, A/B, expiration,
revocation, replay, CSP/storage and final-release tests. Require independent review
of this DRAFT package, all 375 regressions/SQL/type gates, redacted evidence and
a documented teardown. No funded wallet, production account, deployment, binding
activation, migration, merge or automatic continuation is authorized here.
