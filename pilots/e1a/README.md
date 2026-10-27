# GFLO Pilot E1-A — OctoPass Integration Gateway / ID_Entity Baseline

**Status:** ISOLATED CONTRACT LAB; not deployed; no live Builder reviews; NO XP minting.

## Architecture decision
OctoPass is the **identity, consent and access gateway**, not the oracle of activity truth.
OctoPush Builder is the **source** of `builder.reviewed` decisions and their server-side review evidence.
PIE accepts only a separately policy-admitted, verifiable source event; never browser-defined `projects.status`.

`ID_Entity` is a conceptual principal registry, not a claim of uniqueness or humanity:
- `PERSON`: registered human-operated account identifier (not KYC / proof-of-personhood / Sybil-resistant by default);
- `AGENT`: software agent with independently identifiable keys and bounded delegation;
- `SERVICE`: MCP server / integration issuer or connector principal; MCP itself is a transport/protocol, not a human or authenticated agent.
- An agent can act **on behalf of** a PERSON only with explicit project/scope/expiry-bound grant, consent, revocation and auditable delegation chain.
- No inherited write authority, onchain XP rights or automatic person-equivalence.

## First vertical slice (E1)
1. Existing OctoPush `projects.status` stays user-editable for workflow UX; **never** treat as reviewed proof.
2. Protected server-side `builder_review_decisions` (role-checked, no self-review) and append-only `builder_review_events` must be created **atomically** in Supabase after review evidence is checked. Deny browser INSERT/UPDATE/DELETE (including direct PostgREST); pinned `issuerId` and event id uniqueness. RLS, column privileges, SECURITY DEFINER controls and service-key boundaries must be separately red-teamed.
3. Gateway validates issuer binding, signature, schema, digest, unique event id, owner/profile mapping and **explicit read consent**; record revocation/correction rather than rewriting facts.
4. OctoPass can display proof; PIE Explorer can read it under consent. **No rewards** until canonical V04 policy and source truth are independently approved.
5. Future IAM: least-privilege `AGENT` or `SERVICE` principal, capability grants, key rotation, kill switch, traceable actor-vs-subject attribution.

## E1-A executable contract
`gateway.mjs` and `gateway.test.mjs` use **ephemeral Ed25519 lab keys**. They demonstrate type separation, consent/delegation checks, digest and signing-envelope verification, duplicate detection. `issueLabReview` is not a substitute for server-verifiable evidence or DB atomicity. No persistent replay store or real authentication.

## Required gates BEFORE production / any main-branch merge
- R1E mandatory integrated CI across PR #20 still has failures; classify and close without muting tests.
- Independent clean-room Codex revalidation against pinned hashes.
- Verify Lovable/Supabase live schema and policies in a **read-only** preflight, then design an isolated migration and adversarial tests for review permissions.
- Production keys in server-side protected KMS; server-to-server issuer proof pinned by configuration and revocable epochs.
- Consent is scoped by resource and application; no implicit `PERSON` authority for machine `Entity`.
- A trusted reviewer can lie; signed source integrity is not objective truth. Retain audit evidence and dispute/reversal path.
- The older wallet-attached XP/Genesis model is historical vision, **not** current V04 security implementation; wallet signature proves key control only, not uniqueness of human.

Source baseline: OctoPush Lovable commit `e5d89445995e2f73c0f954552a17e847934e5ae8` (Builder directly updates `projects.status`; OctoPass existing page stores profile fields); cookR PR #20 base `3b31939cd3075cf07147f6e35fabf48f06ab126a`.
