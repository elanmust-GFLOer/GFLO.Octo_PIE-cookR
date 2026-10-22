# B2.3-R5 — Operational Quarantine, first independent subgate

This is **only the first R5 security slice**. The SQL overlay revokes executable mutation interfaces and direct table/session access from known untrusted and lab caller roles. It intentionally leaves no authorized application suspension path. Test users must not receive mutator or owner membership.

**Not implemented here:** verified Supabase identity, session generation/revocation contract, complete role/membership inventory across deployed services, DELETE races, request concurrency, lifecycle recovery, pinned provenance or full test manifest. Historic R4 22/22 evidence remains a separate prior baseline; this workflow does not re-execute it. No production authorization, merge or deployment.

Note: postgres and table owners can still alter data and audit. The laboratory R3 mutator is privileged and must not be used as an application credential. All open finding references remain open until new review.
