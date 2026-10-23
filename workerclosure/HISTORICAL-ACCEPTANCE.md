# Historical oracle acceptance recommendation — proposal only

The current correction **does not propagate** into the historical R6A worktree at `12e2df4c32ef51d08c799ec63a565c90221e8bcd`. Frozen Pilot 0A's bootstrap checks that exact anchor and imports its original worker. Its `.4` stage setting, 2-second historical harness budget, original tests/assertions and all 41 archived files remain byte-identical. The current gateway's separate maximum 1-second budget remains unchanged too.

The original `test_concurrent_same_consent_is_single_use` still expects ALLOW / CONSENT_REPLAY DENY. It may continue to observe QUARANTINE / QUARANTINE because the old supervisor remains vulnerable. Its raw result must stay FAIL. Current-code success and a passing diagnostic lock control cannot turn that historical observation into PASS.

## Proposed review decision

**Default policy, still enforced:** the inherited aggregate gate requires all historical tests to pass and stays red on any failure. No waiver is implemented by this package. The complete runner retains all original 59 named historical results and continues unrelated suites to avoid NOT_EXECUTED gaps.

For independent review, the recommended alternative is an explicit, versioned **historical known-defect exception**, narrowly limited to the concurrency case at that exact anchor. It is a governance decision about laboratory integration, not a test correction. Before accepting it, a reviewer must confirm:

1. Exact source/41-file inventory and original assertion/deadline preservation; complete prior red evidence remains accessible with hashes and run IDs.
2. The failed observation is linked to the reaping/cache cause by a sanitized reason/stage trace, with zero unauthorized release. A failure with another reason is not automatically covered.
3. The corrected current worker passes deterministic ownership, real overlapping-child, global-cleanup, unkillable, accounting, timeout and original security gates across the three predeclared cohorts on the same source tree.
4. All 59 historical tests still execute and retain their raw statuses. A failing test is neither skipped, renamed, xfailed nor reported as PASS. Counts distinguish unique names, repeated trials, current-code acceptance and historical findings.
5. Any acceptance statement says “current runtime accepted for isolated laboratory use; historical known-defect failure retained under reviewed exception.” It cannot say “all inherited tests PASS” while a raw failure exists.
6. The exception names the approving human reviewer, exact anchor/test, acceptable failure signature, evidence IDs, scope, expiry/review date and revocation rule. It grants no runtime, migration, wallet, staging, production or merge authority.

If the reviewer rejects an exception, retain the strict red aggregate gate. A separate corrected historical-oracle experiment may be created and named separately, but never replaces the frozen original. Neither repeated opportunistically green historical runs nor substituting current source into the old worktree is an acceptable policy.

The existing green historical results remain valid observations of their own runs. They do not invalidate the preserved failures. This proposal has not been independently approved and is not wired into CI as a waiver.
