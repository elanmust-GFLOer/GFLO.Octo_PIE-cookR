# AR01-05J — Stateful security and provenance gate

Status: **planned stateful suite; not yet executed**. The existing 23/23 signed EVM regression is the baseline.

## Reproducibility improvements in workflow

- PIE source is pinned to `dbd02d3f1ffd31abff3bda9caaa9852ee7cecf5c`.
- Legacy GasFeeLoop source is pinned to `16f5e5aaa52d8022d33cee46cdcbba4e5e49fa7c`.
- Checkout revisions are asserted before running.
- Test output and SHA-256 digests of workflow, test and contract are uploaded as CI evidence.

**Still missing:** lockfile-driven `npm ci`, exact GitHub Action SHAs, and an immutable dependency provenance record. The first CI run after workflow change must be checked before these changes can be marked verified.

## Stateful model test plan

Model variables per recipient: `claimCount`, `dailyReserved[day]`, `weeklyReserved[week]`, `earnedXP`, `usedEvent`, `usedEvidence`, `usedNonce`, `grantStatus`, `released`. Model independent governance-controlled source epoch and active state.

| Sequence | Expected invariant |
|---|---|
| submit → revoke(PENDING) → release → release | First release restores original quota, second reverts; replay keys stay used |
| submit → finalize → revoke(VALID) → release | XP removed by revoke, recovery rejected |
| submit → source pause/rotate → finalize | Finalize rejected; pending claim cannot bypass epoch |
| submit A and B in same day/week → revoke A → release A | B's reservation remains; no underflow |
| submit A in week W → revoke A in W+1 → release A | Only original W buckets decrease |
| independent recipients A/B with identical rule | Recovery for A never modifies B |
| invalid signature → valid retry | Failed submit leaves quota and nullifiers untouched |
| registry pause → read → unpause | Read fails closed during pause; canonical XP restored afterward |
| ignition burn → XP revoke → recovery | Supply never increases, achieved tier stays historical, effective tier falls |

For each operation, snapshot all affected storage, receipt status, logs, Registry XP, token supply and tier. Randomize operation sequences with recorded seed; include a reference model, shrinking/minimal reproduction and at least two distinct recipients and two nonoverlapping week buckets. No PASS claim until this suite is implemented and CI logs inspected.

## Provenance and collusion threat model

- Two distinct EOA addresses are **not** proof of two independent organizations or devices. Model colluding issuers as one adversary.
- On-chain issuer signatures authenticate statements, not the off-chain truth of event completion.
- Evidence hashes need verifiable source, timestamp, canonicalization, retention and dispute procedure.
- Shared global event/evidence nullifiers can create cross-source denial-of-service; test intentionally colliding identifiers.
- Safe owner compromise, source key compromise, malicious verifier and time-bound expiry require documented incident runbooks.

## Gate criteria

1. Existing signed EVM 23/23 PASS on pinned upstream source SHAs.
2. Evidence artifact uploaded and manifest hashes independently checked.
3. Stateful multi-recipient suite implemented, passing, and reproducible from recorded seeds.
4. Dependency lockfile and immutable action references introduced.
5. Unresolved issues entered into audit risk register with severity and owner.

No staging/mainnet approval is implied by any single gate.
