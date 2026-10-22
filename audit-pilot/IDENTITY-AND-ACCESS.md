# Audit pilot identity and access

gfloDEVaccount: **NOT VERIFIED**. No name-based assumption establishes principal,
ownership, environment, enrollment, credentials or effective permissions.

Before real observation, an owner must document the exact verified subject,
Auth project/issuer/audience, controlled ownership proof, non-production
environment, explicit observer entitlement and full effective role/grant graph.
No production credential is needed or permitted for this package.

| Level | Current readiness | Gate |
|---|---|---|
| A: real read-only observation | NOT VERIFIED | Principal and read-only source authorization independently evidenced |
| B: controlled synthetic behavior | Only offline fixtures available | Dedicated environment/accounts, explicit authorization and test ledger |
| C: production writes | BLOCKED | Separate authorization plus complete Auth, SIWE, consent, recovery and audit controls |

The observer must have zero domain INSERT/UPDATE/DELETE/TRUNCATE, zero mutation
EXECUTE, no service-role credential, no owner/mutator membership or SET ROLE path.
Grant no SQL access in R6A. The laboratory observer reads only aggregated counts
from a separate bounded synthetic event sink through the final authorization fence.
It cannot inspect real Auth sessions, user records, wallets, cookies or token logs.
R5 operational roles and privileges remain unchanged.
