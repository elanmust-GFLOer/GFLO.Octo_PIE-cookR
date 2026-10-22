import { runActions } from "./engine";
import type { Action, Issuer, Policy, SimState } from "./types";

// All values below are DEMO parameters, not protocol values.
export const DEMO_ADDRESS = "0xDEMO000000000000000000000000000000000A1";
export const DEMO_CONTRIBUTION = 10;

export const issuers: Issuer[] = [
  { id: "DEMO-ISS-A", sourceGroup: "DEMO-SRC-1", revoked: false },
  { id: "DEMO-ISS-B", sourceGroup: "DEMO-SRC-2", revoked: false },
  { id: "DEMO-ISS-C", sourceGroup: "DEMO-SRC-1", revoked: false },
  { id: "DEMO-ISS-D", sourceGroup: "DEMO-SRC-3", revoked: true },
];

export const policy: Policy = {
  id: "XPPolicy-V05-candidate",
  status: "CANDIDATE",
  minIndependentSources: 2,
  challengeDays: 3,
};

export function genesisState(): SimState {
  return {
    now: 0,
    address: DEMO_ADDRESS,
    genesisXp: 25,
    historicalTier: 0,
    claims: [],
    issuers,
    policy,
    tierRules: null,
    log: [],
  };
}

export function demoClaim(
  n: number,
  opts: { valid?: boolean; nonce?: string; hash?: string } = {},
) {
  return {
    id: `DEMO-CLAIM-${n}`,
    evidenceHash: opts.hash ?? `DEMO-HASH-${n}`,
    nonce: opts.nonce ?? `DEMO-NONCE-${n}`,
    contribution: DEMO_CONTRIBUTION,
    evidenceValid: opts.valid ?? true,
  };
}

export type ScenarioId = "legitimate" | "forged" | "replay" | "collusion" | "revoked";

const legit: Action[] = [
  { kind: "submit", claim: demoClaim(1) },
  { kind: "approve", claimId: "DEMO-CLAIM-1", issuerId: "DEMO-ISS-A" },
  { kind: "approve", claimId: "DEMO-CLAIM-1", issuerId: "DEMO-ISS-B" },
  { kind: "advance", days: 1 },
  { kind: "advance", days: 2 },
];

export const scenarios: Record<ScenarioId, Action[]> = {
  legitimate: legit,
  forged: [{ kind: "submit", claim: demoClaim(2, { valid: false }) }],
  replay: [...legit, { kind: "submit", claim: { ...demoClaim(3), nonce: "DEMO-NONCE-1" } }],
  collusion: [
    { kind: "submit", claim: demoClaim(4) },
    { kind: "approve", claimId: "DEMO-CLAIM-4", issuerId: "DEMO-ISS-A" },
    { kind: "approve", claimId: "DEMO-CLAIM-4", issuerId: "DEMO-ISS-C" },
  ],
  revoked: [...legit, { kind: "revoke", claimId: "DEMO-CLAIM-1" }],
};

export const scenarioIds = Object.keys(scenarios) as ScenarioId[];

export type IdentityFixtureId = "genesisOnly" | "pendingClaim" | "finalizedClaim" | "revokedClaim";

export const identityFixtures: Record<IdentityFixtureId, () => SimState> = {
  genesisOnly: () => genesisState(),
  pendingClaim: () => runActions(genesisState(), legit.slice(0, 3)),
  finalizedClaim: () => runActions(genesisState(), legit),
  revokedClaim: () => runActions(genesisState(), scenarios.revoked),
};

export const identityFixtureIds = Object.keys(identityFixtures) as IdentityFixtureId[];
