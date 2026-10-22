// Pure domain types for the OctoGFLO simulation. DEMO ONLY — no chain, no wallet.

export type ClaimStatus =
  "AWAITING_APPROVALS" | "PENDING" | "FINALIZED_VALID" | "REJECTED" | "REVOKED";

export type RejectReason =
  "FORGED" | "REPLAY" | "SAME_SOURCE" | "REVOKED_ISSUER" | "CHALLENGE_UPHELD";

export interface Issuer {
  id: string;
  sourceGroup: string;
  revoked: boolean;
}

export interface Approval {
  issuerId: string;
  signatureMock: string;
  at: number; // simulated day
}

export interface Claim {
  id: string;
  evidenceHash: string;
  nonce: string;
  /** Demo contribution units. Not a protocol value. */
  contribution: number;
  evidenceValid: boolean;
  approvals: Approval[];
  status: ClaimStatus;
  submittedAt: number;
  challengeEndsAt?: number;
  challenged?: boolean;
  rejectReason?: RejectReason;
}

export interface Policy {
  id: "XPPolicy-V05-candidate";
  status: "CANDIDATE";
  minIndependentSources: number;
  challengeDays: number;
}

export interface TierRule {
  tier: number;
  minXp: number;
}

export interface SimState {
  now: number; // simulated day, injected clock
  address: string;
  genesisXp: number;
  historicalTier: number;
  claims: Claim[];
  issuers: Issuer[];
  policy: Policy;
  tierRules: TierRule[] | null;
  log: SimEvent[];
}

export type SimEventType =
  | "SUBMITTED"
  | "REJECTED"
  | "APPROVED"
  | "PENDING"
  | "CLOCK"
  | "FINALIZED"
  | "CHALLENGED"
  | "CHALLENGE_DISMISSED"
  | "REVOKED"
  | "NOOP"
  | "INVALID";

/** Fail-closed reasons for simulated inputs that are refused without changing claims or XP. */
export type InvalidReason =
  | "DUPLICATE_ID"
  | "BAD_CONTRIBUTION"
  | "DUPLICATE_APPROVAL"
  | "UNKNOWN_ISSUER"
  | "UNKNOWN_CLAIM"
  | "BAD_TIME"
  | "WRONG_STATUS";

export interface SimEvent {
  seq: number;
  day: number;
  type: SimEventType;
  claimId?: string;
  detail?: string;
}

export type Action =
  | { kind: "submit"; claim: Omit<Claim, "approvals" | "status" | "submittedAt"> }
  | { kind: "approve"; claimId: string; issuerId: string }
  | { kind: "advance"; days: number }
  | { kind: "challenge"; claimId: string; upheld: boolean }
  | { kind: "revoke"; claimId: string };

export type Triage = "GREEN" | "YELLOW" | "RED" | "BLACK";
export type EffectiveTier = { evaluated: false } | { evaluated: true; tier: number };
