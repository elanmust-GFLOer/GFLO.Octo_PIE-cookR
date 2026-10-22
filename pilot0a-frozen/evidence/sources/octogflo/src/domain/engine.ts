import type {
  Action,
  Claim,
  EffectiveTier,
  InvalidReason,
  Issuer,
  SimEvent,
  SimState,
  TierRule,
  Triage,
} from "./types";

// Pure, deterministic simulation engine. Every function returns a new state.

function emit(state: SimState, e: Omit<SimEvent, "seq" | "day">): SimEvent[] {
  return [...state.log, { seq: state.log.length + 1, day: state.now, ...e }];
}

function updateClaim(state: SimState, id: string, patch: Partial<Claim>): Claim[] {
  return state.claims.map((c) => (c.id === id ? { ...c, ...patch } : c));
}

/** Fail closed: claims, clock and XP stay unchanged; only an INVALID event is logged. */
function invalid(
  state: SimState,
  reason: InvalidReason,
  claimId?: string,
  extra?: string,
): SimState {
  return {
    ...state,
    log: emit(state, {
      type: "INVALID",
      ...(claimId ? { claimId } : {}),
      detail: extra ? `${reason}:${extra}` : reason,
    }),
  };
}

export function validContribution(n: number): boolean {
  return Number.isInteger(n) && n > 0;
}

export function validDays(n: number): boolean {
  return Number.isInteger(n) && n > 0;
}

export function independentSources(claim: Claim, issuers: Issuer[]): number {
  const groups = new Set<string>();
  for (const a of claim.approvals) {
    const iss = issuers.find((i) => i.id === a.issuerId);
    if (iss && !iss.revoked) groups.add(iss.sourceGroup);
  }
  return groups.size;
}

export function apply(state: SimState, action: Action): SimState {
  switch (action.kind) {
    case "submit": {
      const c = action.claim;
      if (state.claims.some((x) => x.id === c.id)) return invalid(state, "DUPLICATE_ID", c.id);
      if (!validContribution(c.contribution)) return invalid(state, "BAD_CONTRIBUTION", c.id);
      const replay = state.claims.some(
        (x) =>
          x.status !== "REJECTED" && (x.nonce === c.nonce || x.evidenceHash === c.evidenceHash),
      );
      const base: Claim = {
        ...c,
        approvals: [],
        status: "AWAITING_APPROVALS",
        submittedAt: state.now,
      };
      if (!c.evidenceValid || replay) {
        const reason = !c.evidenceValid ? "FORGED" : "REPLAY";
        return {
          ...state,
          claims: [...state.claims, { ...base, status: "REJECTED", rejectReason: reason }],
          log: emit(state, { type: "REJECTED", claimId: c.id, detail: reason }),
        };
      }
      return {
        ...state,
        claims: [...state.claims, base],
        log: emit(state, { type: "SUBMITTED", claimId: c.id }),
      };
    }
    case "approve": {
      const claim = state.claims.find((c) => c.id === action.claimId);
      const issuer = state.issuers.find((i) => i.id === action.issuerId);
      if (!claim) return invalid(state, "UNKNOWN_CLAIM", action.claimId);
      if (!issuer) return invalid(state, "UNKNOWN_ISSUER", claim.id);
      if (claim.status !== "AWAITING_APPROVALS")
        return invalid(state, "WRONG_STATUS", claim.id, claim.status);
      if (claim.approvals.some((a) => a.issuerId === issuer.id))
        return invalid(state, "DUPLICATE_APPROVAL", claim.id);
      if (issuer.revoked) {
        const s = {
          ...state,
          claims: updateClaim(state, claim.id, {
            status: "REJECTED",
            rejectReason: "REVOKED_ISSUER",
          }),
        };
        return {
          ...s,
          log: emit(state, { type: "REJECTED", claimId: claim.id, detail: "REVOKED_ISSUER" }),
        };
      }
      const approvals = [
        ...claim.approvals,
        {
          issuerId: issuer.id,
          signatureMock: `DEMO-SIG-${issuer.id}-${claim.nonce}`,
          at: state.now,
        },
      ];
      const next = { ...claim, approvals };
      let s: SimState = {
        ...state,
        claims: updateClaim(state, claim.id, { approvals }),
        log: emit(state, { type: "APPROVED", claimId: claim.id, detail: issuer.id }),
      };
      const k = state.policy.minIndependentSources;
      const indep = independentSources(next, state.issuers);
      if (indep >= k) {
        s = {
          ...s,
          claims: updateClaim(s, claim.id, {
            status: "PENDING",
            challengeEndsAt: state.now + state.policy.challengeDays,
          }),
          log: emit(s, { type: "PENDING", claimId: claim.id }),
        };
      } else if (approvals.length >= k) {
        s = {
          ...s,
          claims: updateClaim(s, claim.id, { status: "REJECTED", rejectReason: "SAME_SOURCE" }),
          log: emit(s, { type: "REJECTED", claimId: claim.id, detail: "SAME_SOURCE" }),
        };
      }
      return s;
    }
    case "advance": {
      if (!validDays(action.days)) return invalid(state, "BAD_TIME");
      let s: SimState = { ...state, now: state.now + action.days };
      s = { ...s, log: emit(s, { type: "CLOCK", detail: String(s.now) }) };
      for (const c of s.claims) {
        if (
          c.status === "PENDING" &&
          c.challengeEndsAt !== undefined &&
          s.now >= c.challengeEndsAt
        ) {
          s = {
            ...s,
            claims: updateClaim(s, c.id, { status: "FINALIZED_VALID" }),
            log: emit(s, { type: "FINALIZED", claimId: c.id }),
          };
        }
      }
      return s;
    }
    case "challenge": {
      const claim = state.claims.find((c) => c.id === action.claimId);
      if (!claim) return invalid(state, "UNKNOWN_CLAIM", action.claimId);
      // Window is inclusive of its last day until the clock advances past it.
      if (claim.status !== "PENDING") return invalid(state, "WRONG_STATUS", claim.id, claim.status);
      if (action.upheld) {
        return {
          ...state,
          claims: updateClaim(state, claim.id, {
            status: "REJECTED",
            rejectReason: "CHALLENGE_UPHELD",
            challenged: true,
          }),
          log: emit(state, { type: "CHALLENGED", claimId: claim.id, detail: "UPHELD" }),
        };
      }
      return {
        ...state,
        claims: updateClaim(state, claim.id, { challenged: true }),
        log: emit(state, { type: "CHALLENGE_DISMISSED", claimId: claim.id }),
      };
    }
    case "revoke": {
      const claim = state.claims.find((c) => c.id === action.claimId);
      if (!claim) return invalid(state, "UNKNOWN_CLAIM", action.claimId);
      if (claim.status !== "FINALIZED_VALID")
        return invalid(state, "WRONG_STATUS", claim.id, claim.status);
      return {
        ...state,
        claims: updateClaim(state, claim.id, { status: "REVOKED" }),
        log: emit(state, { type: "REVOKED", claimId: claim.id }),
      };
    }
  }
}

export function runActions(state: SimState, actions: Action[]): SimState {
  return actions.reduce(apply, state);
}

/** Genesis + each unique finalized, unrevoked claim, counted once. */
export function canonicalXp(state: SimState): number {
  const seen = new Set<string>();
  let xp = state.genesisXp;
  for (const c of state.claims) {
    if (c.status !== "FINALIZED_VALID") continue;
    if (!validContribution(c.contribution)) continue;
    if (seen.has(c.evidenceHash) || seen.has(c.nonce)) continue;
    seen.add(c.evidenceHash);
    seen.add(c.nonce);
    xp += c.contribution;
  }
  return xp;
}

/** Shown separately. Never part of canonical XP. */
export function pendingXp(state: SimState): number {
  return state.claims.filter((c) => c.status === "PENDING").reduce((s, c) => s + c.contribution, 0);
}

/** Genesis/core XP versus earned XP, both parts of canonical XP. */
export function xpBreakdown(state: SimState) {
  const canonical = canonicalXp(state);
  return {
    genesis: state.genesisXp,
    earned: canonical - state.genesisXp,
    canonical,
    pending: pendingXp(state),
  };
}

export function countsTowardXp(state: SimState, claim: Claim): boolean {
  if (claim.status !== "FINALIZED_VALID") return false;
  const first = state.claims.find(
    (c) =>
      c.status === "FINALIZED_VALID" &&
      (c.evidenceHash === claim.evidenceHash || c.nonce === claim.nonce),
  );
  return first?.id === claim.id;
}

export function effectiveTier(xp: number, rules: TierRule[] | null): EffectiveTier {
  if (!rules || rules.length === 0) return { evaluated: false };
  const sorted = [...rules].sort((a, b) => b.minXp - a.minXp);
  const hit = sorted.find((r) => xp >= r.minXp);
  return { evaluated: true, tier: hit ? hit.tier : 0 };
}

/** OctoPartnR advisory triage. Reads state, never writes it. */
export function triage(state: SimState): Triage {
  const reasons = state.claims.map((c) => c.rejectReason);
  if (reasons.includes("SAME_SOURCE") || reasons.includes("REVOKED_ISSUER")) return "BLACK";
  if (reasons.includes("FORGED") || reasons.includes("REPLAY")) return "RED";
  if (
    state.claims.some(
      (c) => c.status === "PENDING" || c.status === "AWAITING_APPROVALS" || c.status === "REVOKED",
    )
  )
    return "YELLOW";
  return "GREEN";
}
