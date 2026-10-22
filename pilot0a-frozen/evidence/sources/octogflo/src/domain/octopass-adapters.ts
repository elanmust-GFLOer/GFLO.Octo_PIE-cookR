// FUTURE adapter contracts for OctoPass Local. Types only — nothing implements them in MVP 01.
// Invariant: no adapter here can write canonical XP; PIE data flows to OctoPass read-only.

export type ProfileId = string & { readonly __brand: "ProfileId" };
export type ProtocolId = string & { readonly __brand: "ProtocolId" };

export interface WalletOwnershipVerifier {
  /** Proves control of a wallet. Never proves a unique human. */
  verify(challenge: string, signature: string, address: string): Promise<{ owned: boolean }>;
}

export interface ConsentLinker {
  requestLink(
    profile: ProfileId,
    protocol: ProtocolId,
    scopes: string[],
  ): Promise<{ linkId: string }>;
}

export interface IdentifierMap {
  protocolFor(profile: ProfileId): Promise<ProtocolId | null>;
}

export interface SelectiveDisclosure {
  setVisible(profile: ProfileId, field: string, visible: boolean): Promise<void>;
}

export interface LinkRevocation {
  revoke(linkId: string): Promise<void>;
}

export interface AccountRecovery {
  startRecovery(profile: ProfileId): Promise<{ ticket: string }>;
}

export interface CanonicalPieReader {
  /** Read-only view of protocol identity. */
  read(
    protocol: ProtocolId,
  ): Promise<{ canonicalXp: number; historicalTier: number; path: string[] }>;
}
