/** Offline fixture contract. Runtime WeakMap membership, not this type, proves context. */
declare const sessionBrand: unique symbol;
export type SyntheticSessionHandle = Readonly<{ [sessionBrand]: true }>;
export type SourceClass = 'DEMO_FIXTURE' | 'LEGACY_UNTRUSTED_XP';
export interface SourceReference {
 readonly chainId: 11155111; readonly contract: string; readonly reference: string;
 readonly manifestDigest: string; readonly classification: SourceClass;
}
export interface Consent {
 readonly principal: string; readonly profile: string; readonly wallet: string;
 readonly chainId: 11155111; readonly protocolSource: string; readonly protocolManifestDigest: string;
 readonly scopes: readonly ['id-entity.proof.read']; readonly generation: number;
 readonly nonce: string; readonly challengeId: string; readonly requestId: string;
 readonly siweMessageHash: string; readonly expiresAt: number; readonly consentVersion: 'pilot0c/1';
 readonly consentTextDigest: string; readonly authProject: 'GFLO-PILOT-0C-SYNTHETIC'|'GFLO-PILOT-0D1-SYNTHETIC';
}
export interface Challenge {
 readonly challengeId: string; readonly message: string; readonly consent: Consent;
 readonly consentDomain: Readonly<Record<string,unknown>>;
 readonly consentTypes: Readonly<Record<string,readonly Readonly<{name:string;type:string}>[]>>;
 readonly consentText: string; readonly expiresAt: number;
}
export interface Submission {
 readonly challengeId: string; readonly message: string; readonly siweSignature: string;
 /** Exact canonical server-issued consent JSON. */
 readonly consent: string; readonly consentSignature: string;
}
export interface NonAuthority {
 readonly traceId: string; readonly productionAuthorized: false; readonly canonicalXpAuthorized: false;
 readonly mutationCapabilities: readonly []; readonly entitlements: readonly []; readonly reusable: false;
}
export interface ProofObservation extends NonAuthority {
 readonly kind: 'OFFLINE_READ_ONLY_OBSERVATION'; readonly principal: string; readonly profile: string;
 readonly wallet: string; readonly chainId: 11155111; readonly protocolSource: string;
 readonly protocolManifestDigest: string; readonly generation: number;
 readonly scopes: readonly ['id-entity.proof.read']; readonly expiresAt: number;
 readonly sourceClassification: SourceClass; readonly evidenceClassifications: readonly string[];
 readonly consentDigest: string;
}
export interface Denial extends NonAuthority { readonly kind:'DENIED'; readonly reason:string; }
export class OfflineProof {
 constructor(config:{authority:SyntheticAuthority;fence:SyntheticFence;audit:SyntheticAudit;
 wallets:readonly {address:string;kind:'EOA'|'ERC1271'|'UNKNOWN'}[];sources:readonly SourceReference[];
 clock?:()=>number;monotonic?:()=>number;realm?:LocalhostRealm});
 issue(handle:SyntheticSessionHandle,input:{wallet:string;source:string;requestId:string}):Challenge;
 revokeConsent(handle:SyntheticSessionHandle,id:string):void;
 verify(handle:SyntheticSessionHandle,input:Submission,options?:{deadline?:number;signal?:AbortSignal}):Promise<ProofObservation|Denial>;
}
/** Administrative methods below are synthetic test controls, never endpoints. */
export class SyntheticAuthority {
 constructor(owners:readonly (readonly [string,string])[],clock?:()=>number);
 issue(principal:string):SyntheticSessionHandle;
 observe(handle:SyntheticSessionHandle):Readonly<{principal:string;profile:string;sessionId:string;state:string;generation:number;expiresAt:number}>;
 setState(handle:SyntheticSessionHandle,state:'ACTIVE'|'REVOKED'|'UNKNOWN'):void;
 advance(handle:SyntheticSessionHandle):void;
}
export class SyntheticFence {
 constructor(principals:readonly string[]);
 observe(principal:string):Readonly<{generation:number;state:string}>;
 suspend(principal:string):void;advance(principal:string):void;
}
export class SyntheticAudit { available:boolean;approve(event:{traceId:string;requestId:string;principal:string;code:string}):boolean;snapshot():readonly object[]; }

declare const realmBrand: unique symbol;
export interface LocalhostRealm {readonly [realmBrand]:true; readonly domain:'127.0.0.1:43817';readonly uri:'http://127.0.0.1:43817/id-entity';}
export function localhostRealm():LocalhostRealm;
export const LOCAL_ORIGIN:'http://127.0.0.1:43817';
