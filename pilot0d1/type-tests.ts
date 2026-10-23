import {OfflineProof,SyntheticAuthority,SyntheticFence,SyntheticAudit,localhostRealm, type SyntheticSessionHandle,type ProofObservation} from '../pilot0c/proof.cjs';
import type {FixtureBridge,EIP1193Provider} from './contracts';
declare const observer:ProofObservation;
// @ts-expect-error A read-only observation cannot authorize canonical XP.
observer.canonicalXpAuthorized=true;
// @ts-expect-error Session handles cannot be constructed from caller identifiers.
const forged:SyntheticSessionHandle={principal:'victim'};
declare const proof:OfflineProof;
// @ts-expect-error No binding activation capability exists.
proof.activate();
const authority=new SyntheticAuthority([['principal','profile']]);
const handle=authority.issue('principal');
const configured=new OfflineProof({authority,fence:new SyntheticFence(['principal']),audit:new SyntheticAudit(),wallets:[],sources:[],realm:localhostRealm()});
configured.verify(handle,{challengeId:'id',message:'siwe',siweSignature:'sig',consent:'json',consentSignature:'sig'},{deadline:1,signal:new AbortController().signal});
declare const provider:EIP1193Provider;
const bridge:FixtureBridge={mode:'SYNTHETIC_AUTOMATED',provider,session:async()=>({token:'opaque',csrf:'opaque'})};
void [forged,bridge,observer];

import type {IdentityExplorerResult,ChallengeTransportInput} from './contracts';
import type {CanonicalPieReader} from '../pilot0a-frozen/evidence/sources/octogflo/src/domain/octopass-adapters.js';
declare const result:IdentityExplorerResult;
// @ts-expect-error An untrusted null value cannot implement canonical protocol XP.
const canonical:Awaited<ReturnType<CanonicalPieReader['read']>>={canonicalXp:result.syntheticPie.canonicalXp,historicalTier:0,path:[]};
// @ts-expect-error AuthContext is never a client challenge input.
const impersonated:ChallengeTransportInput={wallet:'address',chainId:11155111,requestId:'uuid',source:'demo',AuthContext:{principal:'B'}};
void [canonical,impersonated];
