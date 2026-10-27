// GFLO IB-03B — SYNTHETIC, INJECTED, READ-ONLY reference bridge.
// NOT a real RPC adapter, credential validator, wallet binding or authorization service.
// VERIFIED means only that all *injected mocks* agreed. NEVER grant production access from it.
const addr=/^0x[0-9a-fA-F]{40}$/;
const hash=/^0x[0-9a-fA-F]{64}$/;
const unsigned=/^(0|[1-9][0-9]*)$/;
const eq=(a,b)=>typeof a==="string"&&typeof b==="string"&&a.toLowerCase()===b.toLowerCase();
const deny=(reason,status="NOT_VERIFIED")=>Object.freeze({status,reason});
const uint=v=>typeof v==="bigint"?v.toString():typeof v==="number"&&Number.isSafeInteger(v)?String(v):v;
function hasConsent(binding,t){
 return binding?.status==="ACTIVE"&&addr.test(binding?.wallet??"")&&
 binding?.consent?.revoked===false&&binding.consent?.scopes?.includes("pie:xp:read")&&
 Number.isSafeInteger(binding.consent.expiresAt)&&binding.consent.expiresAt>t;
}
function validConfig(p){
 return p&&unsigned.test(p.chainId??"")&&
 [p.core,p.registry,p.policy,p.owner].every(x=>addr.test(x??""))&&
 [p.hashes?.core,p.hashes?.registry,p.hashes?.policy,p.abiSha256].every(x=>hash.test(x??""))&&
 /^[a-fA-F0-9]{40}$/.test(p.sourceCommit??"")&&
 Number.isSafeInteger(p.maxAgeSeconds)&&p.maxAgeSeconds>=0;
}
export async function readOctoPassPie({pins,identity,chain,clock,codehash}){
 if(!validConfig(pins)||typeof clock!=="function"||typeof codehash!=="function"||
 typeof identity?.session!=="function"||typeof identity?.binding!=="function"||
 !chain||["chainId","finalized","runtime","abiHash","registryState","policyState","totalXp"].some(x=>typeof chain[x]!=="function"))
  return deny("INVALID_CONFIGURATION");
 try{
  const time=clock();
  if(!Number.isSafeInteger(time)||time<0)return deny("BAD_CLOCK");
  const session=await identity.session();
  if(!session?.authenticated||!session?.subject)return deny("UNAUTHORIZED");
  const binding=await identity.binding(session.subject,pins.chainId);
  if(!hasConsent(binding,time))return deny("BINDING_OR_CONSENT_INVALID");
  if(binding.chainId!==pins.chainId)return deny("CHAIN_MISMATCH");
  if(uint(await chain.chainId())!==pins.chainId)return deny("CHAIN_MISMATCH");
  const b=await chain.finalized();
  if(b?.finalized!==true||!unsigned.test(uint(b.number)??"")||!hash.test(b.hash??"")||
     !Number.isSafeInteger(b.timestamp)||b.timestamp>clock()||clock()-b.timestamp>pins.maxAgeSeconds)
    return deny("UNFINALIZED_OR_STALE","UNAVAILABLE");
  // Every injected read MUST be fixed to b.hash. This mock contract cannot independently
  // attest to actual RPC block pinning, TLS provenance or real EVM codehash.
  for(const k of ["core","registry","policy"]){
   const runtime=await chain.runtime(pins[k],b.hash);
   if(!runtime||runtime==="0x"||!eq(await codehash(runtime),pins.hashes[k]))return deny("CODEHASH_MISMATCH");
  }
  if(!eq(await chain.abiHash(b.hash),pins.abiSha256))return deny("ABI_MISMATCH");
  const reg=await chain.registryState(pins.registry,b.hash);
  const pol=await chain.policyState(pins.policy,b.hash);
  if(reg?.paused===true||pol?.paused===true)return deny("PAUSED","UNAVAILABLE");
  if(!eq(reg?.core,pins.core)||!eq(reg?.activePolicy,pins.policy)||
   !eq(reg?.activePolicyHash,pins.hashes.policy)||!eq(reg?.policyOwner,pins.owner)||
   !eq(pol?.core,pins.core)||!eq(pol?.owner,pins.owner))return deny("UNAPPROVED_SOURCE");
  const xp=uint(await chain.totalXp(pins.registry,binding.wallet,b.hash));
  if(typeof xp!=="string"||!unsigned.test(xp)||BigInt(xp)>((1n<<64n)-1n))return deny("INVALID_XP");
  // Revalidate identity after all awaits, to reject consent/binding revocation races.
  const secondSession=await identity.session();
  const second=await identity.binding(session.subject,pins.chainId);
  if(!secondSession?.authenticated||secondSession.subject!==session.subject||
   !hasConsent(second,clock())||second.chainId!==pins.chainId||
   !eq(second.wallet,binding.wallet)||second.bindingGeneration!==binding.bindingGeneration||
   second.consent.generation!==binding.consent.generation)return deny("STALE_AUTHORIZATION","UNAVAILABLE");
  if(clock()-b.timestamp>pins.maxAgeSeconds)return deny("UNFINALIZED_OR_STALE","UNAVAILABLE");
  return Object.freeze({status:"MOCK_VERIFIED",wallet:binding.wallet,canonicalXp:xp,
   chainId:pins.chainId,registry:pins.registry,blockHash:b.hash,
   sourceCommit:pins.sourceCommit,nonAuthoritative:true});
 }catch{return deny("INJECTED_DEPENDENCY_FAILURE","UNAVAILABLE");}
}
