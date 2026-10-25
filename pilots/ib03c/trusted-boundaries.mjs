// IB-03C — reference server-side TRUST BOUNDARIES.
// No network endpoint, live SIWE verifier, persistent ledger or real finality authority provided.
// All injected dependencies MUST be independently authenticated before production use.
const address=v=>typeof v==="string"&&/^0x[0-9a-fA-F]{40}$/.test(v);
const bytes32=v=>typeof v==="string"&&/^0x[0-9a-fA-F]{64}$/.test(v);
const same=(a,b)=>typeof a==="string"&&typeof b==="string"&&a.toLowerCase()===b.toLowerCase();
const fail=m=>{throw new Error("IB03C_"+m)};
const numeric=v=>typeof v==="bigint"?v:typeof v==="number"&&Number.isSafeInteger(v)&&v>=0?BigInt(v):typeof v==="string"&&/^(0|[1-9][0-9]*)$/.test(v)?BigInt(v):fail("INTEGER");
const hexNum=v=>typeof v==="string"&&/^0x[0-9a-fA-F]+$/.test(v)?BigInt(v):fail("HEX_INTEGER");
const tag=h=>({blockHash:h,requireCanonical:true});
function port(o,fields){
 if(!o||fields.some(n=>typeof o[n]!=="function"))fail("UNTRUSTED_PORT");
}
export function createTrustedRpcBoundary({transport,finality,codec,crypto,pins,clock}){
 port(transport,["send"]);port(finality,["checkpoint"]);port(codec,["encode","decode","abiSha256"]);port(crypto,["keccak256"]); 
 if(typeof clock!=="function"||!pins||!numeric(pins.chainId)||!address(pins.core)||!address(pins.registry)||!address(pins.policy)||!address(pins.owner)||
 !bytes32(pins.coreHash)||!bytes32(pins.registryHash)||!bytes32(pins.policyHash)||!bytes32(pins.abiSha256)||
 !Number.isSafeInteger(pins.maxAgeSeconds)||pins.maxAgeSeconds<0)fail("PINS");
 const request=async(method,params)=>{if(!["eth_chainId","eth_getBlockByHash","eth_getCode","eth_call"].includes(method))fail("RPC_METHOD");return transport.send(method,params)};
 async function read(){
  if(hexNum(await request("eth_chainId",[]))!==numeric(pins.chainId))fail("CHAIN");
  const checkpoint=await finality.checkpoint();
  if(checkpoint?.finalized!==true||!bytes32(checkpoint.hash)||!Number.isSafeInteger(checkpoint.timestamp)||!Number.isSafeInteger(clock()))fail("FINALITY");
  if(checkpoint.timestamp>clock()||clock()-checkpoint.timestamp>pins.maxAgeSeconds)fail("STALE_BLOCK");
  const block=await request("eth_getBlockByHash",[checkpoint.hash,false]);
  if(!same(block?.hash,checkpoint.hash)||hexNum(block?.number)!==numeric(checkpoint.number)||hexNum(block?.timestamp)!==BigInt(checkpoint.timestamp))fail("BLOCK_INTEGRITY");
  for(const [addr,want] of [[pins.core,pins.coreHash],[pins.registry,pins.registryHash],[pins.policy,pins.policyHash]]){
   const code=await request("eth_getCode",[addr,tag(checkpoint.hash)]);
   if(typeof code!=="string"||!/^0x(?:[0-9a-fA-F]{2})+$/.test(code)||!same(await crypto.keccak256(code),want))fail("CODEHASH");
  }
  if(!same(await codec.abiSha256(),pins.abiSha256))fail("ABI_PIN");
  const call=async(contract,signature,args=[])=>{
   const data=codec.encode(signature,args);
   if(typeof data!=="string"||!/^0x[0-9a-fA-F]+$/.test(data))fail("CALL_ENCODING");
   const raw=await request("eth_call",[{to:contract,data},tag(checkpoint.hash)]);
   return codec.decode(signature,raw);
  };
  const registryPaused=await call(pins.registry,"paused()");
  const source=await call(pins.registry,"activeSource()");
  const registryCore=await call(pins.registry,"pieCore()");
  const policyPaused=await call(pins.policy,"paused()");
  const policyCore=await call(pins.policy,"pie()");
  const policyOwner=await call(pins.policy,"owner()");
  if(registryPaused!==false||policyPaused!==false)fail("PAUSED_OR_INVALID_FLAG");
  if(!same(registryCore,pins.core)||!same(policyCore,pins.core)||!same(policyOwner,pins.owner)||
    !same(source?.policy,pins.policy)||!same(source?.runtimeCodehash,pins.policyHash)||!same(source?.policyOwner,pins.owner))fail("UNTRUSTED_POLICY");
  if(hexNum(await request("eth_chainId",[]))!==numeric(pins.chainId))fail("CHAIN_CHANGED");
  return Object.freeze({snapshot:{blockHash:checkpoint.hash,number:String(numeric(checkpoint.number)),timestamp:checkpoint.timestamp},
    async totalXp(wallet){
      if(!address(wallet))fail("WALLET");
      // Each call is pinned to the same finalized hash: no latest fallback.
      const xp=await call(pins.registry,"totalXP(address)",[wallet]);
      const value=numeric(xp);
      if(value>(1n<<64n)-1n)fail("XP_RANGE");
      return value.toString();
    }});
 }
 return Object.freeze({read});
}
export function createTrustedIdentityBoundary({sessions,ledger,clock,policy}){
 port(sessions,["current"]);port(ledger,["bindingSnapshot"]);
 if(typeof clock!=="function"||!policy||typeof policy.domain!=="string"||!numeric(policy.chainId)||!Number.isSafeInteger(policy.maxSessionSeconds))fail("IDENTITY_CONFIG");
 const validateSession=s=>{
  const t=clock();
  if(!Number.isSafeInteger(t)||s?.assurance!=="SIWE_VERIFIED"||typeof s.subject!=="string"||!s.subject||
    !address(s.wallet)||s.domain!==policy.domain||String(s.chainId)!==String(policy.chainId)||
    s?.nonceConsumed!==true||!Number.isSafeInteger(s.verifiedAt)||!Number.isSafeInteger(s.expiresAt)||
    s.verifiedAt>t||t-s.verifiedAt>policy.maxSessionSeconds||s.expiresAt<=t)fail("SIWE_SESSION");
  return s;
 };
 return Object.freeze({
  async session(){
   const s=validateSession(await sessions.current());
   return Object.freeze({authenticated:true,subject:s.subject,wallet:s.wallet,sessionGeneration:s.generation});
  },
  async binding(subject,chainId){
   const s=validateSession(await sessions.current());
   if(subject!==s.subject||String(chainId)!==String(policy.chainId))fail("IDENTITY_SCOPE");
   const b=await ledger.bindingSnapshot(s.subject,chainId);
   if(!same(b?.wallet,s.wallet)||b?.chainId!==String(policy.chainId)||b?.status!=="ACTIVE"||
      !Number.isSafeInteger(b.bindingGeneration)||!Number.isSafeInteger(b?.consent?.generation)||
      b?.consent?.revoked!==false||!Array.isArray(b.consent.scopes)||!b.consent.scopes.includes("pie:xp:read")||
      !Number.isSafeInteger(b.consent.expiresAt)||b.consent.expiresAt<=clock())fail("BINDING_CONSENT");
   return Object.freeze({...b,consent:Object.freeze({...b.consent,scopes:Object.freeze([...b.consent.scopes])})});
  }
 });
}
