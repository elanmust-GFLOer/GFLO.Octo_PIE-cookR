// IB-03T gateway. Signed key epoch must equal canonical PostgreSQL epoch.
// Separate issuer process invokes independent SIWE signature + DB context verifier.
import fs from "node:fs";
import {spawnSync} from "node:child_process";
import {verify} from "node:crypto";
import {canonicalEpochRequest} from "./epoch-auth.mjs";
const q=s=>"'"+String(s).replaceAll("'","''")+"'";
const refuse=reason=>process.stdout.write(JSON.stringify({ok:false,reason}));
function db(query){
 const p=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",query],{
 encoding:"utf8",timeout:8000,env:{
 PGHOST:"127.0.0.1",PGPORT:process.env.IB03T_DBPORT||"5432",PGDATABASE:"gflo_test",
 PGUSER:"gflo_issuer_replay_lab",PGPASSWORD:process.env.IB03T_REPLAY_PASSWORD||""}});
 if(p.status!==0)throw Error("DB_UNAVAILABLE");
 return p.stdout.trim();
}
try {
 const e=JSON.parse(fs.readFileSync(0,"utf8")),now=Math.floor(Date.now()/1000);
 if(Object.keys(e).sort().join(",")!==["kid","nonce","issuedAt","expiresAt","audience","request","signature","keyEpoch"].sort().join(","))
 throw Error("BAD_FIELDS");
 if(!Number.isSafeInteger(e.issuedAt)||!Number.isSafeInteger(e.expiresAt)||
 e.issuedAt>now+5||e.expiresAt<=now||e.expiresAt-e.issuedAt>30||now-e.issuedAt>30)
 throw Error("EXPIRED");
 const bytes=Buffer.from(e.signature||"","base64url");
 if(bytes.length!==64)throw Error("BAD_SIGNATURE");
 const signed=canonicalEpochRequest(e);
 const row=db("SELECT epoch,encode(convert_to(public_key,'UTF8'),'hex') FROM ib03r.active_key("+q(e.kid)+")");
 if(!row)throw Error("KEY_REVOKED");
 const [epoch,pubHex]=row.split("|");
 if(Number(epoch)!==e.keyEpoch)throw Error("EPOCH_MISMATCH");
 if(!verify(null,Buffer.from(signed),Buffer.from(pubHex,"hex").toString("utf8"),bytes))throw Error("BAD_SIGNATURE");
 const claimed=db("SELECT ib03r.claim_authenticated_request("+q(e.kid)+","+e.keyEpoch+","+q(e.nonce)+","+e.expiresAt+")");
 if(claimed!=="t")throw Error("REPLAY_OR_ROTATED");
 const p=spawnSync(process.execPath,["pilots/ib03p/issuer.mjs"],{
 input:JSON.stringify(e.request),encoding:"utf8",timeout:12000,env:{
 PATH:process.env.PATH,IB03P_SECRET_PATH:process.env.IB03P_SECRET_PATH,
 IB03P_PGPASSFILE:process.env.IB03P_PGPASSFILE}});
 if(p.status!==0)throw Error("ISSUER_UNAVAILABLE");
 process.stdout.write(JSON.stringify(JSON.parse(p.stdout)));
}catch(err){refuse(err instanceof Error?err.message:"FAIL_CLOSED")}
