// IB-03S: gateway replacement; shared PostgreSQL replay rather than local files.
import fs from "node:fs";
import {spawnSync} from "node:child_process";
import {verify} from "node:crypto";
import {canonicalRequest} from "../ib03q/request-auth.mjs";
const q=x=>"'"+String(x).replaceAll("'","''")+"'";
const output=(ok,reason)=>process.stdout.write(JSON.stringify({ok,reason}));
function db(statement) {
 const p=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",statement],{
 encoding:"utf8",timeout:8000,env:{PGHOST:"127.0.0.1",PGPORT:process.env.IB03S_PGPORT||"5432",
 PGDATABASE:"gflo_test",PGUSER:"gflo_issuer_replay_lab",PGPASSWORD:process.env.IB03S_PGPASSWORD||""}});
 if(p.status!==0)throw Error("STORE_UNAVAILABLE");
 return p.stdout.trim();
}
try {
 const e=JSON.parse(fs.readFileSync(0,"utf8")),now=Math.floor(Date.now()/1000);
 if(Object.keys(e).sort().join(",")!==["kid","nonce","issuedAt","expiresAt","audience","request","signature"].sort().join(","))
 throw Error("BAD_FIELDS");
 if(!Number.isSafeInteger(e.issuedAt)||!Number.isSafeInteger(e.expiresAt)||
 e.issuedAt>now+5||e.expiresAt<=now||e.expiresAt-e.issuedAt>30||now-e.issuedAt>30)throw Error("EXPIRED");
 const encoded=canonicalRequest(e);
 const keyrow=db("SELECT epoch,encode(convert_to(public_key,'UTF8'),'hex') FROM ib03r.active_key("+q(e.kid)+")");
 if(!keyrow)throw Error("KEY_REVOKED");
 const [epoch,keyHex]=keyrow.split("|");
 const sig=Buffer.from(e.signature||"","base64url");
 if(sig.length!==64||!verify(null,Buffer.from(encoded),Buffer.from(keyHex,"hex").toString("utf8"),sig))
 throw Error("BAD_SIGNATURE");
 // DB locks key-state when claiming; no local replay fallback.
 const claimed=db("SELECT ib03r.claim_authenticated_request("+q(e.kid)+","+Number(epoch)+","+q(e.nonce)+","+e.expiresAt+")");
 if(claimed!=="t")throw Error("REPLAY_OR_ROTATED");
 const p=spawnSync(process.execPath,["pilots/ib03p/issuer.mjs"],{input:JSON.stringify(e.request),
 encoding:"utf8",timeout:10000,env:{PATH:process.env.PATH,
 IB03P_SECRET_PATH:process.env.IB03P_SECRET_PATH,IB03P_PGPASSFILE:process.env.IB03P_PGPASSFILE}});
 if(p.status!==0)throw Error("ISSUER_FAILED");
 process.stdout.write(JSON.stringify(JSON.parse(p.stdout)));
} catch(e){output(false,e?.message||"FAILED_CLOSED")}
