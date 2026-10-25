// Issuer UID validates independent admission Ed25519 signature and replay before SIWE.
import fs from "node:fs";
import {createHash,verify} from "node:crypto";
import {spawnSync} from "node:child_process";
import {canonicalRequest} from "./request-auth.mjs";
const fail=reason=>process.stdout.write(JSON.stringify({ok:false,reason}));
try{
 const e=JSON.parse(fs.readFileSync(0,"utf8"));
 if(!e||Object.keys(e).sort().join(",")!==
 ["kid","nonce","issuedAt","expiresAt","audience","request","signature"].sort().join(","))throw Error("BAD_FIELDS");
 const t=Math.floor(Date.now()/1000);
 if(e.issuedAt>t+5||e.expiresAt<=t||e.expiresAt-e.issuedAt>30||t-e.issuedAt>30)throw Error("EXPIRED");
 if(typeof e.signature!=="string"||!/^[A-Za-z0-9_-]{86}$/.test(e.signature))throw Error("BAD_SIGNATURE");
 const registry=JSON.parse(fs.readFileSync(process.env.IB03Q_TRUST_PATH,"utf8"));
 const k=registry.keys.find(x=>x.kid===e.kid&&x.active===true);
 if(!k)throw Error("KEY_REVOKED");
 const bytes=Buffer.from(e.signature,"base64url");
 if(bytes.length!==64||!verify(null,Buffer.from(canonicalRequest(e)),k.publicKey,bytes))throw Error("BAD_SIGNATURE");
 const file=process.env.IB03Q_REPLAY_DIR+"/"+createHash("sha256").update(e.kid+"|"+e.nonce).digest("hex");
 const fd=fs.openSync(file,"wx",0o600);fs.closeSync(fd);
 // fail-closed: even unsuccessful requests consume the transport nonce.
 const p=spawnSync(process.execPath,["pilots/ib03p/issuer.mjs"],{
  input:JSON.stringify(e.request),encoding:"utf8",timeout:12000,
  env:{PATH:process.env.PATH,IB03P_SECRET_PATH:process.env.IB03P_SECRET_PATH,
    IB03P_PGPASSFILE:process.env.IB03P_PGPASSFILE}});
 if(p.status!==0)throw Error("ISSUER_FAILED");
 const answer=JSON.parse(p.stdout);
 process.stdout.write(JSON.stringify(answer));
}catch(err){fail(err instanceof Error?err.code==="EEXIST"?"REPLAY":err.message:"GATEWAY_UNAVAILABLE")}
