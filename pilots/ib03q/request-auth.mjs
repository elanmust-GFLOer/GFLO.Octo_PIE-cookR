// IB-03Q fixed-schema request authentication. Does not replace SIWE verification.
import {createHash} from "node:crypto";
export function canonicalRequest(envelope){
 const {kid,nonce,issuedAt,expiresAt,audience,request}=envelope;
 if(typeof kid!=="string"||!/^[A-Za-z0-9_-]{1,64}$/.test(kid)||
 typeof nonce!=="string"||!/^[0-9a-f]{32}$/.test(nonce)||
 !Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
 audience!=="gflo-issuer-ib03q"||!request||typeof request!=="object"||Array.isArray(request))
 throw Error("BAD_ENVELOPE");
 const keys=["message","signature","subject","sessionId","expectedDomain","expectedUri","expectedChain","issuerKeyId","keyEpoch","sessionSeconds"];
 if(Object.keys(request).sort().join(",")!==keys.sort().join(","))throw Error("REQUEST_SCHEMA");
 return ["GFLO_IB03Q_AUTH_V1",kid,nonce,String(issuedAt),String(expiresAt),audience,
 createHash("sha256").update(JSON.stringify(request),"utf8").digest("hex")].join("\n");
}
