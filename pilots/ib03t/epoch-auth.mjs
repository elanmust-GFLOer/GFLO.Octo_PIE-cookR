// IB-03T canonical, versioned Ed25519 signed envelope with explicit key epoch.
import {createHash} from "node:crypto";
import {canonicalRequest} from "../ib03q/request-auth.mjs";
export function canonicalEpochRequest(e){
 if(!e||!Number.isSafeInteger(e.keyEpoch)||e.keyEpoch<1)throw Error("INVALID_KEY_EPOCH");
 // Validate base IB03Q message schema before binding explicit epoch.
 return ["GFLO_IB03T_EPOCH_V1",String(e.keyEpoch),canonicalRequest(e)].join("\n");
}
export function signableDigest(e){return createHash("sha256").update(canonicalEpochRequest(e),"utf8").digest("hex")}
