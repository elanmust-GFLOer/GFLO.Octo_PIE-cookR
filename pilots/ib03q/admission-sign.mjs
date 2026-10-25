// Admission-only ephemeral private key; no issuer HMAC access.
import fs from "node:fs";
import {sign,randomBytes,createPrivateKey} from "node:crypto";
import {canonicalRequest} from "./request-auth.mjs";
const request=JSON.parse(fs.readFileSync(0,"utf8"));
const now=Math.floor(Date.now()/1000);
const envelope={kid:process.env.IB03Q_SIGNER_KID,nonce:randomBytes(16).toString("hex"),issuedAt:now,expiresAt:now+25,audience:"gflo-issuer-ib03q",request};
const privateKey=createPrivateKey(fs.readFileSync(process.env.IB03Q_SIGNER_KEY_PATH,"utf8"));
const signature=sign(null,Buffer.from(canonicalRequest(envelope)),privateKey).toString("base64url");
process.stdout.write(JSON.stringify({...envelope,signature}));
