# IB-03U — Canonical Cryptographic Envelope & Independent Verification Vectors
Status: **CRYPTOGRAPHIC PROTOCOL LAB / PRODUCTION BLOCK**.

This is a NEW **proposed** wire-format version, not backwards compatible with IB-03T's JSON-stringify-based canonical preimage or IB-03O's pipe-delimited HMAC message. **Do not** silently accept legacy envelopes, replay tickets, or MACs. The production gateway is unchanged.

## Canonical byte layout
- Admission prefix: ASCII `GFLO:IB03U:ADMISSION:V1` plus one NUL byte.
- Attestation prefix: ASCII `GFLO:IB03U:ATTESTATION:V1` plus one NUL byte.
- Fields follow exactly the respective `ADMISSION_FIELDS` / `ATTESTATION_FIELDS` order in `protocol.mjs`. No field count, JSON or implicit defaults.
- `id`, `nonce`, `domain`, `uri`, `audience`, `scope`, `utf8`: unsigned 4-byte BE byte length followed by **exact** UTF-8 bytes. Invalid UTF-8 replacement characters, unpaired surrogates, CR and unexpected fields must fail.
- `hex16`, `hex20`, `hex32`, `hex65`: fixed-width raw bytes. `0x` prefix is only accepted where explicitly specified (wallet, EOA signature). Lowercase canonical hex only.
- `u64`: unsigned 8-byte BE. `u32`: unsigned 4-byte BE. On JSON input all integers are canonical base-ten **strings** (no leading zeros, sign or exponent).
- Admission signature is **Ed25519 over the entire admission preimage bytes**, no implicit SHA-256 prehash. SHA-256 vectors are for verification/auditing only. Attestation is HMAC-SHA256 over the attestation preimage.
- Admission includes **signed `keyEpoch` and `issuerKeyEpoch`**; attestation binds wallet, chain, subject, challenge, consent/binding generations, URI, domain, scope, times, session and issuer key epoch. Strong schema validation does not itself verify that these values came from an authenticated source.
- JSON is only a transport for **typed fields**; it is not part of signed preimage.

## Evidence
`vectors.json`: two pinned test-only vectors (ASCII and multibyte UTF-8), both with exact preimage lengths, SHA-256 hashes, Ed25519 signatures and HMAC values. The test seed and MAC key are intentionally public and MUST NEVER be used elsewhere. Test EOA signature and address are synthetic bytes; this suite **does not verify SIWE EOA signatures**.
`conformance.test.mjs`: Node cryptography and negative mutation tests.
`independent.py`: independent Python canonical serializer, SHA-256/HMAC plus OpenSSL Ed25519 verification including changed-preimage rejection.

## Blocking boundaries
Not integrated into IB-03T issuer or the IB-03O SQL verification function. Protocol negotiation/downgrade prevention, independent real EIP-191 SIWE verification, EIP-1271 EVM state pinning, operational key custody, cross-language production decoders and distributed revocation remain separate work. NO merge, deployment, Supabase or Lovable write.
