# GFLO IB-03V — Canonical Decoder / Downgrade Resistance / Migration Gate
Status: **STRUCTURAL LAB ONLY / PRODUCTION BLOCK**.

The decoder is a strict inverse of the **existing** IB-03U exact binary schemas. Each field is parsed by fixed order/width, with u32 length for UTF-8 fields, fatal UTF-8 decoding, input size limits, exact original-byte re-encoding, and trailing-byte rejection. It does not accept JSON or IB-03T/IB-03Q legacy frames.

**No implicit migration:** migrationDecision accepts only `minimumVersion=IB03U_V1`, exact `gflo-ib03u-*` key scope and matching admission/attestation domain tags, and returns `STRUCTURAL_ONLY_NOT_AUTHENTICATED`. Old sessions/receipts remain untrusted and cannot be silently upgraded or relabeled. To authenticate, callers must separately verify the exact decoded Ed25519 signature/HMAC and all SIWE/DB session fences.

Known security boundaries: IB03U test EOA address and signature are synthetic; real Ethereum SIWE uses EIP-191 or chain-pinned EIP-1271 and cannot be certified by an Ed25519 admission-vector PASS. This parser is not integrated into the live IB-03T gateway or IB-03O database; no actual old/new interoperability has been proven. The prior decoder still has schema-dependent maximum widths; no generic wire compatibility is claimed.

**Etherscan read-only preflight (Sepolia, chain 11155111):**
- `0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e` verified PIECore source/ABI with `getXP(address)` and `getTier(address)` legacy getters; `gainXP(uint256)` is user-callable after path selection. This is NOT proof of canonical V04 and should never be trusted as its source.
- `0x414DEDcf9264614Fd087BDa58bE27a0B698CcC54` GFLOIgnition and `0x563b2e3b499818a2f84c472efb3169a2667807fe` GFLOToken are not source/ABI verified by Etherscan V2; verification and bytecode/ABI pinning required.
- No verified deployed IB-03U smart contract was found from the supplied list. Ed25519 admission signatures and HMAC attestations are **off-chain**, not natively verified by the legacy PIECore ABI.

No remote merge, deployment, Supabase/Lovable writes or production key operations.
