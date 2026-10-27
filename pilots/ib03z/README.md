# GFLO IB-03Z — Independent Sepolia RPC & Contract Provenance Gate

**Evidence levels:**
1. Etherscan Sepolia chain 11155111 source/ABI queried read-only, 2026-10-25. Legacy PIECore `0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e` is verified (contract PIECore, solc 0.8.34), includes `getXP(address)`, `getTier(address)`, and user-callable `gainXP(uint256)`. This is NOT canonical V04. GFLOIgnition `0x414DEDcf9264614Fd087BDa58bE27a0B698CcC54` and GFLOToken `0x563b2e3b499818a2f84c472efb3169a2667807fe` are NOT source verified.
2. Two independent external Sepolia HTTP RPCs are queried read-only. Their `eth_chainId`, finalized observations and block hash at the lower finalized height must agree. `eth_getCode` for all three addresses is requested using the same EIP-1898 `{blockHash,requireCanonical:true}`. Exact runtime bytes and keccak256 code hashes must agree; otherwise fail. Different finalized heights are allowed only when a common lower finalized block is retrieved consistently.
3. A successfully compared pair of RPC endpoints is **NOT independent Ethereum consensus, a light client, a finalized checkpoint authenticity proof, or evidence of canonical V04 deployment**. Providers can collude or share upstream infrastructure. No checked live EIP-1271 wallet address is supplied.

**Outputs:** `ib03z-evidence.json` (report only, no credentials). Offline deterministic negative tests are separate from live RPC; live job must FAIL if providers are unavailable, inconsistent, or lack EIP-1898 code reads. Never convert failure to a false PASS.

**Codex independent audit:** a new empty workspace with only the pinned commit, exact CI run IDs, source paths, and no prior chat conclusions; use `CODEX_CLEAN_ROOM.md`. Read-only; report independently, include contrary evidence.

**No** deployment, secret access, live wallet signatures, ABI acceptance from legacy into V04, production migration, merge or Supabase/Lovable writes.
