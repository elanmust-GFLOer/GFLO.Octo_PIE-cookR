IB-03X — Pinned-block ERC-1271 boundary. LAB ONLY / PRODUCTION BLOCK.

The new injected-RPC verifier requires Sepolia chainId, a blockHash with EIP-1898 requireCanonical=true for both eth_getCode and eth_call, bytecode runtime keccak256 codehash, a matching block and provider-reported finalized height. Invalid magic, provider outage, chain drift, altered code and block mismatch deny.

Security caveats: RPC tests use an untrusted MOCK provider; forged provider responses can bypass all claims. Re-running the real Solidity ERC1271 IB03W local EVM test is separate evidence, NOT live Sepolia finality or independent external consensus. A mocked eth_call can yield valid magic for an invalid message digest; the caller must derive digest from exact verified SIWE message. No EIP1271 owner rotation or independent Codex audit completed. Canonical V04 still lacks verified live deploy proof. No production operations.
