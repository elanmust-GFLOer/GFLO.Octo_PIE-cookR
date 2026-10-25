# GFLO IB-03W — Real EOA SIWE & EIP-1271 Compatibility Evidence Gate

**Candidate only — production BLOCK.** This package performs actual Ethereum secp256k1/EIP-191 wallet-message signatures using test-only EOA keys, then executes a compiled Solidity ERC-1271 isValidSignature(bytes32,bytes) verifier in an **isolated EthereumJS EVM** configured for Sepolia chainId 11155111. No RPC to a live Sepolia contract and no real wallet operations are performed. The test exercises the existing IB-03D.1 EIP-4361 parser. Synthetic ERC-1271 success metadata (`finalized=true`, made-up block hash) is **NOT a finality or canonical chain proof**; its cryptographic return magic is from actual Solidity runtime executed in EVM. Distinguish crypto validation from finalized block attestation.

## On-chain Etherscan read-only evidence
- Sepolia PIECore legacy verified at [0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e](https://sepolia.etherscan.io/address/0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e#code). Verified ABI has getXP(address), getTier(address), gainXP(uint256). NOT canonical V04 and NOT an ERC-1271 verifier.
- GFLOIgnition [0x414DEDcf9264614Fd087BDa58bE27a0B698CcC54](https://sepolia.etherscan.io/address/0x414DEDcf9264614Fd087BDa58bE27a0B698CcC54#code) and GFLOToken [0x563b2e3b499818a2f84c472efb3169a2667807fe](https://sepolia.etherscan.io/address/0x563b2e3b499818a2f84c472efb3169a2667807fe#code): source/ABI not verified in latest checked Etherscan result.
- **No verified deployed canonical XP V04 / live ERC-1271 smart wallet is proven here.** Testing a local Solidity contract cannot serve as an Etherscan contract deployment proof.

## Evidence tracks
1. GitHub Actions: the pinned source, dependency lock, compiled contract, EOA signature recovery and real EVM 1271 isValidSignature outcome; negative cases.
2. Manual Termux reproduction: `termux-reproduce.sh` is a template whose placeholder commit must be pinned to the final **passing** CI commit prior to execution. It does not run automatically or require any user's private key.
3. Codex independent audit: give Codex the passing commit SHA and immutable workflow run, request fresh reproduction and adversarial review; no merge or deployment without explicit instruction.

## Security limitations
No real onchain contract read, no actual Ethereum finality, no EIP-6492 counterfactual wallets, no full EIP-4361 ABNF conformance proof, no real smart-wallet owner rotation, no KMS/HSM, no EIP-1271 isValidSignature state change/race across blocks, no live chain RPC anchoring or production authorization. EIP-191 signMessage includes Ethereum signed message prefix; Ed25519 admission is a different trust domain. Test keys are publicly embedded and forbidden in real deployments.
