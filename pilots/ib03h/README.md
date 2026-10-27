# IB-03H — Cryptographically Attested Admission Gate
**LAB candidate only. Production BLOCK.** CI uses random ephemeral 256-bit HMAC key generated at run time. The key is inserted by the isolated test DB owner into restricted ib03h.attestation_keys and never committed. The admission role cannot select key bytes, forge a different tag, or call legacy IB03F/G session issuance.

HMAC-SHA256 covers domain tag, key ID, challenge ID, subject, chain, wallet, exact message digest, session ID, binding/consent generations, TTL and expiry. Database SECURITY DEFINER function verifies tag before calling atomic D3 transaction, thus missing/replayed/modified attestations fail closed. Key revocation and consent revocation are tested.

**Critical limitations:** the test generates a trusted MAC in process, but does not prove the actual cryptographic EIP-191/4361 verifier is the only holder of the key. If verifier or HMAC key is compromised, it can forge tags. SQL bytea/mac equality is not asserted constant time. Service-level key distribution, HSM/KMS, signed attestation provenance, independent verifier deployment, secret rotation and no-bypass RPC/endpoint inventory are not proven. PostgreSQL owner is privileged and can override evidence. This does not implement a real production SIWE gateway, secure session cookies, complete EIP-4361 parser, on-chain ERC-1271, finalized RPC or distributed revocation.

*Scope intentionally excludes Lovable and Supabase writes, live wallets, deployments and merges.* Lab pass != production authorization.
