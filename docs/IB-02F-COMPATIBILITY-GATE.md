# IB-02F — Compiler ABI / FULL Storage Layout Compatibility Gate
Security classification: **laboratory scope, not production release**.
- Source commit for original V04: `8e46c99e575b508b7cb98d74972d96f5de44e5dc`, blob `bed6450d08b572181b718cb5cfa19d9c65e90ee5`.
- Candidate: PR #19; pin HEAD and read live CI logs before interpreting results.
- Gate independently compiles the baseline and candidate with `solc 0.8.34`, Cancun, optimizer runs 200.
- Existing ABI function inputs/outputs and event indexed parameters must not change; new `expirePending`, `GrantExpired`, enum `EXPIRED=4` are additions requiring downstream consumers to recognize them.
- Compare every root state variable including nested mapping value and every Grant struct storage member (slot/offset/width/type), not just root slots.
- Pinned consumers compile: `TrustedXPSourceRegistryV02`, `EffectiveTierGateV01`, `GFLOIgnitionV01`, `PIECoreIgnitionV01`; their canonical XP interfaces are checked.
- Check is **not** a deployed proxy storage migration approval. Not all app ABI decoders, event indexers or EXPIRED state machines are inventoried. No deployment codehash matching or on-chain addresses for V04 exist.
- Source signature compatibility does not prove caller's governance, RPC finality, correct chain, user's SIWE consent, or issuer factual-work.
- Release status: **BLOCK** regardless of this source-compatible gate's success.
