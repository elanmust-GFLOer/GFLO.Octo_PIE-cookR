# AR01-05J.4 — Dependency reproducibility gate

## Current implementation

- The three GitHub Actions references in `.github/workflows/ar01-v05-signed-evm.yml` are pinned to full commit SHAs.
- `_evm_deps/package.json` declares the isolated EthereumJS, Safe, OpenZeppelin, ethers and solc dependencies.
- CI uses `npm ci --ignore-scripts --no-audit --no-fund` **only if** a committed `_evm_deps/package-lock.json` exists.
- Until then, CI executes a **bootstrap** `npm install`, saves `evidence/package-lock.json`, and records `dependency_mode=BOOTSTRAP_LOCK_PENDING_REVIEW`. A bootstrap green build is **not** a reproducibility PASS.
- The evidence archive includes npm top-level dependency versions, lockfile and its SHA-256, contract/test/workflow hashes, and upstream commit SHAs.

## Mandatory acceptance sequence

1. Inspect the first CI run after the workflow and package manifest commits. Verify job result and artifact creation.
2. Download the generated artifact; review `package-lock.json` for resolved versions, integrity digests, package source and unexpected dependencies. Review `npm-top-level.txt`.
3. Commit the **exact reviewed** lockfile to `_evm_deps/package-lock.json` without rewriting it.
4. Re-run CI; verify `dependency_mode=LOCKED_NPM_CI`, successful `npm ci`, 25/25 signed EVM PASS and artifact hashes.
5. Update evidence pack with commit SHA, job URL, lockfile SHA-256 and the action SHA pins.

## Remaining limits

- Node 22 is specified by major, and `ubuntu-latest` is mutable. For stricter reproducibility, pin a Node patch version and runner image/container digest.
- The fixture remains synthetic signed EVM, not mainnet validation or external audit.
- The seed-based model currently covers pending revocation/recovery; finalized grant sequences, source collusion, and additional recipients require expanded tests.

**Status: bootstrap pending CI verification; reproducibility gate OPEN.**
