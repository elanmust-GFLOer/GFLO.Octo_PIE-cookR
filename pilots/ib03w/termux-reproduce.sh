#!/usr/bin/env bash
# MANUAL Termux reproduction; does not operate a live wallet or deploy to a chain.
set -euo pipefail
REPO="https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR.git"
HARNESS="1ea68bc5b796901e5f652b6580c0584236ba2c5f"
BRANCH_COMMIT="__PIN_THIS_TO_IB03W_FINAL_HEAD_AFTER_CI__"
# Requires git, Node >=22, Python >=3, sha256sum, npm, and git network access.
# Never run in an existing project directory; prepare two temporary dirs.
mkdir -p "$HOME/gflo-ib03w-repro"
cd "$HOME/gflo-ib03w-repro"
git clone "$REPO" cookr
git clone "$REPO" harness
git -C cookr checkout --detach "$BRANCH_COMMIT"
git -C harness checkout --detach "$HARNESS"
mkdir -p harness/pilots/ib03d harness/pilots/ib03w
cp cookr/pilots/ib03d/siwe-core.mjs harness/pilots/ib03d/
cp cookr/pilots/ib03w/local-erc1271.test.mjs harness/pilots/ib03w/
cd harness
test "$(git hash-object package-lock.json)" = "61e8a5ede9ad9031fdc58424cefb0fc442e3d9b3"
npm ci --ignore-scripts --no-audit --no-fund
node pilots/ib03w/local-erc1271.test.mjs | tee ../ib03w-local-log.txt
cd ..
git -C cookr rev-parse HEAD | tee ib03w-source-commit.txt
sha256sum ib03w-local-log.txt cookr/pilots/ib03w/local-erc1271.test.mjs > ib03w-evidence-sha256.txt
echo "Evidence kept only on your device; no secrets, deployment or signing with user wallets."
