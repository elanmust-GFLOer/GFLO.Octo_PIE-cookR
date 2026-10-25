#!/usr/bin/env bash
set -euo pipefail
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gflo_issuer_os
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gflo_admission_os
sudo install -d -m 0700 -o gflo_issuer_os -g gflo_issuer_os /tmp/gflo-ib03p-key
KEY="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
printf '%s' "$KEY" | sudo tee /tmp/gflo-ib03p-key/secret.hex >/dev/null
sudo chown gflo_issuer_os:gflo_issuer_os /tmp/gflo-ib03p-key/secret.hex
sudo chmod 0400 /tmp/gflo-ib03p-key/secret.hex
echo "IB03P_SECRET_PATH=/tmp/gflo-ib03p-key/secret.hex" >> "$GITHUB_ENV"
echo "IB03P_FIXTURE_KEY_HEX=$KEY" >> "$GITHUB_ENV"
# Ephemeral lab setup knows the key: this is NOT HSM or strong CI-runner compromise isolation.
