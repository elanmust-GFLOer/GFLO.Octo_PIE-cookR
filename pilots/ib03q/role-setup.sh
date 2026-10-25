#!/usr/bin/env bash
set -euo pipefail
sudo install -d -m 0700 -o gflo_admission_os -g gflo_admission_os /tmp/gflo-ib03q-admission
sudo install -d -m 0700 -o gflo_issuer_os -g gflo_issuer_os /tmp/gflo-ib03q-replays
echo "IB03Q_ADMISSION_DIR=/tmp/gflo-ib03q-admission" >> "$GITHUB_ENV"
echo "IB03Q_REPLAY_DIR=/tmp/gflo-ib03q-replays" >> "$GITHUB_ENV"
echo "IB03Q_TRUST_PATH=/tmp/gflo-ib03p-key/trusted-admission.json" >> "$GITHUB_ENV"
