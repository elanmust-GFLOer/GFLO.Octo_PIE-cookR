#!/usr/bin/env bash
# Disposable Postgres only. Proves SKIP LOCKED chooses second available outbox.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ "${PGDATABASE:-}" == rt6d4_* && "${RT6D4_DISPOSABLE_DB_ACK:-}" == YES ]] || {
  echo 'Refusing non-disposable database' >&2; exit 2;
}
psql -X -v ON_ERROR_STOP=1 -q -c "SET ROLE gflo_rt_ingest; SELECT gflo_bridge.record_reviewed_event('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000111','00000000-0000-0000-0000-000000000211','00000000-0000-0000-0000-000000000311','r11','0x' || repeat('1',64),'00000000-0000-0000-0000-000000000411','nonce-011');"
psql -X -v ON_ERROR_STOP=1 -q -c "SET ROLE gflo_rt_ingest; SELECT gflo_bridge.record_reviewed_event('00000000-0000-0000-0000-000000000012','00000000-0000-0000-0000-000000000112','00000000-0000-0000-0000-000000000212','00000000-0000-0000-0000-000000000312','r12','0x' || repeat('2',64),'00000000-0000-0000-0000-000000000412','nonce-012');"
lock_log="$(mktemp)"
trap 'rm -f "$lock_log"' EXIT
{
  echo 'BEGIN;'
  echo "SELECT outbox_id FROM gflo_bridge.attestation_outbox WHERE event_id='00000000-0000-0000-0000-000000000011' FOR UPDATE;"
  echo '\echo RT6D4_ROW_LOCK_HELD'
  sleep 4
  echo 'ROLLBACK;'
} | psql -X -v ON_ERROR_STOP=1 -qAt >"$lock_log" 2>&1 &
locker=$!
ready=0
for _ in $(seq 1 35); do
  if grep -q 'RT6D4_ROW_LOCK_HELD' "$lock_log"; then ready=1; break; fi
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then
  wait "$locker" || true
  echo 'Did not observe database row lock in time' >&2; exit 1
fi
start=$(date +%s)
response=$(psql -X -v ON_ERROR_STOP=1 -qAt -c "SET ROLE gflo_rt_worker; SELECT event_id FROM gflo_bridge.lease_next_event(60);")
spent=$(( $(date +%s) - start ))
[[ "$response" == *'00000000-0000-0000-0000-000000000012'* ]] || { echo "SKIP LOCKED selected wrong event: $response" >&2; exit 1; }
[[ "$spent" -lt 4 ]] || { echo 'SKIP LOCKED blocked while row locked' >&2; exit 1; }
wait "$locker"
echo 'RT6D4-09 independent connection SKIP LOCKED PASS'
