#!/usr/bin/env bash
set -euo pipefail
psql -X -v ON_ERROR_STOP=1 -f pilots/ib03d/ledger.sql >/dev/null
psql -X -v ON_ERROR_STOP=1 -f pilots/ib03d/issuance-fence.sql >/dev/null
q(){ psql -X -At -v ON_ERROR_STOP=1 -c "$1" | tail -1; }
eq(){ [[ "$1" == "$2" ]] || { echo "FAIL $3: expected=$2 actual=$1";exit 1; };echo "PASS $3"; }
mkdir -p /tmp/gflo-ib03d3
tmp=$(mktemp -d);trap 'rm -rf "$tmp"' EXIT
q "INSERT INTO ib03d2.bindings VALUES('alice',11155111,'wallet-A','ACTIVE',1);
INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '1 hour',1);
INSERT INTO ib03d2.challenges VALUES('c1','alice','wallet-A',11155111,'example.test',now()+interval '5 minutes',NULL,'digest-A');" >/dev/null
call="SELECT ib03d2.issue_verified_session('c1','alice',11155111,'wallet-A','digest-A'"
for n in $(seq 1 8); do
 (q "$call,'SESSION_1234567890_$n',1,1,600);" >"$tmp/$n") &
done
wait
eq "$(grep -l '^t$' "$tmp/"* | wc -l | tr -d ' ')" 1 "parallel session issue: one winner"
eq "$(q "SELECT count(*) FROM ib03d2.sessions;")" 1 "only one session stored"
eq "$(q "SELECT count(*) FROM ib03d2.challenges WHERE consumed_at IS NOT NULL;")" 1 "nonce consumed once"
eq "$(q "$call,'SESSION_1234567890_REPLAY',1,1,600);")" f "nonce replay denied"
q "INSERT INTO ib03d2.challenges VALUES('c2','alice','wallet-A',11155111,'example.test',now()+interval '5 minutes',NULL,'digest-B');" >/dev/null
eq "$(q "SELECT ib03d2.issue_verified_session('c2','alice',11155111,'wallet-A','WRONG','SESSION_1234567890_BAD',1,1,600);")" f "mismatched digest denied"
eq "$(q "SELECT consumed_at IS NULL FROM ib03d2.challenges WHERE id='c2';")" t "failed session did not consume nonce"
eq "$(q "SELECT ib03d2.issue_verified_session('c2','alice',11155111,'wallet-A','digest-B','SESSION_1234567890_OK',1,1,600);")" t "successful fresh session issuance"
# Same lock order: binding -> consent -> session
sess=$(q "SELECT session_id FROM ib03d2.sessions WHERE session_id LIKE 'SESSION_1234567890_%' LIMIT 1;")
(
 psql -X -At -v ON_ERROR_STOP=1 -c "SET lock_timeout='5s';BEGIN;SELECT ib03d2.authorize_read('$sess','pie:xp:read',1,1);SELECT pg_sleep(1);COMMIT;" >"$tmp/read"
) &
readpid=$!
sleep 0.2
eq "$(q "SELECT ib03d2.revoke_consent('alice',11155111);")" 2 "concurrent revoke serialized"
wait "$readpid"
eq "$(q "SELECT ib03d2.authorize_read('$sess','pie:xp:read',1,1);")" f "old consent denied after commit"
q "INSERT INTO ib03d2.challenges VALUES('c3','alice','wallet-A',11155111,'example.test',now()+interval '5 minutes',NULL,'digest-C');" >/dev/null
eq "$(q "SELECT ib03d2.issue_verified_session('c3','alice',11155111,'wallet-A','digest-C','SESSION_1234567890_LATE',1,1,600);")" f "revoked consent blocks session issue"
eq "$(q "SELECT consumed_at IS NULL FROM ib03d2.challenges WHERE id='c3';")" t "rejected issuance preserves challenge"
eq "$(q "SELECT ib03d2.suspend_binding('alice',11155111);")" 2 "suspension increments binding generation"
eq "$(q "SELECT count(*) FROM ib03d2.sessions WHERE revoked;")" 2 "all sessions invalidated on suspension"
echo IB03D3_ISSUANCE_FENCE_PASS
