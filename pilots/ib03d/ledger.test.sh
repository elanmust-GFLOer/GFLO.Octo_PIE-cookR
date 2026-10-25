#!/usr/bin/env bash
set -euo pipefail
export PGOPTIONS='-c search_path=public'
psql -v ON_ERROR_STOP=1 -f pilots/ib03d/ledger.sql >/dev/null
q(){ psql -X -At -v ON_ERROR_STOP=1 -c "$1" | tail -1; }
eq(){ test "$1" = "$2" || { echo "FAIL $3: expected '$2', got '$1'"; exit 1; }; echo "PASS $3"; }
q "INSERT INTO ib03d2.challenges VALUES('c1','alice','wallet-A',11155111,'example.test',now()+interval '10 minutes',NULL,'digest-A');" >/dev/null
# Atomic concurrent update of the SAME unique nonce; exactly one can succeed.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
for n in 1 2 3 4 5 6 7 8; do
 (q "SELECT ib03d2.consume_challenge('c1','alice','wallet-A','digest-A');" >"$tmp/$n") &
done
wait
success=$(grep -l '^t$' "$tmp/"* | wc -l | tr -d ' ')
eq "$success" '1' 'nonce race 8 contenders exactly one winner'
eq "$(q "SELECT ib03d2.consume_challenge('c1','alice','wallet-A','digest-A');")" f 'nonce replay denied'
q "INSERT INTO ib03d2.challenges VALUES('expired','alice','wallet-A',11155111,'example.test',now()-interval '1 minute',NULL,'digest-B');" >/dev/null
eq "$(q "SELECT ib03d2.consume_challenge('expired','alice','wallet-A','digest-B');")" f 'expired nonce denied'
q "INSERT INTO ib03d2.bindings VALUES('alice',11155111,'wallet-A','ACTIVE',1);
INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '1 hour',1);
INSERT INTO ib03d2.sessions VALUES('session-A','alice',11155111,'wallet-A',now()+interval '1 hour',false,1);" >/dev/null
eq "$(q "SELECT ib03d2.authorize_read('session-A','pie:xp:read',1,1);")" t 'active scope read authorized'
eq "$(q "SELECT ib03d2.authorize_read('session-A','pie:xp:write',1,1);")" f 'XP write scope denied'
eq "$(q "SELECT ib03d2.authorize_read('session-A','pie:xp:read',2,1);")" f 'stale binding generation denied'
eq "$(q "SELECT ib03d2.authorize_read('session-A','pie:xp:read',1,2);")" f 'stale consent generation denied'
# Hold the consent row lock during successful authorization; revoke must wait.
(
 psql -X -At -v ON_ERROR_STOP=1 -c "BEGIN; SELECT ib03d2.authorize_read('session-A','pie:xp:read',1,1); SELECT pg_sleep(2); COMMIT;" >"$tmp/reader"
) &
pid=$!
sleep 0.3
eq "$(q "SELECT ib03d2.revoke_consent('alice',11155111);")" '2' 'revocation increments generation'
wait "$pid"
eq "$(q "SELECT ib03d2.authorize_read('session-A','pie:xp:read',1,1);")" f 'old consent denied after revoke'
eq "$(q "SELECT ib03d2.authorize_read('session-A','pie:xp:read',1,2);")" f 'revoked new consent denied'
eq "$(q "SELECT ib03d2.suspend_binding('alice',11155111);")" '2' 'binding suspension increments generation'
eq "$(q "SELECT revoked FROM ib03d2.sessions WHERE session_id='session-A';")" t 'session revoked on suspension'
eq "$(q "SELECT status FROM ib03d2.bindings WHERE subject_id='alice';")" SUSPENDED 'binding remains suspended'
echo 'IB03D2_SQL_GATE_PASS'
