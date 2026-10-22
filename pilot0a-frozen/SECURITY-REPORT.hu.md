# GFLO ID–Entity Integration Pilot 0A — független security & compatibility gate

## A. Verdict és audit anchorok

| Vizsgált határ | Verdict |
|---|---|
| Eldobható, szintetikus ID–Entity proof | PASS a dokumentált fixture-scope-ra: 59/59 lokális teszt |
| Teljes R6A closure | CONDITIONAL: az eredeti 1 másodperces autorizációs követelmény nem teljesül |
| Legacy PIE canonical XP/Tier forrásként | BLOCKED — LEGACY_UNTRUSTED_XP |
| Valós OctoPass × wallet × PIE × OctoGFLO integráció | BLOCKED |
| Production vagy gazdasági jogosultság | BLOCKED; engedély nem keletkezett |

Ezek külön döntések. A green teszt nem zárja le a forrás-oracle által bizonyított
hibát, és a synthetic ALLOW nem production-engedély.

| Forrás | Rögzített anchor |
|---|---|
| cookR R6A head | `12e2df4c32ef51d08c799ec63a565c90221e8bcd` |
| cookR tree | `c2ef9cf327b3b4cd1fb489347758cb79d6f995aa` |
| PR #15 | DRAFT / OPEN / UNMERGED; read-only ellenőrizve |
| R6A CI checkout | `60e72e3f294d0a987c7dba273bd3dcbd60af579f`; tree a head-del azonos |
| PIE main head | `a29ef20f938940aa89c66cbf6f685b48fa667d4c` |
| PIE main tree | `83e46aa4fd83513c7a2de8f032d7ffa4679156ef` |
| PIE v0.2 candidate | `a4e11cb467c2eae6f6baf2419aaa38aa653fdf16` |
| Candidate tree | `12c65220eb4abab2bf6b4c4e1fe9c72971c7fd4f` |
| OctoGFLO project | `1bd6a65f-35c7-4257-826e-e49f2e0d7521` |
| OctoGFLO commit | `157b15c0315644a16d22df17b9453bfc1c5b8deb`; latest is ezzel egyezett |
| Sepolia contract | `11155111` / `0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e` |

Az Etherscan live ABI- és verified-source lekérdezése sikeres. Proxy flag: 0;
compiler: `v0.8.34+commit.80d5c536`; optimizer: kikapcsolva. A verified Solidity
bájtról bájtra azonos a main `contracts/PIECore.sol` fájljával. A deployed ABI
azonos a `compiled3/contracts_PIECore_sol_PIECore.abi` tartalmával.

A 16 letöltött PIE-fájl Git blob SHA-ját és SHA-256-ját helyben ellenőriztem.
Az OctoGFLO fájlokat a megadott commit refen olvastam; a publikált projektet
nem módosítottam. A részletes evidence az `evidence/anchors.json` fájlban van.

Nem történt friss `eth_getCode`-alapú runtime hash-ellenőrzés vagy független
Solidity újrafordítás. Az archivált runtime hash
`0x08ec177b4916a018cb99ad3d5acf177f3bffa43c49c247767ce315b71f6b4481`
a repository **történeti** bizonyítéka a 11956132-es blokkon, nem új megfigyelés.
Az ABI/source egyezéshez az Etherscan verifikációját használjuk; nem állítunk
új, saját bytecode-build attestationt.

## B. Architektúra és interface-mapping

Verified offline JWT principal → friss user observation → független session
authority → szerveroldali profil-ownership → explicit policy → primary-lock →
wallet/chain/contract/protocol tuple → mock scoped consent + epoch/generation →
source classification/digest → audit approval → végső session/policy/fence →
bounded audit commit → szinkron, saját profilú fixture-adatkiadás.

A két principal UUID különbözik a két profile UUID-tól. A mock wallet-címek
nem principalok, és nem unique-human bizonyítékok. A protokollrekordok frozen
szintetikus adatok; a consent-, replay- és audit-bookkeeping külön helyi állapot.
A binding-kérés nem hajt végre domain-módosítást: saját profilra QUARANTINE,
idegen profilra DENY. A visszatérő Decision nem használható későbbi adatolvasásra.

Az OctoGFLO `src/domain/octopass-adapters.ts:1` jövőbeli típusokat tartalmaz,
implementációt nem. A `src/domain/fixtures.ts:1` DEMO-paramétereket deklarál.
Az alkalmazás `canonicalXp()` függvénye is DEMO-szimulációs fogalom, nem a
Sepolia legacy ledger elfogadása. A típusonkénti mapping a `DATA-CONTRACT.md`-ben.

## C. Biztonsági és kompatibilitási findingek

### ID0A-01 — HIGH: permissionless önosztott XP a legacy PIECore-ban

Forrás: `gflo-pie@a29ef20.../contracts/PIECore.sol:59`, illetve a helyi
`evidence/sources/etherscan/verified-PIECore.sol:59`. A baseline reproducer:
`test/PIECore-baseline.test.js:130` és `:135–139`.

Támadási trace: friss EVM account → `choosePath(1)` → `gainXP(1000000)`.
A függvény egyetlen feltétele a nem-None path; nincs attestor-, admin- vagy
contribution-ellenőrzés. Az összeg a hívó saját XP-jéhez adódik, a uint256
overflow határáig. Más felhasználó XP-jének közvetlen módosítása ebből nem
következik, és token-/burn-feltételeket sem bizonyítunk megkerülhetőnek.

Ha downstream canonical XP-ként vagy privilégiumként kezeli, a hiba kritikus
trust-boundary sérüléssé válhat. Jelen pilot ezt a forrást kizárólag
LEGACY_UNTRUSTED_XP-ként kezeli; nincs migration vagy entitlement.

Kontroll: `test_own_legacy_read_never_promotes_arbitrary_xp`,
`test_legacy_cannot_be_relabelled_demo`, `test_xp_tier_and_token_state_are_unchanged`.
A baseline JavaScript EVM-tesztet itt **nem futtattam**: solc/Hardhat/EthereumJS
nem áll rendelkezésre. A sérülékeny végrehajtási út forrásból és ABI-ból bizonyított;
a helyi source-oracle ezt ellenőrzi. Semmilyen chain-írás nem történt.

### ID0A-02 — MEDIUM: forrás- és artifact-azonosság nem következik a PIECore névből

Forrás: main `PIECore.sol:107` csak `onlyAuthorized addXP`-t tartalmaz; más,
263 soros implementáció, a deployed 100 soros contract nem ez. A
`deploy_piecore.js:13–14` a gyökérszintű `.abi/.bin` fájlokra mutat, miközben
ez az ABI, valamint a compiled/compiled2 ABI eltér a deployed ABI-tól.
Példa: a régi ABI-ban nincs getXP/getTier/addXP/owner; a deployed ABI-ban van.
A compiled3 ABI egyezik; ez önmagában nem bizonyítja a `.bin` deploy-azonosságát.

Kockázat: név/path alapján téves implementációhoz vagy dekóderhez kötött adapter,
hibás canonical-data állítás. Elvárt javítás: chain/address/runtime-codehash/
ABI-hash/source-commit/compiler/review-scope közös allowlist-manifestje; mismatch
esetén BLOCKED. Nincs selector- vagy ABI-fallback a pilotban.

Kontroll: `test_root_copy_is_not_deployed_implementation`,
`test_deployment_script_points_at_a_different_abi`,
`test_verified_abi_exactly_matches_compiled_artifact`.

### ID0A-03 — MEDIUM / OPEN: az R6A alapértelmezése 2 s, nem az eredeti 1 s

Forrás: cookR `b23r6a/gateway.py:25`, `workers.py:38`, README:28–37;
HTTP abszolút kapcsolatlimit: `http_server.py:49–62`.

A végső helyi diagnosztika **1.857 s után ALLOW** döntést kapott a változatlan
R6A-tól. Az eredeti 1 másodperces követelmény státusza ezért **FAIL/OPEN**.
A teszt PASS-ja ezt a megfigyelést reprodukálja, nem a határidő-követelményt zárja.
Az első, 0.16 s adapterlépcsős diagnosztika 2.003 s-nál QUARANTINE-t kapott:
a 2 s budget valóban elutasított. A kontrollált újramérés 0.10 s lépcsőt
használ; az ALLOW és az elapsed > 1 s assertion nem változott.

A jelen implementáció szerinti 2 s autorizációs budget különbözik a legfeljebb
200 ms worker cleanup grace-től, a HTTP 2 s inactivity és 3 s absolute limittől.
A process-kill nem tud már commitolt külső side effectet visszacsinálni;
az adapterek ezért kizárólag read-onlyk, domain credential nélküliek.

Feloldás: külön jóváhagyott határidő-szerződés és regresszió szükséges. Ha 1 s
marad, arra kell fail-closed működést és bounded cancellationt bizonyítani.
A pilot megőrzi a 2 s kódot és mind a 86 tesztet; az eltérést nem legitimálja.

### ID0A-04 — HIGH / BLOCKED: nincs elfogadott canonical PIE deployment

Forrás: candidate `contracts/PIECoreV02.sol:17–39`,
`docs/VERIFIED-CONTRIBUTION-SECURITY-GATE-V01.md:3`;
`EffectiveTierGateV01.sol:28–37`.

A v0.2 source candidate 25 Genesis XP-t és Tier 0-t ad, nincs gainXP/addXP
entrypoint; cél-path nem earned Tier. A feature-ágon PR #11 scoped hardening
beolvadt, de ez nem teljes protokoll-/deployment-engedély. A registry/policy,
valós proof-source, consumer és review/deployment kapcsolat együtt nem igazolt.
Sem a legacy, sem az eltérő root Core nem acceptable canonical forrás ebben a
pilotban. A candidate csak pinned összehasonlítási forrás, nem aktivált authority.

A `harness.py:101–106` minden REVIEWED_PROTOCOL_DATA igényt karanténba tesz,
mivel nincs jóváhagyott manifest. Historical Tier önmagában nem entitlement.

### ID0A-05 — MEDIUM / BLOCKED: CanonicalPieReader nem tudja kifejezni a hiányzó authority-t

Forrás: OctoGFLO `src/domain/octopass-adapters.ts:36–40` kötelező
`canonicalXp:number` mezőt ír elő. A mock és legacy rekordokhoz ilyen hiteles
szám nincs. `null → 0` konverzió vagy legacy XP betöltése implicit workaround lenne.

Szükséges következő szerződés: discriminated union BLOCKED / DEMO / LEGACY /
REVIEWED ágakkal, canonical érték csak megfelelő forrásigazolással. Jelenleg
az adapter típus-only, nem élő exploit. Az alkalmazást változatlanul hagytuk.

## D. Tényleges tesztledger és elfogadási mátrix

Végső parancs: `python3 run_verified.py`. Eredmény: **59/59**, 36.598 s;
47 synthetic behavior + 12 source/compatibility/diagnostic eset, nulla skip
vagy expected failure. Az ismert-hiba diagnosztikák nem sikeres mitigációk.
Minden tesztnév és státusz: `evidence/test-ledger.json`; nyers log:
`evidence/test-run.log`. Runtime: Python 3.12.14, PyJWT 2.13.0, Linux.

| Acceptance | Eredmény | Érdemi bizonyíték / korlát |
|---|---|---|
| A nem olvashatja/kötheti B profilját | PASS a fixture-ben | Külön A/B principal/profile/session/wallet; own binding is QUARANTINE |
| Wrong chain/address/contract/protocol | PASS | Egyetlen request-mező változik; pontos mismatch reason |
| Missing/expired/replayed consent | PASS | Mock-MAC, store, scope/version, exclusive expiry, nonce/ticket, replay |
| REVOKED/UNKNOWN nem ad adatot | PASS | Initial és audit alatti final session-váltás is tesztelt |
| Legacy XP nem canonical | PASS a tiltó kontrollra | Milliós fixture-XP mellett canonical_xp=null, nincs entitlement |
| XP/Tier/token változatlan | PASS a fixture-ben | Frozen rekord és teljes synthetic token-state snapshot |
| Allowed read source + trace | PASS | Source classification/digest és azonos audit trace; pseudonym actor |
| Dependency-unavailable nem ALLOW | PASS | JWT/user/session/policy/emitter külön hiánya, timeout, audit-outage |
| R5/R6A gate-ek megőrzése | PASS source preservation | Teljes tracked diff üres; eredeti 86-name manifest és R5 blob egyezik |
| Valós wallet/SIWE/consent-signature | BLOCKED / NOT TESTED | Mock nem válik VERIFIED_WALLET_CONTROL-lá |
| Production Auth/revocation/distributed fence | BLOCKED / NOT TESTED | Független authority csak szimulátor |
| Canonical protokolladat | BLOCKED | Nincs approved deployment/source manifest |
| Eredeti 1 s R6A határ | FAIL / OPEN | Reprodukált ALLOW 1.857 s-nál |

Konkurens tesztek: azonos consentből pontosan egy adatkiadás; revocation-first
DENY; read-first esetén revoke a delivery végéig blokkolt; final policy revoke
DENY; adatkiadás csak végső fence és audit után. Restart-/replica-garancia nincs.

Az eredeti R6A core **42/42** és manifest **3/3** ebben a feladatban újrafutott.
A 13 HTTP teszt és 28 PostgreSQL teszt helyben **NOT EXECUTED**: socketcreation
PermissionError, illetve nincs PostgreSQL kliens/server/psycopg. Nem lett skip-pel
zöldre állítva. A teljes korábbi **86/86 + SQL** eredményt csak archivált CI-ként
ellenőriztem: run **39835995049**, job **120024362835**, exact merge/tree a fenti
anchoron. A log összes named MANIFEST PASS-ját külön visszaolvastam.

Nincs új CI-run, EVM-suite vagy publikált artifact ebben a read-only pilotban.
A helyi SHA-256 manifest nem helyettesít független CI-attestationt vagy auditot.

## E. Dependency és readiness mátrix

| Komponens | Igazolt állapot | Readiness |
|---|---|---|
| Offline identity/ownership fixture | Lokálisan tesztelt | PASS a 0A scope-ra |
| R6A worker timeout/cancellation/final fence | Újrafutott meglévő core és saját final-race tesztek | CONDITIONAL: 1 s specifikáció OPEN; primary process-local |
| R5 operacionalis role quarantine | SQL blob változatlan, archived PostgreSQL gate PASS | Megőrzött; friss PG replay nem történt |
| Supabase Auth | Nincs production adapter/liveness-contract | BLOCKED |
| Wallet-control és signed consent | Mock-only, valós aláírás nincs | BLOCKED |
| Durable audit/consent/idempotency | Bounded memory-only állapot | BLOCKED productionre |
| PIE legacy source/ABI | Live read-only Etherscan ellenőrzés | LEGACY_UNTRUSTED_XP; canonical BLOCKED |
| PIE reviewed source candidate | Exact commit és scoped source review | Deployment/canonical gate BLOCKED |
| OctoGFLO | Rögzített DEMO forrás, future types, változatlan app | Kompatibilitási terv; live adapter BLOCKED |
| OctoPartnR | A megtekintett engine-ben advisory DEMO triage | Nem authorization vagy XP authority |
| gfloDEVaccount | Principal/owner/effective grants továbbra sincsenek bizonyítva | NOT VERIFIED; production write BLOCKED |
| Python/PyJWT | Meglévő helyi 3.12.14 / 2.13.0, új dependency nincs | Rögzített megfigyelés; nem egyezik az R6A CI lockkal |

## F. Következő legkisebb biztonságos csomag

**0A.1: offline authority/source-contract closure**, külön engedélyezéssel.

1. R6A deadline-spec tulajdonosi döntése: marad-e a kötelező 1 s. Az eltérés
   feloldásáig a closure CONDITIONAL. Az R5 permission és 86 regression marad.
2. Csak a külön pilotban: `contracts.py` ReviewedSourceManifest típusa
   chain/contract/runtime-codehash/ABI/source-commit/review-ref/block mezőkkel;
   `harness.py` fail-closed manifest-validator, alapból üres approved registry.
3. `test_pilot.py`: wrong codehash/ABI/source/block, expired/revoked review,
   legacy promotion és missing manifest negatívok; a jelenlegi 59 eset megőrzése.
4. `DATA-CONTRACT.md`: a CanonicalPieReader tervezett tagged unionje. Az
   OctoGFLO alkalmazás módosítása nélkül. Reviewed manifestet nem lehet pusztán
   fixture-címkével jóváhagyni: külön forrás-/deploy-bizonyíték és review kell.

Valós Auth/SIWE/consent/recovery/DB adapter vagy public bridge nem része ennek a
következő csomagnak sem. Külön integrációs és élesítési engedély nélkül nincs
production vagy R6B továbblépés.

## G. Változások és lezárás

Csak `/workspace/gflo-id-entity-pilot-0a` alatt készült új lokális implementáció:
contracts.py, bootstrap.py, harness.py, pilot_fixtures.py, test_pilot.py,
run_verified.py, a két manifest és a dokumentáció/evidence.
Az R6A tesztek csak ignored helyi ledgert hoztak létre. A cookR Git munkafa tiszta.

Nincs repository commit/push, PR-módosítás, merge, migráció, grant, deployment,
production credential, valódi wallet-művelet vagy XP/token-írás. A publikált
OctoGFLO és a valós PIE/Supabase állapot változatlan.
