# Pilot 0D-1 — implementáció és biztonsági átadás

## Scope és anchorok

- Kiindulás: `44d077f4f0d8a0a978fb18ad18190ee361cc9608`, draft PR #17.
- Az alkalmazáskód ellenőrzött változata: `d337200d62eb6af8661b2307345537fa4bf8789b`.
- Draft PR: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/pull/18.
- A későbbi diagnosztikai/dokumentációs commitok pontos checkoutját, szülőit és
  tree-jét a CI provenance-artifact rögzíti; nem írunk előre ismeretlen hash-t.

Az implementáció kizárólag szintetikus localhost labor. A publikált OctoGFLO és
OctoPush alkalmazás, a production Supabase és az on-chain rendszerek változatlanok.
Nincs binding-aktiválás, persistent wallet-authority, új RPC/DML-jog, migration,
token/XP-művelet, deployment vagy merge. Production verdict: **BLOCK**.

## Architektúra és trust boundary

1. A tesztvezérlő külön A/B synthetic sessiont és opaque capabilityt állít elő.
   A szerver birtokolja a principal/profile/session összerendelést és a challenge-t.
2. A böngésző explicit EIP-1193 providert kap a fixture-hídtól. Nem olvassa vagy
   hívja az injektált valódi walletet. A cím discovery, nem ownership-bizonyíték.
3. A szerver kizárólag `127.0.0.1:43817` címen figyel. A Host és Origin pontosan
   a rögzített localhost origin; a sensitive POST külön Bearer capabilityt és CSRF
   tokent igényel. Cookie és caller AuthContext nem authority.
4. A felhasználó külön művelettel erősíti meg a SIWE personal_sign és az EIP-712
   consent aláírását. A szöveg, scope és pontos typed fields előtte látható.
   A kliens fixed signing policyja az eltérő scope/domain/schema esetén nem kér
   aláírást. A signer külön eldobható processz; kulcs nem kerül a böngészőbe vagy
   a proof HTTP-szerverbe, nincs key-export RPC.
5. A Pilot 0C verifier mindkét valódi EOA-signature-t, a server-owned challenge-t,
   sessiont, generationt, consentet és replay állapotot ellenőrzi.
6. A redaktált audit és JSON-előkészítés után, az első protected write előtt újra
   ellenőrződik a session/generation és a consent revocation/expiry. Az exact
   in-memory eredmény egyszer adható át; másolat vagy retry nem delivery capability.

A határidő a request handler kezdetétől az első protected application write-ig
legfeljebb egy másodperc. Ez nem hard real-time hálózati kézbesítési garancia.
Timeout/abort/UNKNOWN/revocation/auditkiesés nem adhat ki protected eredményt.
Nincs automatikus retry vagy halasztott mutation queue. A health nem foglal
protected workerkapacitást. A kliens CSP-t, textContent-renderelést és memory-only
állapotot használ; nincs érzékeny adat storage-ban, cookie-authorityban vagy URL-ben.

Források: `server.cjs`, `frontend/{app,wallet,policy}.mjs`, `browser-fixture.cjs`,
`signer-worker.cjs`; a végső consent-fence a `../pilot0c/proof.cjs` deliver metódusa.
A package/type/dependency-határokat `type-tests.ts`, `provenance.py` és
`check-dependencies.cjs` ellenőrzi. A frozen OctoGFLO CanonicalPieReader típusa nem
implementálható hiteles XP nélkül; nincs nullból implicit canonical nulla.

## Végrehajtott bizonyíték

| Csoportról rendelkezésre álló bizonyíték | Eredmény / hely |
|---|---|
| Eredeti Python/PostgreSQL/R6A.1/manifest csomag | 148/148 PASS a push és PR CI-ben |
| Frozen Pilot 0A | Push CI 59/59; PR CI 58 PASS + 1 FAIL; új helyi futás 59/59 |
| Pilot 0C crypto | 96/96 PASS helyben és push CI-ben |
| Pilot 0D-1 unit | 22/22 PASS helyben és push CI-ben |
| Pilot 0D-1 browser/HTTP | 50/50 PASS a push és PR CI-ben |
| SQL, R5 quarantine ACL, strict TypeScript | PASS CI-ben |
| Külön frozen concurrency diagnosztika | Három előre rögzített helyi próba: eredeti assertion teljesült |

A push run `39910829746` pontosan 375 egyedi tesztet futtatott sikerrel, nulla
skippel. A PR run `39911187463` pontos merge checkouton 256 PASS / 1 FAIL /
118 NOT EXECUTED eredményű: a frozen hiba után az inherited runner megállt.
Ezek eltérő futások, nem vonhatók össze egy zöld PR-gate állításává.

Az új egyedi tesztnevek: `unit-manifest.json` (22) és `browser-manifest.json`
(50: 27 browser + 23 HTTP). Mind a 303 inherited tesztnév, test/SQL forrás és
assertion megmaradt. A három diagnosztikai ismétlés nem három új egyedi regresszió
és nem helyettesíti a frozen 59-es gate-et.

Helyi frozen futás: Python 3.12.14, PyJWT 2.13.0, 31.401 s. A diagnosztikai
eredeti konkurens esetek 937–988 ms alatt egy ALLOW és egy CONSENT_REPLAY DENY
eredményt adtak, próbánként egy adatkiadással. A 33 megfigyelt worker-lépés közül
a maximum 158.050 ms volt; worker-exception nem történt. A kezdeti, külön ideiglenes probe szintén három sikeres megfigyelést adott;
az ellenőrzött utility futása nem a sikertelen CI újrapróbálása. Ez helyi megfigyelés,
nem a CI-hiba okának igazolása. A CI Python/PyJWT verziója eltér, és az artifact
rögzíti azt. A pontos nyers eredmények az `evidence/` és a CI artifactok részei.

A helyi sandbox nem enged AF_INET socketet; ezért a localhost HTTP, Chromium és
PostgreSQL végrehajtás CI-only. A ténylegesen renderelt szintetikus UX két képe a
browser-artifact része. Nem történt helyi manual headed vagy valódi wallet-próba.

## Fennmaradó findingek és release gate

| ID / súlyosság | Megállapítás és szükséges bizonyíték |
|---|---|
| P0D1-REG-01 / MEDIUM / OPEN | A változatlan `../pilot0a-frozen/test_pilot.py:176` PR CI-ben QUARANTINE/QUARANTINE-t kapott ALLOW/DENY helyett. A pontos reason/stage ott nem maradt meg. Határidő- vagy scheduling-ok csak hipotézis; a helyi siker nem zárja le. A teljes gate reprodukálhatósága és független review szükséges a 0D-2 előtt. |
| P0D1-AUTH-02 / HIGH production blocker | A synthetic authority nem Supabase session-authority. Nincs bizonyított external signout/revocation ordering, production adapter vagy account-auth integráció. Ez a labor deklarált határa, nem production PASS. |
| P0D1-STATE-03 / HIGH production blocker | A Map/fence/replay/audit állapot egy processzhez kötött. Nem bizonyít durable consentet, distributed replay protectiont, DB-atomicitást vagy recoveryt. |
| P0D1-SOURCE-04 / HIGH integration blocker | Nincs elfogadott canonical PIE deployment. A legacy Sepolia PIECore LEGACY_UNTRUSTED_XP; a megjelenített rekordok synthetic, canonicalXp és historicalTier null. Nincs XP/Tier/token/governance privilege. |
| P0D1-ENV-05 / LOW / OPEN | Az immutable browser/OS image és npm SRI reprodukálható artifact-határ; nem teljes advisory clearance, hermetic rebuild vagy privileged-host/extension elleni védelem. |

Az új `frozen-diagnostics.py` kizárólag eldobható offline megfigyelés. Az eredeti
tesztesetet három előre rögzített alkalommal futtatja; nem változtat assertiont,
értéket, deadline-t vagy kimenetet, és nem próbálkozik sikerig. A megfigyelő wrapper
csak stage-nevet, időket, outcome/reason és release-számlálót rögzít; nem argumentot,
payloadot, tokent vagy kulcsot. Az eredeti forrás-fingerprint ellenőrzése előtte és
utána kötelező. A diagnosztika saját hibája nonzero eredmény; sikerével nem lesz
zöld egy korábban megbukott inherited job. A CI az eredeti gate után külön futtatja,
és az evidence mindkét eredményt megőrzi.

## Pilot 0D-2 — csak javasolt elfogadási kapu

Előfeltétel a teljes inherited+új gate reprodukálhatóságának lezárása és a draft
független review-ja. Ezután külön tulajdonosi engedélynek kell megneveznie a pontos
origin, böngésző/extension-verzió, asset nélküli disposable EOA wallet és manual
aláírási lépések körét. A kulcs/seed az extensionben marad; az app nem kéri.

Kötelező az exact personal_sign bytes és typed consent ellenőrzése; cancel,
wallet/chain switch, origin, A/B isolation, replay, expiry, revocation, CSP/storage,
audit-outage és zero unauthorized release ismétlése. Sem transaction-, sem token-
approval RPC nem megengedett. A teardown és a redaktált bizonyíték kötelező.
ERC-1271 külön specifikáció és verifier nélkül NOT SUPPORTED. gfloDEVaccount
NOT VERIFIED. Nincs automatikus 0D-2, production vagy merge-engedély.
