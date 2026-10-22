# R6A.1 + Pilot 0B — ellenőrzési határ

Kiindulás: `12e2df4c32ef51d08c799ec63a565c90221e8bcd`.
Izolált branch: `feature/b23r6a1-pilot0b-security-closure`.

Az eredeti R6A 2 másodperces alapértéke megsértette az 1 másodperces
autorizációs szerződést. A determinisztikus kontroll ugyanazt a végső policy
megfigyelést 1,857 másodpercre késlelteti: a befagyasztott régi forrás ALLOW-t
és adatot ad, az új implementáció QUARANTINE-t, védett adat nélkül.
A korábbi valós processzes reprodukció a változatlan Pilot 0A tesztje marad;
annak tényleges mért ideje futásonként eltér.

Az új Budget legfeljebb 1 másodperc, az egyes munkafolyamatok legfeljebb
400 ms-ot és a megmaradt keretet kapják. Az audit, generation fence,
válasz-előkészítés, kezdeti adatátadás és cleanup utáni ALLOW-visszatérés
ellenőrzött. A pontos végpontokat és hálózati korlátokat a
`b23r6a/DEADLINE-CONTRACT.md` rögzíti. Ez nem hard real-time hálózati garancia.

A hét processzindítás az új keret mellett helyben időnként biztonságos
timeoutot okozott a konkrét DENY/ALLOW-t váró régi tesztekben. A forrást és
assertionöket változatlanul hagytuk. Négy, egyenként leállított és reaperelt,
csak olvasó batch csökkenti az indítási költséget; a végső session/policy
bizonyíték továbbra is friss, audit utáni és fence-en belüli. Ezután az eredeti
42 gateway-teszt teljes helyi futása sikeres. A korábbi hibás futások nem PASS
eredmények, és nem production regressziók bizonyítékai.

## Változó fájlok

| Fájlok | Feladat |
|---|---|
| `b23r6a/deadline.py`, `adapter_batches.py` | Közös időkeret, határolt megfigyelések |
| `gateway.py`, `events.py`, `workers.py`, `http_server.py` ugyanitt | Végső ellenőrzések, határidős audit és adatátadás, cleanup |
| `b23r6a/tests/test_deadlines.py` | 25 új, név szerint rögzített határidőteszt |
| `b23r6a/test-manifest.json`, `run_verified.py`, `run_combined.sh` | Pontos tesztazonosság és összesítés |
| `b23r6a/provenance.py`, `frozen_pilot.py` | Eredeti teszt/SQL blobok, 0A snapshot, checkout/merge és függőségbizonyíték |
| `.github/workflows/b23r6a-combined.yml` | Új branch/PR gate, letölthető evidence |
| `b23r6a/README.md`, `DEADLINE-CONTRACT.md` | Aktuális szerződés és korlátok |
| `pilot0b/manifest.py`, `tests/test_manifest.py` | Típusos offline validátor, 37 teszt |
| `pilot0b/legacy-sepolia.incomplete.json` | Valódi történeti forráslenyomatok, hiányzó runtime/deployment bizonyíték |
| `pilot0b/pilot0a-inventory.json`, `pilot0a-frozen/**` | Az eredeti 41 fájl és bizonyíték byte-pontos megőrzése |
| `pilot0b/README.md`, ez a jelentés és package `__init__.py` fájlok | Használati és értelmezési határ |

Az összes B2.2–R5 forrás, SQL gate és jogosultságdefiníció változatlan.
Az eredeti 86 Python-teszt neve **és forrásblobja** változatlan. Nincs új domain
DML, mutation EXECUTE vagy adatbázis-kapcsolat a gateway/manifest útvonalon.

## Tesztledger és acceptance

| Csoport | Elvárt pontos darabszám |
|---|---:|
| B2.2, R2, R3, R4, R5 PostgreSQL Python | 6 + 7 + 6 + 3 + 6 = 28 |
| Eredeti gateway, HTTP, manifest | 42 + 13 + 3 = 58 |
| Új deadline és forrásmanifest | 25 + 37 = 62 |
| Befagyasztott Pilot 0A a régi R6A ellen | 59 |
| Összesen | **207**, továbbá a változatlan SQL gate-ek |

Helyben a 42 + 3 + 25 + 37 és az eredeti 59 lefutott: **166/166 PASS**.
A helyi sandboxban nincs PostgreSQL és engedélyezett socketes HTTP-végrehajtás;
a hiányzó 28 + 13 végrehajtását csak a disposable GitHub-job igazolhatja.
Ennek sikerét ez a forrásjelentés nem előlegezi meg. A futásazonosítót és
végleges állapotot a PR és az adott futás artifactja rögzíti.

A CI kizárólag akkor zöld, ha minden pontos név megvan, minden státusz PASS,
nincs skip/expected failure, az összes SQL gate sikeres, a két friss adatbázis
külön OID-val fut, a merge szülői és fája megfelelő, a függőségek hash szerint
egyeznek és az evidence feltöltődik. Az artifact tartalmazza az egyedi JSON
ledgereket, logokat, platformverziókat, forrás-hashokat és SHA256SUMS fájlt.
Az archivált 0A ismert-hiba tesztjeinek PASS státusza régi hibát reprodukál.

## Forrásbizonyíték és fennmaradó findingek

* **HIGH / production blocker:** a legacy PIECore permissionless `gainXP`
  útvonala: `pilot0a-frozen/evidence/sources/etherscan/verified-PIECore.sol:59`;
  kontroll: `pilot0a-frozen/evidence/sources/pie/baseline.js:130`. Az XP
  LEGACY_UNTRUSTED_XP, nem canonical XP vagy jogosultság.
* **HIGH / production blocker:** nincs hiteles friss deployment/runtime/proxy
  bizonyíték vagy elfogadott canonical PIE manifest. A valódi legacy rekord
  UNKNOWN, hiányzó hashokkal elutasított; nincs kitalált kriptográfiai digest.
* **HIGH / production blocker:** nincs production Supabase session-authority,
  cross-system azonnali revoke-garancia, tartós/disztribuált gateway fence,
  audit/idempotency, SIWE, külön aláírt consent vagy recovery. A szimulátor
  sikeres tesztje ezeket nem bizonyítja.
* **MEDIUM / korlátozás:** offline Registry megbízható konfigurációs input.
  A validátor belső konzisztenciát ellenőriz, nem lánclekérdezést vagy forrásból
  újrafordítást. Jelenleg kizárólag a dokumentált `balanceOf(address)` selector
  vektor támogatott; más selector elutasított. Nincs valódi PIE read connector.
* **MEDIUM / korlátozás:** az audit ALLOW-bejegyzés jóváhagyási esemény, nem
  kézbesítési nyugta. Későbbi timeout végső QUARANTINE-t eredményez; a már
  beírt eseményt nem értelmezzük adatátadási bizonyítékként.
* **LOW / reprodukálhatóság:** az Action SHA-k, PostgreSQL digest és wheel
  hashok rögzítettek; a hosted OS/kernel és Python patch rögzített futási
  bizonyíték, nem hermetikus OS-rebuild. Az artifact ZIP digestjének helyi
  újrahash-elése külön bizonyítékot igényel.

gfloDEVaccount továbbra is **NOT VERIFIED**. A synthetic observer nulla domain
DML és nulla mutation EXECUTE képességgel rendelkezik. Production auditolvasás
vagy írás nem engedélyezett ebből a csomagból.

**Labor:** az itt felsorolt helyi ellenőrzések PASS; teljes gate a CI-től függ.
**Production: BLOCK.** Kizárólag sikeres teljes tesztelés után DRAFT PR,
merge/deploy/migráció/aláírás/XP- vagy tokenművelet nélkül. Következő munka csak
külön jóváhagyott review lehet; nincs automatikus R6B vagy valódi integráció.
