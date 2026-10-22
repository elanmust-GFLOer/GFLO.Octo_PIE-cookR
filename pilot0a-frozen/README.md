# GFLO ID–Entity Integration Pilot 0A

Izolált, szintetikus Python harness. A cookR repository, a publikált OctoGFLO
és a PIE repository változatlan. Nincs HTTP-szerver, RPC-, adatbázis- vagy
wallet-kliens. Nincs commit, push, PR, migráció vagy deployment ebben a pilotban.

Futtatás az aktuális workspace-ben:

```sh
cd /workspace/gflo-id-entity-pilot-0a
python3 run_verified.py
```

A szomszédos `/workspace/gflo-r6a` Git HEAD-je kötelezően
`12e2df4c32ef51d08c799ec63a565c90221e8bcd`; a bootstrap minden import előtt
ellenőrzi az anchort és a tracked változások hiányát. Más anchor esetén megáll.
A meglévő R6A offline JWT-verifierét, független session-fixture-jét,
killable workerét és primary-lock szimulátorát használja. Új csomag telepítése
nem történt; a tényleges helyi Python/PyJWT verzió a tesztledgerben olvasható.
Nem állítunk egyezést az R6A CI hash-locked dependency-készletével.

`contracts.py`: typed ID–Entity rekordok és bizonyítékbesorolások.
`harness.py`: kizárólag védett fixture-adatolvasás, deny/quarantine útvonalak.
`pilot_fixtures.py`: két synthetic principal, profil, wallet, mock consent és
PIE rekord; kizárólag trusted teszt-setup. A mock MAC nem wallet-aláírás.
`test_pilot.py`: név szerint rögzített támadási és kompatibilitási esetek.
`run_verified.py`: fingerprint- és pontos tesztnév-ellenőrzés, zero-skip ledger.

`DATA-CONTRACT.md` tartalmazza a trust boundary-kat és a jövőbeli adapter-mappinget.
`SECURITY-REPORT.hu.md` a findingeket, eredményeket és a külön verdictet.
`evidence/anchors.json` és `evidence/sources/` a read-only forrásbizonyítékok.
`evidence/test-ledger.json` a tényleges végső lokális tesztledger;
`evidence/test-run.log` a teljes futási log. A `file-manifest.json` a
végrehajtott forrás és a snapshotok SHA-256-ját rögzíti. Nem GitHub-attestation.

A harness a rögzített R6A 2 másodperces policy-ját követi. Az eredeti 1 másodperc
nem teljesülő, nyitott specifikációs követelmény; nem fogadjuk el hallgatólagosan
a módosítását. A megfelelő diagnostic teszt PASS-ja a hibát reprodukálja.

A 59 tesztből a forrás-oracle és ismert-hiba diagnosztika nem protokollbiztonsági
PASS. A valódi wallet control, production Auth, canonical PIE, consent-aláírás,
durable state és multi-replica garancia nincs implementálva. Ezek BLOCKED.
