# GFLO repók érettsége — pro és kontra (vázlat, 2026-10-27)

Kiegészítés a [repó-audithoz](GITHUB-REPO-AUDIT-2026-10-27.md). Kérdés: mennyire érett a tartalom, és mire használható most.

## Összkép egy mondatban

**Biztonsági kutatási labor, nem termék.** A cookR és a gflo-pie fegyelmezett, tesztvezérelt prototípus-munkát mutat. Semmi sincs integrálva, deployolva vagy élesben használva, és a munka nagy része nem a `main` ágon van.

## Érettségi skála (0–5)

0 = ötlet · 1 = dokumentált terv · 2 = működő prototípus · 3 = tesztelt, integrált, `main`-ben · 4 = élesben/teszthálón használt · 5 = auditált, üzemeltetett

| Repó / terület | Szint | Indoklás |
|---|---|---|
| **GFLO.Octo_PIE-cookR** | **2** | 33 pilot, ~4100 sor kód és teszt, 36 CI-workflow; mind „lab only”, egyik sincs a `main`-ben |
| **gflo-pie** `main` (PIECore v3) | **2–4** | Sepolián deployolva és verifikálva (4), de két fő funkciója mindig revertál, a `gainXP` nyitott, felhasználó nincs (2) |
| **gflo-pie** `feature/pie-core-v0.2` | **2** | V02/V03 szerződések, Hardhat tesztek, 2 CI; 146 commit merge nélkül, nincs deployolva |
| **gflo-frontend** | **2** | Működő React/wagmi UI, de kiszivárgott kulcs, commitolt bináris, 1 teszt |
| **gflo-backend** | **2** | Kicsi Flask API (14 fájl, 10 commit), 1 teszt |
| **GasFeeLoop-, gflo-clean** | **1** | Régi vagy duplikált kód; archiválásra érett |
| **PIE-README.md** | **1** | Jegyzetek |

## ✅ Pro — ami valóban erős

1. **Biztonsági gondolkodás átlag feletti.** A threat model, a fail-closed alapelv és az egymástól elkülönített főkönyvek (app credit ≠ XP ≠ GFLO) egyértelműen ki vannak mondva. A README őszinte: „architecture proposal only”.
2. **A tesztek valódiak, nem csak leírások.** Node `node:test`, eldobható PostgreSQL 16, lokális EVM, ERC-1271 és SIWE támadási tesztek. Az eredmények pontos számokkal vannak dokumentálva (pl. 15/15, 28/28, 9/9).
3. **A CI ellátási lánc szempontjából gondos.** A GitHub Actionök commit SHA-ra vannak pinelve, a jogosultság `permissions: contents: read`, a `persist-credentials: false` be van állítva, a `package-lock` hash ellenőrzött, és `npm ci --ignore-scripts` fut.
4. **Az önkorlátozás következetes.** Minden pilot README-je kimondja, mit NEM bizonyít (pl. „sourceVerification=NOT_ESTABLISHED_BY_RPC”, „Production BLOCK”). Ez ritka és értékes.
5. **A commitok fegyelmezettek.** Conventional commit üzenetek, tematikus ágak, minden lépésről dátumozott eredmény-dokumentum.
6. **Van egy valódi on-chain eredmény.** A PIECore v3 forrása byte-pontosan egyezik és verifikált.

## ❌ Kontra — ami az érettséget visszatartja

1. **Nulla integráció.** A cookR-ben 19 nyitott PR van, egy sincs mergelve. Egymásra rakott láncot alkotnak (#8 → #9 → … → #18), így egyetlen hiba az elején az egész láncot blokkolja. A `main` 10-17 óta nem változott.
2. **A CI jelenleg piros.** A legfrissebb PR (#20, `517d95e`) fején **37 workflowból 13 bukik**. Gyökérok például az IB-03D1-nél: a workflow kézzel másolja át a fájlokat egy külső „harness”-be, és a `siwe-parser.mjs` kimaradt a listából (`ERR_MODULE_NOT_FOUND`). A korábbi pilotok tehát regresszióval eltörtek, és ezt senki nem vette észre.
3. **Törékeny tesztarchitektúra.** Nincs `package.json` a cookR ágon. Minden workflow egy *másik ág* rögzített commitjából (`1ea68bc`, ib02d) veszi a függőségeket, és egyenként másolja a fájlokat. Pilotonként külön workflow fut (36 db), közös tesztparancs nincs. Ez nem skálázódik.
4. **A koncepciók gyorsabban szaporodnak, mint ahogy lezárulnak.** Egyetlen ágon az IB-03 A-tól Z-ig ért, majd jött R1A–R1D, kb. 10 nap alatt. 1371 CI-futás volt, közben a 10-16-os on-chain blokkolók közül egyet sem javítottunk ki. Ez a „magas koncepcionális, alacsony operatív sebesség” minta.
5. **Egyszemélyes projekt, független emberi review nélkül.** A commitok kb. 99%-a egy szerzőtől származik (több fióknévvel). A review-k AI-promptokon keresztül futnak (`CODEX_REVIEW_PROMPT.md`), ami hasznos, de nem helyettesíti a külső auditot. A bus factor 1.
6. **Szétszórt kódbázis.** 7 repó van, ebből 2 halott vagy duplikált, és félrevezető nevek is vannak (a `GasFeeLoop-` nem a deployolt GasFeeLoop forrása). A deployolt GFLOToken és GasFeeLoop forrása egyik repóban sincs meg.
7. **A dokumentáció és a valóság távolsága.** A papíron kidolgozott architektúra (XPPolicyV03, EffectiveTierGate, OctoPass-híd) mögött nincs deployolt szerződés. A deployolt token közben korlátlan `faucet()`-tel mintel, ami ellentmond a „fixed-supply” elvnek.
8. **Alap higiéniai hibák.** A frontend `main` ágán Infura kulcs, commitolt `.env` és `ngrok` bináris van. A dependabot PR 07-30 óta nyitva áll.

## Mérleg

| Szempont | Értékelés |
|---|---|
| Ötlet- és tervminőség | ⭐⭐⭐⭐ |
| Biztonsági gondolkodás | ⭐⭐⭐⭐ |
| Tesztek mennyisége | ⭐⭐⭐⭐ |
| Tesztek karbantarthatósága | ⭐⭐ |
| Integráció / merge | ⭐ |
| Deploy / éles használat | ⭐ |
| Higiénia (titkok, halott kód) | ⭐⭐ |
| Csapat / review | ⭐ |

**Ítélet:** jó minőségű kutatási anyag, amely termékként még a 2-es szint alján áll. A következő érettségi szintet nem újabb pilot hozza, hanem az, ha **kevesebb dolgot zárunk le, de azokat teljesen**.

## Mi vinné a 3-as szintre (sorrendben)

1. **CI zöldre:** egy közös `package.json` a cookR-ben, egyetlen `npm test` parancs, amely minden pilotot futtat. A kézi fájlmásolást és a más ágra mutató harness-t meg kell szüntetni.
2. **Merge-politika:** a stacked lánc (#8 → #18) aljától kezdve sorban merge, vagy egy összevont PR. Új pilot csak akkor induljon, ha a `main` zöld.
3. **Egy vertikális szelet végig:** a `gainXP` javítása, egy működő `burn` útvonal, deploy és verifikálás Sepolián, és legalább egy valódi, nem admin tranzakció.
4. **Takarítás:** a `GasFeeLoop-` és a `gflo-clean` archiválása, a deployolt GFLOToken és GasFeeLoop forrásának visszakeresése vagy újraírása, a titkok rotálása.
5. **Külső szem:** legalább egy független emberi review a PIECore V02/V03-ra a deploy előtt.
