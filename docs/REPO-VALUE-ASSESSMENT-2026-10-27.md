# Mi az értékes a repókban? — pro/kontra és kapcsolhatóság (2026-10-27)

Hatókör: `GasFeeLoop-`, `gflo-pie`, `GFLO.Octo_PIE-cookR`, az összes águkkal együtt (kb. 45 ág).
Kiegészíti a `claude/github-repos-analysis-6dtl2b` ágon lévő audit- és érettségi vázlatot. Azokat nem ismétli meg, hanem azt nézi, **melyik kód használható újra, és mi köthető össze**.
Jelölések: **[LIVE]** = most igaz · **[BLOCKER]** = akadályoz · **[ROADMAP]** = csak terv/teszt.

## TL;DR

1. **[LIVE] A legértékesebb lelet:** a `gflo-pie@feature/pie-core-v0.2` modulok **végig összeköthetők**. Saját E2E teszt (`tests/e2e/v02-composition.test.cjs`) bizonyítja a teljes láncot egy lokális EVM-en: identity → EIP-712 aláírt XP → 3 napos challenge → GFLO-égetés → tier-emelés → visszavonás után az effektív tier leesik. A meglévő 15/15 teszt is zöld (solc 0.8.28, OZ 5.6.1).
2. Ez pontosan az a vertikális szelet, amely a **deployolt** rendszerben mindig revertál: a token nem ismeri a `burn`/`burnFrom`-ot, és a PIECore-ból hiányzik az `upgradeTier`. **A javítás már megvan, csak nincs mergelve és deployolva.**
3. **[BLOCKER]** A deployolt PIECore `gainXP` függvénye továbbra is jogosultság nélküli (`main` és v0.2 `contracts/PIECore.sol:59`). A `security/piecore-xp-access-hardening-20261025` ág üres.
4. Az on-chain állapot a 10-16-os baseline óta nem változott: a GFLO tokennek nincs új transzfere (az utolsó a 10313368-as blokkban volt: 1M GFLO ragadt a token-szerződésben).

## Repónként: pro / kontra

### gflo-pie — a mag (érték: ⭐⭐⭐⭐)
**Pro**
- Kis, olvasható, egyfeladatos szerződések (22–190 sor), custom errorokkal, fail-closed logikával.
- A v0.2 tervezése helyes: az `achievedTier` (történeti) és az `effectiveTier` (jogosultság) külön van választva. A visszavont XP után a jogosultság automatikusan megszűnik.
- `GFLOFixedSupplyV01`: tiszta OZ `ERC20Burnable`, nincs admin, nincs mint. Ez a deployolt token `faucet()`-hibájának egyenes javítása.
- `GFLOIgnitionV01` ellenőrzi, hogy az égetés pontos volt-e (balance és supply delta), és van reentrancy guardja.
- A `tests-v02` harness reprodukálható: lockolt compiler, `npm ci`, nincs hálózat.

**Kontra**
- 146+ commit a `main` előtt, merge nélkül. A `main` gyökérkönyvtára szemetes: 3 `compiled*` mappa, `Lock.sol`, duplikált `gflo-wallet.js`/`gflo_wallet.js`, és a gyökérben egy második `PIECore.sol`.
- A gyökér `package.json` keveri a Hardhat 3-at a toolbox 6-tal, és hiányzik belőle az OZ, pedig a `GFLOFixedSupplyV01` importálja. Csak a `tests-v02` alprojekt működik.
- Három párhuzamos XP-policy él (V02, V03, és V04 a cookR-ben), kanonikus kiválasztás nélkül.

### GFLO.Octo_PIE-cookR — biztonsági labor (érték: ⭐⭐⭐ ötletként, ⭐ kódként)
**Pro**
- Kiváló threat model és ADR-0001: a staking nem ad XP-t, és külön van az app credit, az XP és a token. Ez a projekt „alkotmánya”, érdemes megtartani.
- Újrahasznosítható darabok:
  - `XPPolicyV04` + `GFLOSourceBoundAttestorV01` (ib02d ág): EXPIRED státusz, rögzített attestor, ERC-1271. Ez a V03 utódja.
  - `pilot0c/proof.cjs`: SIWE és EIP-712 wallet-consent. Kiindulópont az OctoPass ↔ wallet összekötéshez.
  - `b23r6a/gateway.py`: fail-closed döntési gateway.
- Sok támadási teszt (replay, issuer-rotáció, ERC-1271, concurrency).

**Kontra**
- A `main` 10-17 óta áll; 23+ ág, egymásra rakott PR-ek, 0 merge.
- Nincs `package.json`; 36 külön workflow fájlokat másol más ágakból, ami törékeny (a legfrissebb ágon CI-javítás kellett hiányzó `siwe-parser.mjs` miatt).
- Egy ágon 517 KB vendorolt `ethers.umd.min.cjs` van.
- A kód nagy része Python/JS teszt-harness; termékkód alig van benne.

### GasFeeLoop- — archívum (érték: ⭐)
**Pro**
- Történeti forrás: a GFLOIgnition majdnem egyezik a deployolttal (1 selector eltér). A Python `core/` egy 24 soros REGEN-reward vázlat, ötletként megtartható.

**Kontra**
- Félrevezető név: a `contracts/GasFeeLoop.sol` **nem** a deployolt GasFeeLoop forrása. Az ADR-0001 szerint ez nem kompatibilis XP-író (`addXP`, 1e18-skála, stake-szorzó).
- Szemét fájlok: `0` (üres), `gflo.p`, `gitignore_helper.p`, `.bak`/`.backup` configok.
- **Javaslat: archiválni.**

## Kapcsolhatósági térkép (ellenőrizve)

| Fogyasztó → szolgáltató | Szükséges interfész | Állapot |
|---|---|---|
| GFLOIgnitionV01 → PIECoreIgnitionV01 | `getIdentity`, `upgradeTier` | ✅ E2E |
| GFLOIgnitionV01 → CanonicalXPAdapterV02 | `pieCore()`, `totalXP` | ✅ E2E |
| GFLOIgnitionV01 → GFLOFixedSupplyV01 | `burnFrom`, `balanceOf`, `totalSupply` | ✅ E2E |
| CanonicalXPAdapterV02 → XPPolicyV03 | `pie()`, `totalXP` | ✅ E2E |
| EffectiveTierGateV01 → Adapter / Registry | `pieCore()`, `totalXP` | ✅ E2E + RT5-15 |
| Deployolt GFLOIgnition → deployolt PIECore/GFLOToken | `upgradeTier`, `burnFrom` | ❌ hiányzik → mindig revert |
| Legacy GasFeeLoop → PIECoreV02/IgnitionV01 | `addXP` | ❌ szándékosan nincs (ADR-0001) |
| PIECoreV02 (v0.2) → GFLOIgnitionV01 | `upgradeTier` | ❌ nincs; helyette a `PIECoreIgnitionV01` kell |

Csapda: a `PIECoreV02` és a `PIECoreIgnitionV01` két külön core. Az ignition-láncot **csak** az utóbbi támogatja.

## Észrevételek az E2E futásból (nem blokkolók, döntést igényelnek)
- Visszavonáskor (`revoke`) az elégetett GFLO elveszik, de a tier „achieved” marad. Ez szándékos, de a felhasználónak ki kell írni.
- A Reformerhez 1000 XP kell, a heti cap 3000, így a Praxishoz (5000 XP) legalább 2 hét kell. Ez paraméterdöntés.
- A `HIGH_TRUST_FROM = 500` miatt az 500+ XP-s szabályokhoz 2-es szintű verifier kell.

## Következő lépés (sorrendben)
1. **Merge:** `gflo-pie` `feature/pie-core-v0.2` → `main`. A kanonikus lánc legyen `PIECoreIgnitionV01` + `XPPolicyV03` (vagy V04) + `CanonicalXPAdapterV02` + `EffectiveTierGateV01` + `GFLOFixedSupplyV01` + `GFLOIgnitionV01`. Az E2E tesztet a `tests-v02/test/` alá kell tenni.
2. **Sepolia újradeploy** ugyanezzel a lánccal, verifikálva. A régi PIECore v3 / GFLOToken / GFLOIgnition / GasFeeLoop kerüljön „legacy” címkét. Ez egyben megszünteti a `gainXP`- és a `faucet()`-problémát is.
3. **Takarítás:** a `GasFeeLoop-` archiválása; a cookR-ben közös `package.json` + `npm test`; új pilot csak zöld `main` mellett.

A minta változatlan: **magas koncepcionális, alacsony operatív sebesség**. A megoldás itt nem újabb pilot, mert a működő kód már megvan. Egyetlen merge és egyetlen deploy kell hozzá.
