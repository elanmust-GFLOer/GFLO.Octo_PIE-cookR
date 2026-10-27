# GFLO GitHub repó-audit — vázlat (2026-10-27)

Előző alapállapot: 2026-10-16. Forrás: mind a 7 publikus `elanmust-GFLOer` repó összes ága (`git ls-remote` + teljes klón), cookR PR-lista (GitHub API), Etherscan Sepolia verifikációs állapot.
Jelölések: **[LIVE]** = most igaz · **[BLOCKER]** = akadályoz · **[ROADMAP]** = csak terv/teszt.

## TL;DR

1. **[BLOCKER] Semmi nem jut be a `main`-be.** A cookR `main` 10-17 óta áll; 23 feature-ág, **19 nyitott PR, 0 merge**, egymásra rakott (stacked) láncban. A gflo-pie `feature/pie-core-v0.2` **146 committal** a `main` előtt jár, merge nélkül.
2. **[BLOCKER] Az Infura kulcs még mindig a gflo-frontend `main`-ben van** (`hullam.mjs`, `hullam.j`: `52c5b8…`). A `security/remove-hardcoded-secrets` ág már be van mergelve, de a kulcsot **nem** távolította el.
3. **[BLOCKER] A PIECore `gainXP` hibájának javítása nincs elkezdve.** A `security/piecore-xp-access-hardening-20261025` ág **üres** (azonos a `main`-nel). A deployolt és a v0.2-ági `PIECore.sol` `gainXP` függvénye továbbra is jogosultság-ellenőrzés nélküli.
4. **[LIVE] Új:** a PIECore v3 (`0x9CF5…991e`) **verifikálva** van az Etherscanen. GFLOToken, GFLOIgnition, GasFeeLoop: **továbbra sem**.
5. **Minta:** 10-17 és 10-26 között ~70 új commit, 6+ új koncepciószál (B2.x, R6A, Pilot 0B–0D, IB-02/03, V04), miközben a 10-16-os on-chain blokkolók (`burn`/`burnFrom` hiányzik, `gainXP`, az `ignite()` mindig revertál) változatlanok. Ez a **„magas koncepcionális sebesség, alacsony operatív sebesség”** minta.

## Szerződések (Sepolia)

| Szerződés | Verifikált? | Forrás a GitHubon | Működik? |
|---|---|---|---|
| GFLOToken `0x563b…07fe` | ❌ | nem található | ⚠️ `faucet()` korlátlan, nincs `burn` |
| PIECore v3 `0x9CF5…991e` | ✅ **(új)** | gflo-pie `contracts/PIECore.sol` (exact) | ⚠️ `gainXP` nyitott, az upgrade mindig revertál |
| GFLOIgnition `0x414D…CC54` | ❌ | majdnem egyező (GasFeeLoop-, 1 selector eltér) | ❌ az `ignite()` mindig revertál |
| GasFeeLoop `0xd2C9…A9C7` | ❌ | nem található | ⚠️ az epoch cap nem köt |

On-chain aktivitást ebben a körben nem ellenőriztem újra, csak a verifikációt.

## Repók

| Repó | Utolsó commit | Mi van benne valójában | Jelzés |
|---|---|---|---|
| **GFLO.Octo_PIE-cookR** | 10-26 (ág) / 10-17 (`main`) | Integrációs blueprint és red-team tesztek (RT6A–D8), izolált PostgreSQL/Auth gate-ek (B2.2–B2.3R6A), Pilot 0B–0D (offline SIWE, localhost explorer), IB-02D V04-jelölt, IB-03B OctoPass reader mock | [ROADMAP] 19 nyitott PR, 0 merge; nincs deploy |
| **gflo-pie** | 10-23 (ág) / 10-20 (`main`) | `main` = a deployolt PIECore v3. A `feature/pie-core-v0.2` ágon: PIECoreV02, XPPolicyV02/V03, EffectiveTierGateV01, GFLOFixedSupplyV01, CanonicalXPAdapterV02, registry-k, CI (2 workflow). További ágak: OctoPass wallet binding, proof bridge, CI provenance, hardhat-hardening | [BLOCKER] v0.2 +146 commit merge nélkül; 1 üres security-ág; dependabot (lodash) 07-30 óta nyitva |
| **GasFeeLoop-** | 08-02 | Félrevezető név: régi PIECore/GFLOIgnition/GasFeeLoop források, HelloCrypto, Python szimuláció | Csapda: nem a deployolt GasFeeLoop forrása |
| **gflo-backend** | 08-01 | Railway Flask API, faucet blueprint (`FAUCET_PRIVATE_KEY` env), scheduler, Black Duck CI | Nincs commitolt titok |
| **gflo-clean** | 07-25 | Régebbi Flask-másolat, AI modulok, nem deployolt moduláris szerződések | Duplikátum, halott kód |
| **gflo-frontend** | 08-02 | React/Vite/wagmi, címek bekötve (`useUserPaths` → pieCore) | 🔴 **Infura kulcs `52c5b8…`** a `main`-ben; commitolt `.env` (csak `VITE_API_URL`) és `ngrok` bináris; 3 be nem mergelt Vercel-analytics ág |
| **PIE-README.md** | 07-31 | Jegyzetek/assetek (`gflo-Sov-Pro`) | Nem kód |

Titokkeresés (minden ág, a teljes history-ban privát kulcs formájú hex is): az Infura kulcson kívül **nincs** találat (`gsk_`, `sk-`, `ghp_`, JWT, `PRIVATE_KEY=0x…`). A gflo-pie `.env.example` csak placeholdereket tartalmaz.

## Kritikus hibák (bizonyítékkal)

- **Infura kulcs kiszivárgott** — `gflo-frontend@main:hullam.mjs:6`, `hullam.j:2`. A `security/remove-hardcoded-secrets` a `main` őse, mégis mindkét fájl tartalmazza a kulcsot. A history-ban maradó kulcsot rotálni kell, a törlés önmagában nem elég.
- **`gainXP` jogosultság nélkül** — `gflo-pie@feature/pie-core-v0.2:contracts/PIECore.sol:59-62`: bárki, akinek van ösvénye, korlátlan XP-t ír magának. A deployolt kódban ugyanez (az Etherscan forrása megerősíti). A javító ág (`security/piecore-xp-access-hardening-20261025`) commit nélküli.
- **A deployolt PIECore `burn()`-t hív egy tokenen, amelyben nincs `burn`** — a verifikált forrás most nyilvánosan is mutatja: az `upgradeToReformer`/`upgradeToPraxis` mindig revertál.

## Doksi vs. valóság

- cookR README: „architecture proposal only” → **igaz**, és még mindig az. A „15/15”, „28/28”, „9/9” PASS-eredmények **izolált lokális/CI** környezetre vonatkoznak, nem Sepoliára.
- Az „XPPolicyV03 / EffectiveTierGate” csak a gflo-pie feature-ágon létezik, **nincs deployolva** → [ROADMAP].
- A „GFLO fixed-supply” állítás a prototípusra (`GFLOFixedSupplyV01`) vonatkozik; a **deployolt GFLOToken korlátlan `faucet()`-tel mintel** → ellentmondás.

## Változás az alapállapothoz képest (10-16 → 10-27)

- ✅ PIECore v3 verifikálva az Etherscanen.
- ➕ cookR: 23 új ág, 19 PR (mind nyitott). gflo-pie: 6 új ág (security/CI/OctoPass).
- ➖ Semmi nem javult a 10-16-os on-chain blokkolók közül; az Infura kulcs maradt.

## Következő lépés (sorrendben)

1. **Infura kulcs rotálása most** (Infura dashboard → új kulcs), utána `hullam.mjs`/`hullam.j` → `import.meta.env.VITE_RPC_URL`, a `.env` és az `ngrok` bináris kivétele a repóból (`git rm --cached .env ngrok`).
2. **Merge-stop az új szálaknál:** a cookR PR #1–#8 közül döntsd el, mi kerül a `main`-be, és zárd le a többit, mielőtt új pilotot nyitsz. A gflo-pie `feature/pie-core-v0.2` → `main` PR.
3. **Egy on-chain blokkoló lezárása:** `gainXP` → `onlyAuthorized` (vagy törlés), a meglévő üres `security/piecore-xp-access-hardening-20261025` ágon, újradeploy és verifikálás ugyanazzal a recepttel, mint a PIECore v3-nál (solc 0.8.34, optimizer OFF, source unit `contracts/PIECore.sol`).
