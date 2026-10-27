# GFLO teljes repó-leltár — hasznos és támogató kód/adat (2026-10-27)

Hatókör: az `elanmust-GFLOer` fiók mind a 12 repója, minden águkkal. Az on-chain adatok a Sepoliáról, az Etherscanen keresztül.
Jelölések: **[LIVE]** = most igaz · **[BLOCKER]** = akadályoz · **[ROADMAP]** = csak terv/teszt.

## TL;DR

1. **[LIVE] Mind a 4 deployolt Sepolia-szerződés forrása megvan, byte-pontosan** (a CBOR metadata-hash egyezik). A 10-16-os baseline még „nem található / majdnem egyező” volt. A források:
   - GFLOToken → `gflo-clean/contracts/MockGFLOToken.sol`
   - GFLOIgnition → `GasFeeLoop-@893f896` (régi commit, nem a `main`)
   - GasFeeLoop → `GasFeeLoop-@b454bd4` (régi commit, nem a `main`)
   - PIECore v3 → `gflo-pie@main` (ez már verifikált)

   A kész Etherscan Standard-JSON bemenetek: `verification/sepolia-legacy/`.
2. **[LIVE]** A `gflo-pie@feature/pie-core-v0.2` modulok végig összeköthetők. Az E2E teszt zöld (`tests/e2e/v02-composition.test.cjs`, előző kör).
3. **[LIVE] Új támogató kód:** a `GFLO-Sovereign-v0.1-@dev/contribution-ledger` ágon lévő `ContributionLedger` tesztjei 9/9 zöldek. Kétlépcsős adminátadást tartalmaz, ami a v0.2 policy/registry szerződésekből **hiányzik**.
4. **[BLOCKER]** Az Infura kulcs (`52c5b8…`) mind a 4 `gflo-frontend` ágon bent van. Rotálni kell.
5. **[BLOCKER] Frontend-hiba:** a `useUserPaths` 1e18-cal osztja a PIECore nyers egész XP-jét, ezért a 15 000 XP 0-ként jelenik meg.

## Szerződések (Sepolia) — verifikációs recept

| Szerződés | Etherscan | Forrás (exact) | solc | Optimizer | Source unit | Konstruktor-argok |
|---|---|---|---|---|---|---|
| GFLOToken `0x563b…07fe` | ❌ nem verifikált | gflo-clean `contracts/MockGFLOToken.sol` + OZ **4.9.3** (4.9.0–4.9.3 azonos) | 0.8.33 | ON, 200 | `MockGFLOToken.sol`, contract `MockGFLOToken` | nincs |
| PIECore v3 `0x9CF5…991e` | ✅ | gflo-pie@main `contracts/PIECore.sol` | 0.8.34 | OFF | `contracts/PIECore.sol` | — |
| GFLOIgnition `0x414D…CC54` | ❌ | GasFeeLoop-@`893f896` `contracts/core/GFLOIgnition.sol` | 0.8.34 | OFF | **`GFLOIgnition.sol`** (könyvtár nélkül) | pieCore `0x9cf5…991e`, token `0x563b…07fe`, treasury `0xf80a…fa31` |
| GasFeeLoop `0xd2C9…A9C7` | ❌ | GasFeeLoop-@`b454bd4` `contracts/GasFeeLoop.sol` | 0.8.34 | OFF | `contracts/GasFeeLoop.sol` | token `0x563b…07fe`, pieCore `0x9cf5…991e` |

Etherscan → *Verify & Publish* → *Solidity (Standard-Json-Input)* → a megfelelő `*.standard-input.json` feltöltése, a fenti compilerrel. Contract name: `MockGFLOToken.sol:MockGFLOToken`, `GFLOIgnition.sol:GFLOIgnition`, `contracts/GasFeeLoop.sol:GasFeeLoop`. Az ABI-kódolt konstruktor-argok a creation tx végéről származnak:
- GFLOIgnition: `0000000000000000000000009cf55d0b9d61dc28ef3cb10765cf4b861cd0991e000000000000000000000000563b2e3b499818a2f84c472efb3169a2667807fe000000000000000000000000f80a456710b7af746d88733dc456bc3190e6fa31`
- GasFeeLoop: `000000000000000000000000563b2e3b499818a2f84c472efb3169a2667807fe0000000000000000000000009cf55d0b9d61dc28ef3cb10765cf4b861cd0991e`

Csapdák:
- A token valódi neve `MockGFLOToken`, és `1 000 000 000` GFLO-t mintelt a deployernek. A „GFLOToken” név csak címke.
- A GasFeeLoop- `main` ága már **nem** a deployolt kód. Ezt a 07-23-i „Fix” commitok átírták, ezért volt a baseline-ban csak „near match”.

## Repók — mit érdemes megtartani

| Repó | Utolsó commit | Hasznos / támogató | Csapda / szemét | Javaslat |
|---|---|---|---|---|
| **gflo-pie** | 10-23 (ág) | v0.2 modulok (Core, XPPolicyV03, Adapter, EffectiveTierGate, FixedSupply token, IgnitionV01), `tests-v02` harness, red-team scriptek, Sepolia evidence archívum | `main` gyökér: 3 `compiled*` mappa, duplikált wallet-scriptek, `Lock.sol`; a `gainXP` nyitott; a hardening ág üres | **MAG.** v0.2 → main |
| **GFLO.Octo_PIE-cookR** | 10-27 (ág) | Threat model, ADR-0001, XPPolicyV04 + SourceBoundAttestor, SIWE/EIP-712 wallet-consent (`pilot0c/proof.cjs`), fail-closed gateway | 23+ ág, 0 merge, nincs `package.json`, 517 KB vendorolt ethers | **Labor + dokumentáció.** A V04 és a SIWE átemelése |
| **GFLO-Sovereign-v0.1-** | 10-12 | CORE-01…07 elfogadási kritériumok (jó checklist). `ContributionLedger` (2-lépcsős owner, egyszeri contribution-ID, 9/9 teszt) | A `main` csak dokumentáció; a v0.2-vel átfedő céllal | A **CORE-checklist** legyen a v0.2 merge kapuja. Az owner-átadási minta átemelése |
| **GasFeeLoop-** | 08-02 | **A deployolt GFLOIgnition és GasFeeLoop egyetlen forrása** (régi commitok) | A `main` nem egyezik a deployolttal; szemétfájlok (`0`, `.p`, `.bak`) | Tag: `deployed-2026-03-09` a `b454bd4`-re, utána archiválás |
| **gflo-clean** | 07-25 | **A deployolt GFLOToken forrása** (`MockGFLOToken.sol`). Moduláris Sovereign/Praxis/Reformer szerződésvázlatok | Az `ai/` modulok üresek (`class XPFraudDetector: pass`, `MEVGuard: pass`); `.en`, `gflo` szemét; duplikált backend | A tokenforrás megőrzése, utána archiválás |
| **gflo-backend** | 08-01 | Flask API, faucet blueprint (cooldown, env-kulcs, web3 v6), scheduler, CodeQL + Black Duck CI | Commitolt `__pycache__`; a faucet JSON-fájlba ír, captcha nincs; a legacy token `faucet()`-je amúgy is mintel | A faucet újrahasznosítható a FixedSupply tokenhez (transfer-alapú), Redis/PG + captcha kell hozzá |
| **gflo-frontend** | 08-02 | React/Vite/wagmi váz, címek bekötve, design tokenek (`gflo-design-tokens.css`), Dashboard komponensek | 🔴 Infura kulcs, commitolt `.env`, **40 MB `ngrok` bináris + tgz**; XP/1e18 hiba; legacy ABI-k (`getXP`/`getTier`); egy másik, nem kapcsolódó `GasFeeLoop.sol` | A UI-váz és a tokenek megtartása, az ABI-k átkötése a v0.2-re (`getIdentity`, `totalXP`, `effectiveTier`) |
| **gfloV1-00** | 08-01 | `PIECore` EIP-712 `grantXPWithSig` + nonce + `onlyAuthorized` gainXP; `sign_grant.js`; multisig/timelock README | A token `burn()`-t hív (a legacy tokenben nincs); nincs owner-transfer; a `consolidate-from-repos` ág csak töröl | A v0.2 XPPolicyV03 lefedi. Archív referencia |
| **PIE-README.md** | 07-31 | Pozicionáló szöveg („Identity First”, „XP = Proof of Becoming”) | Kód nincs | Marketing-forrás |
| **ElanMust-GFLOer-README.md** / **ElanMust-Diginthrope-README.md** | 08-11 | Profil-README, branding | — | Nem fejlesztési repó |
| **gflo-clean-** | 03-02 | — (csak LICENSE) | Üres | Törlés/archiválás |

## Kapcsolhatóság a repók között

- **Kanonikus lánc** (ellenőrizve): `PIECoreIgnitionV01` → `XPPolicyV03` (később V04) → `CanonicalXPAdapterV02` → `EffectiveTierGateV01`, plusz `GFLOFixedSupplyV01` + `GFLOIgnitionV01`.
- **Kiegészítő** a Sovereign repóból: a kétlépcsős `transferOwnership`/`acceptOwnership` minta. A `XPPolicyV03`, a `TrustedXPSourceRegistryV02` és a `PIECoreIgnitionV01` owner-e nem átadható (0 találat). Ha a Safe-et cserélni kell, újradeploy kell. Ezt dönteni kell: tudatos immutabilitás, vagy CORE-05 szerinti átadás.
- **Wallet-összekötés:** a cookR `pilot0c/proof.cjs` (SIWE + EIP-712 consent) és a gflo-pie `feature/octopass-wallet-binding-pilot` ugyanazt a problémát oldja meg. Egyet kell választani.
- **Frontend → v0.2:** a `gflo-web3-config.js` ABI-jait cserélni kell. A régi `identities()` tuple és a `getXP`/`getTier` a v0.2-ben nem létezik.
- **Backend faucet → FixedSupply token:** illeszkedik (transfer-alapú, előre feltöltött wallet). Ez az ADR „pre-funded treasury” elvével is egyezik.
- **Nem köthető:** a legacy GasFeeLoop (`addXP`, 1e18) a v0.2-höz (ADR-0001); a gflo-frontend saját `GasFeeLoop.sol`-ja (ERC20 + DetectorRegistry) semmihez.

## Titkok

Mind a 12 repó minden ágán kerestem (Infura, Alchemy, `gsk_`, `sk-`, `ghp_`, JWT, privátkulcs-hex). Egyetlen találat volt: az Infura `52c5b8…` a `gflo-frontend` mind a 4 ágán (`hullam.mjs:6`, `hullam.j:2`). A `security/remove-hardcoded-secrets` ágon is bent maradt.

## Doksi vs. valóság

- A baseline szerint „a GFLOToken/GasFeeLoop forrása nem található”. **Megcáfolva:** mindkettő megvan, exact match.
- A baseline szerint „a GFLOIgnition near match, 1 selector eltér”. Ez a `main` verzió volt; a **`893f896` commit exact**.
- A gfloV1-00 README multisig-átadást ír, de a PIECore-ban nincs owner-transfer (a Sovereign baseline ezt helyesen jelezte).
- A gflo-clean AI-modulok nevei (fraud detector, MEV guard) képességet sugallnak, de üres osztályok → [ROADMAP].

## Következő lépés (sorrendben)

1. **Infura kulcs rotálása most**, utána `git rm --cached .env ngrok ngrok-*.tgz` a frontendben.
2. **3 Etherscan-verifikáció** a `verification/sepolia-legacy/*.standard-input.json` fájlokkal (kb. 10 perc). Utána a teljes legacy rendszer nyilvánosan auditálható. Előtte érdemes egy git tag: `GasFeeLoop-@b454bd4` → `deployed-2026-03-09`.
3. **v0.2 → main merge** a Sovereign CORE-01…07 checklisttel mint elfogadási kapuval. Utána újradeploy és a frontend ABI-átkötése (az 1e18-hiba javításával együtt).
4. **Archiválás:** GasFeeLoop- (a tag után), gflo-clean (a tokenforrás kimentése után), gfloV1-00, gflo-clean-.
