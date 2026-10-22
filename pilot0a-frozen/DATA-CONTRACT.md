# ID–Entity 0A: adat- és authority-szerződés

## Typed kapcsolatok

| Típus / mező | Bizalom forrása | Pilot 0A viselkedés |
|---|---|---|
| `PrincipalId` | JWT-verifier + friss user + független session-authority | R6A ephemeral testkulcs; nem Supabase production |
| `ProfileId` | Szerveroldali principal → profil ownership lookup | Külön profil-UUID-k, nem a caller principal-állítása |
| `WalletRef(chain_id,address)` | Későbbi, külön wallet-possession proof | Két fixture-cím, assurance kizárólag DEMO_FIXTURE |
| `ProtocolRef(protocol_id,chain_id,contract,account)` | Szerveroldali verziózott forrásreferencia | A teljes tuple pontos összevetése; nincs címnév-alapú bizalom |
| `Relation` | Authenticated principal + profile owner + wallet/protocol-association | Szerverben előre seedelt, szintetikus read-only kapcsolat |
| `Consent` | Külön scoped consent-authority | Mock HMAC a teljes struktúrán, nem Ethereum-aláírás |
| `generation` | Hitelesített session és primary fence egyetértése | R6A process-local szimulátor; nincs distributed állítás |
| `epoch`, `revocation_generation` | Helyi binding lifecycle-authority | Régi consent mindkettő változására elutasítva |
| `Provenance` | Forrásspecifikus registry + tartalomdigest + ellenőrzési scope | Fixture URI/digest/confidence; reviewed registry üres, canonical BLOCKED |

A protokollazonosság nem azonos az alkalmazásprofiléval. A wallet-cím önmagában
nem azonosítja az Auth principal-t; a principal ownership önmagában nem bizonyít
wallet controlt. Egyik sem bizonyít unique humanityt vagy hozzájárulást.

A harness wire-formátuma canonical lower-case 20 byte hex címet vár, nulla címet
elutasít. Nem EIP-55/ENS verifier, nem valós wallet onboarding.

## Egymástól külön bizonyítékosztályok

| Osztály | Mit jelent | Mit enged itt |
|---|---|---|
| DEMO_FIXTURE | Szintetikus identitás/adat/mock proof | Saját profilhoz engedélyezett fixture-olvasás |
| VERIFIED_WALLET_CONTROL | Célállapot: valós cryptographic possession proof | Nincs verifier; ilyen assurance kérése QUARANTINE |
| LEGACY_UNTRUSTED_XP | Önosztott XP-t megengedő legacy forrás | Csak címkézett, szintetikus reported XP; canonical_xp=null |
| REVIEWED_PROTOCOL_DATA | Célállapot: felülvizsgált, pontosan pinned forrás | Nincs jóváhagyott deploy/source registry; QUARANTINE |

A besorolások nem lépcsőfokok automatikus előléptetéssel. Verified wallet control
nem emeli a hozzá társított XP-forrás bizalmát. A mock proof kriptográfiailag
ellenőrizhető teszt-MAC-ja sem válik wallet-aláírássá vagy felhasználói consentté.

## Consent és életciklus

A mock consent a principal, profil, session, chain, contract, wallet/account,
protocol ID, scope, verzió, nonce, kiadás/lejárat, generation, epoch és
revocation_generation értékeit köti össze. A kiadó csak teszt-fixture builder.
A caller nem hozhat létre authority-t ezen mezők megadásával.

A 0A consent **egyszer használható disclosure-ticket**, nem tartós binding-consent.
A már kibocsátott kapcsolatot nem aktiválja, nem módosítja. `now == expires_at`
elutasítás; az érvényesség legfeljebb 300 fixture-másodperc. Ugyanaz a ticket
új request ID-val is replay. Audit-/authority-hiba előtt nem fogy el a ticket.
Response-vesztés után nincs automatikus adat-újraküldés: új ticket és request kell.
Azonos request ID eltérő, egyébként érvényes payloaddal konfliktus.

`bind` minden esetben nem végrehajtó döntés. Idegen profil DENY, saját profil
QUARANTINE. Nincs binding-írás, XP/Tier-írás, mint, burn, token- vagy governance-jog.

## Adatkiadás és audit

Verifier → user → független session → owner lookup → policy → primary-lock →
epoch/consent/source lookup → audit approval → friss session/policy/expiry/fence →
audit commit → ticket bookkeeping → szinkron fixture-delivery a zár alatt.

A visszatérő Decision nem újrahasználható adatkiadási capability. Adatot csak a
trusted, szinkron teszt-callback kap. A callback nem public transport vagy plugin.
Timeout, dependency-unavailable, UNKNOWN/REVOKED vagy audit-hiba nem ad adatot.
A read-before-revoke sorrend a zár alatt kiadott adatot engedi; revocation-first
tilt. Már kiadott byte nem vonható vissza. Külső Supabase signout nem atomikus ezzel.

Az audit 128 elemű bounded deque, pseudonym actorral, trace/request ID-val,
döntéssel, stabil reasonnel és source classificationnel. Nem tárol JWT-t,
kulcsot, raw principal/profile/wallet mezőt. ALLOW az autorizáció eseménye,
nem hálózati kézbesítési nyugta. Restart után nem durable; admin-proof állítás nincs.

## OctoGFLO adapter-mapping — implementáció nélkül

| Meglévő OctoGFLO típus | Pilot-kapcsolat | Integrációs döntés |
|---|---|---|
| WalletOwnershipVerifier | Wallet assurance | Csak mock; valós verifier BLOCKED |
| ConsentLinker | Consent/disclosure-ticket | Nem tartós link; requestLink nincs implementálva |
| IdentifierMap | Relation.protocol | Szerveroldali, saját profilra korlátozott lookup |
| SelectiveDisclosure | identity:read scope + owner policy | Nincs UI vagy production preference-írás |
| LinkRevocation / AccountRecovery | epoch/revocation_generation | Csak negatív fixture; valós recovery BLOCKED |
| CanonicalPieReader | reviewed protocol projection | BLOCKED: jelenleg kötelező canonicalXp:number, ami a 0A null értékét nem fogadhatja |

Később külön discriminated union kell: BLOCKED / DEMO_FIXTURE /
LEGACY_UNTRUSTED_XP / REVIEWED_PROTOCOL_DATA, nem `null → 0` coercion. A reviewed
ág sem ad jogosultságot pusztán historicalTier alapján; consumer-engedélyezéshez
külön effective entitlement-gate kell. A publikált alkalmazás változatlan maradt.
