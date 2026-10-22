<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Architecture rules
- All simulation logic lives in pure functions under src/domain (no I/O, injected clock) so rules stay deterministic and testable.
- UI strings live in src/i18n/en.ts and hu.ts with identical keys; a test enforces parity.
- MVP 01 has no backend, wallet, chain or third-party integrations; every screen shows DEMO labels.
- Invalid simulated inputs fail closed: the engine logs an INVALID event and leaves claims, clock and XP unchanged; mock checks are never presented as real cryptographic verification.
- src/domain/octopass-adapters.ts holds future OctoPass interfaces as types only; none may write canonical XP.
- External platform links (e.g. OctoPush) are navigation-only via src/lib/links.ts; never share auth, identity, wallet or XP state.
- /evidence is English-only by design and holds a dated, hand-curated snapshot of real GitHub references in src/domain/evidence.ts; never fetch live data or present it as simulated.
