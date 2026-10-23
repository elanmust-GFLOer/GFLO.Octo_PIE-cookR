# Worker lifecycle correction — isolated security candidate

Reference: causal reproducer `cbc4cbdaa3c6cb80aa797e3f91b3dc0000a680a8`, cookR draft PR #18. No production integration, migration, wallet operation or merge is authorized. Pilot 0D-2 remains HOLD.

## Root cause to patch

| Proven cause / risk | Exact correction | Named evidence |
|---|---|---|
| `BaseProcess.start()` invokes global `_cleanup()`, which polls other threads' children. OS reaping can precede cached exitcode publication. | `b23r6a/process_lifecycle.py`: each owned child has its own `RLock`; every owner/global-cleanup `Popen.poll()` performs nonblocking `waitpid` and cache publication inside that lock. No stdlib monkeypatch or global work lock. | `test_waitpid_and_cache_publication_have_one_owner`; `test_global_cleanup_and_owner_share_real_child_state` |
| A readable exit sentinel can briefly precede a waitable OS status. A one-shot nonblocking replacement can falsely report failed cleanup. | The owned `wait(timeout)` repeatedly calls atomic nonblocking poll within the existing join budget. It never substitutes blocking `waitpid(0)`. | `test_join_retries_nonwaitable_exit_without_losing_budget`; `test_join_of_live_child_remains_bounded`; the first local candidate failed, and that failure is retained. |
| Signal-versus-reaping race can make a reaped PID a signal target. | Signal-state check and delivery use the same per-child lock. Cached reaped children are not signaled. | `test_reaped_pid_is_never_signaled` |
| Accounting formerly disappeared before `process.close()`. | `workers.py` removes the PID only after confirmed termination/reaping **and successful close**. Cleanup/close exceptions poison future admission and retain accounting. Parent pipe endpoints close even on failure. | `test_capacity_is_released_only_after_close`; `test_close_failure_retains_capacity_and_poisoned_admission`; `test_unkillable_child_retains_capacity_and_poisoned_admission` |
| Spawn can raise after OS child creation, before returning its handle. | The owned factory retains that partial handle on exception; the supervisor records it, runs bounded cleanup, and poisons admission after any startup failure. | `test_spawn_factory_retains_postlaunch_failure_handle`; `test_postlaunch_exception_reaps_real_child_and_blocks_admission`; `test_prelaunch_exception_blocks_further_process_admission` |
| A broad lock could hide the race by eliminating concurrency. | Different children have independent locks; adapter execution, waiting and separate children remain concurrent. | `test_distinct_child_poll_is_not_globally_serialized`; two real child adapters rendezvous at a shared barrier under the unchanged `.4` stage limit in `test_real_children_execute_concurrently_under_stage_limit`. |
| Worker cleanup cannot expand authorization validity. | No gateway, deadline, generation, audit, consent, policy or delivery implementation changed. Existing `.4` stage, `.1` cleanup joins, and maximum 1-second current authorization budget remain. Cleanup time is still charged before returning a worker result. | Original deadline 25, gateway 42, HTTP 13, crypto 96, units 22 and browser/HTTP 50 retain their identities and assertions. |

`OwnedSpawnContext` is local to each supervisor; it does not mutate the standard `multiprocessing` context singleton. Existing unowned processes, including the raw causal reproducer and the historical checkout, remain unchanged. All multiprocessing lifecycle paths for an owned child reach its overridden poll. Arbitrary foreign `os.waitpid()` callers, privileged host interference and unsupported runtimes are outside this ownership contract.

The implementation deliberately uses a narrow private CPython spawn/Popen seam. Its supported profile is **Linux, CPython 3.12**; other profiles fail before spawn. CI records the exact interpreter and SHA-256 of the participating stdlib modules. This is a reviewed runtime dependency boundary, not portability or production approval. No external Python/npm/crypto dependency is added by the lifecycle patch.

## Exact scope

Only the existing `b23r6a/workers.py` runtime file changes relative to the causal commit. The new `b23r6a/process_lifecycle.py` supplies ownership. New `workerclosure/**` files and its dedicated workflow provide tests, provenance, evidence retention and read-only planning. Every other inherited tracked blob, including all test/SQL sources, package lockfiles, 41 frozen files, consent UI and frontend/server contracts, is checked unchanged.

The genuine-unkillable control is an injected process object that remains alive after terminate, kill and both original joins. It proves fail-closed result/accounting/admission behavior; no dangerous kernel D-state process is created. The late-side-effect control uses a real terminated child. There is no hard real-time OS scheduling claim.

## Reproduction and full-suite accounting

Local CPU-only controls:

```sh
PYTHONPATH=. python3 workerclosure/test_lifecycle.py
python3 pilot0d1/reaping-cause.py
```

The first command requires the historical Git object for its separation control. CI uses full-history checkout; a shallow local checkout must supply the genuine object, never fabricate a passing anchor. The test refuses a missing object. The second command intentionally reproduces the **raw, unpatched stdlib** race; its PASS demonstrates the old failure mechanism, not a bypass in the corrected owned process.

The dedicated workflow predeclares three independent regression cohorts on separate disposable runners/PostgreSQL services, plus the existing browser job in its immutable, network-disabled container. It has no retry-until-green logic. Each cohort runs every suite independently, so a historical failure cannot suppress the later 96 crypto, 22 units or new controls. Original suite runners/assertions are unchanged.

Each cohort inventories 343 exact names: 148 Python/PostgreSQL + 59 historical + 96 crypto + 22 units + 17 lifecycle + 1 separately classified raw causal probe. The independent browser job adds 50 names, giving **393 unique names** across the two jobs. Repeated cohorts do not become new unique tests. SQL and strict TypeScript are separate gates. Skips, errors and not-executed cases remain explicit.

`workerclosure-complete-ledger.json` records every test and command exit. `status` remains FAIL if the historical gate fails; `current_code` separately reports the corrected runtime's results. This distinction is an observation, **not an accepted historical waiver**. See [historical policy](HISTORICAL-ACCEPTANCE.md).

`run_historical.py` copies the immutable snapshot to a disposable directory, removes only that disposable copy's pre-existing archived ledger to prevent stale PASS reuse, and runs the original verifier once against its exact historical worktree. The original archived evidence stays untouched. A newly generated historical ledger is copied **byte-for-byte** to `workerclosure-historical-raw-ledger.json`; separate metadata records its digest and source. Failed results and logs survive worktree cleanup.

The runner never runs a schema outside its fresh loopback PostgreSQL service. No migration file, grant, production connection or permission-restoration change is part of this patch.

## Review limits and verdicts

The code and named controls are a security correction candidate. Independent review must assess the private Popen seam, all lifecycle paths, lock hold times, signal ordering, supported-runtime policy, accounting retention, and remaining host/kernel trust. Historical acceptance and AUD-01 / INV-10 remain separately reviewable blockers. A green cohort never erases a red cohort or old evidence.

Laboratory: current-code functional results may pass while aggregate historical acceptance remains CONDITIONAL/BLOCKED. Staging: BLOCK. Production: BLOCK. Main: no merge recommendation until the independent review and explicit laboratory-only integration policy in [the dependency matrix](INTEGRATION-READINESS.md) are accepted. Pilot 0D-2: HOLD.
