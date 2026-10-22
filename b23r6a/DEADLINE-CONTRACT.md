# R6A.1 authorization deadline

Anchor: `12e2df4c32ef51d08c799ec63a565c90221e8bcd`. Non-production only.

Authorization starts at entry to `Gateway.handle`, before parsing, UUID creation,
admission and identity verification. A server-created monotonic Budget expires
at start + at most **1.000 seconds**. Equality is expired. Request input cannot
increase it. An ALLOW is provisional until all remaining checks succeed.
Authorization ends with initial protected delivery under the local generation
fence and the final guarded return after cleanup. An ALLOW return is not a
reusable capability. No new protected ALLOW return or initial application-level
handoff is permitted when the sampled monotonic time is at/after expiration.

The same budget covers adapter startup, execution, decoding and reaping; request
ledger locking; primary fence acquisition; final independent session and policy
verification; summary construction; audit approval and local commit; response
construction/serialization/header preparation; and initial data delivery.
Initial JWT/user/session observations and final session/policy observations are
batched into separate read-only children (four process starts per full read,
instead of seven). Identity validation precedes downstream observations; the
parent still validates every returned record. No child survives its batch, and
the final batch remains after audit approval, under the primary fence.
Each worker batch/stage gets `min(400 ms, remaining budget)`, measured from before
process startup. Time spent cleaning up cannot yield a stale successful result.
Final checks run after local audit commit, before transport handoff and after
cleanup. A terminal timeout contains no protected payload and is never retried.

The HTTP transport carries the server-created budget through `HttpDelivery`.
It checks after serialization/header preparation, before flushing headers and
again before writing the protected JSON. Expiration after headers closes the
response without a protected body. A started write is never followed by a
second response or an automatic retry. A generic trusted synchronous callback
defines its initial handoff as invocation; transports that prepare asynchronously
or delay their first write must implement the budget-aware `prepare` contract.
Arbitrary user-provided callbacks are outside the trust model.

This is **not a hard real-time network-delivery guarantee**: Python scheduling,
kernel buffering, preemption between a check and syscall, and remote receipt are
outside it. Bytes accepted by a timely write cannot be recalled. A blocked write
has the remaining timeout; the connection has a distinct 3-second absolute
lifetime and 2-second inactivity bound. Headers and bodies may arrive later at
the peer. The tests prove guard placement and sampled application ordering,
not physical wire arrival time or a hard real-time process scheduler.

Adapter timeouts terminate/join then kill/join if necessary. The two cleanup
attempts are bounded (100 ms each); an unreapable worker seals the supervisor.
Cleanup/terminal denial may finish after authorization expiry, but cannot yield
ALLOW or a new protected release. Only trusted read-only offline adapters run;
they receive no domain credentials. Killing a process cannot undo an already
committed external write. Such adapters remain prohibited. Public minimal
health uses nonblocking best-effort events, independent of protected capacity.

The local event sink appends under a budgeted lock. An ALLOW event means an
authorization approval, **not proof of successful data receipt**. If subsequent
preparation/delivery/cleanup expires, the final outcome is QUARANTINE and a
best-effort terminal event is appended. An append already completed cannot be
undone; consumers must correlate trace IDs rather than infer delivery from an
ALLOW approval. A future external/durable sink needs its own cancellation,
commit-status and transactional contract; this implementation provides none.

`test_exact_1857ms_old_allow_becomes_quarantine` loads the exact historical
gateway and advances a controlled monotonic clock to 1.857 s: old ALLOW with
data, new QUARANTINE with zero protected release. This deterministic diagnostic
is separate from the unchanged Pilot 0A real-process historical reproduction
(whose measured elapsed time varies). Further tests expire final session,
policy, fence acquisition, audit, response preparation, initial write and
cleanup. Original process cancellation/capacity and HTTP race tests remain
byte-identical. Production Supabase authority and persistent fencing remain BLOCKED.
