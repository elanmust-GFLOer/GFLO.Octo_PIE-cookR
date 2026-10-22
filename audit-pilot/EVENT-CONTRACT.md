# Sanitized decision events

Source: R6A offline gateway only. Environment marker: R6A-OFFLINE.
Allowlisted fields: environment, trace_id, request_id, decision, reason_code,
operation, actor_pseudonym, session_pseudonym. Unknown operations become unknown.
Actor/session pseudonyms use per-process random HMAC keys and are not durable
cross-environment identifiers. No JWT, cookie, key, request payload, raw subject,
session UUID, wallet address, exception text or production data is emitted.

Trace/request IDs correlate authorization decisions. Request IDs are untrusted
correlation labels, not identity proof. ALLOW means permission to attempt the
bounded read; it is not proof that transport delivery completed. Audit approval
and the parent sink commit precede any protected payload release. Sink failure
quarantines the read. Terminal DENY/QUARANTINE recording is best effort during
sink failure; it never authorizes fallback data release.

The separate synthetic deque retains at most 4096 events in memory. Restart
loses events/pseudonym keys. Summaries disclose only environment/counts. No
claim of immutable, durable, administrator-proof or production audit integrity.
A future deployment needs approved retention, key rotation, encryption, access
reviews, attribution, tamper evidence and out-of-band privileged access auditing.
