# IU-WS5-01 notification Effect participation

This slice connects the existing `POST /notification-events` product Caller to
an explicitly injected fixture Effect participant. Requests without the
`X-Autostream-Lifecycle` header retain the existing v2 notifier, dedupe, retry,
history and response behavior. An explicit v3 request never falls back to it.
Normal startup does not inject the participant and returns
`notification_effect_not_connected` / `NOT_QUALIFIED` for the explicit path.

The shared module is
`github.com/Kome-Lab/Autostream-Contracts/v3lifecycle`, version
`v0.0.0-20261115145906-d32ea3514b1c`, commit
`d32ea3514b1c1010391caae0348b0ff9e751f447`. The original Contracts module pin,
Canonical/Binding/Evidence, existing API and diagnostic meanings are preserved.

## Product path and trusted boundary

The header carries the frozen CC07 Go-native `Record`, logical revision 1,
`G0-P-EFFECT-OUTCOME` revision 1. This internal fixture transport does not select
a production signing/wire, Root, clock, D4 or provider profile. The product owner
adapter must bind the complete original immutable request, current domain,
producer incarnation, channel target, policy/trust and Effect generation under
its local currentness guard. Request JSON cannot authorize dispatch.
The owner must also supply its explicit read frame. If journal state cannot be
observed, coverage is UNAVAILABLE and every unobserved Effect boundary remains
UNKNOWN; the response does not synthesize a persisted journal revision. An
authorization/currentness refusal returns no trusted coverage from request data.

The sequence is a durable one-attempt submission marker, intent commit, a fresh
owner/currentness check and dispatch-possible CAS. The owner guard and journal
transaction both end before the Provider port is called once. The port resolves
the non-secret `ContentRef` itself. Notification bodies, destinations, URLs and
credentials are not parameters to the journal or dispatch interface. A v3 Caller
does not copy or interpret the legacy body as a Provider receipt.

`FixtureEffectJournal` uses only a disposable explicit fixture namespace named
`notification-effects.fixture.json`. Exclusive file creation reserves the original
Effect; atomic file replacement under an exclusive lock serializes journal
transactions. Duplicate submissions inspect the original entry. The marker is
retained if intent/dispatch/result ACKs are lost, including when a journal row is
not visible. A crash-held transaction lock is never aged out or auto-released.
There is no standard-startup schema creation or migration.

The fixture observes file `Sync` and close, not power-loss, filesystem, host or
production Store durability qualification. File markers and locks need a future
qualified owner persistence adapter; they are not a selected production Store.
Restoring both the submission markers and journal together with the trusted
owner frame to the same past cannot be detected by equality of those restored
values. Independent freshness and real Store restore qualification remain
first-release blockers; the fixture is not a production exactly-once claim.

## Boundary results and lookup

The response is the frozen CC08 `Record`, not a new success boolean:

| Boundary | Meaning |
| --- | --- |
| `LOCAL_PERSISTENCE / INTENT` | Metadata intent is observed locally. |
| `LOCAL_PERSISTENCE / DISPATCH_POSSIBLE` | One Provider invocation may have occurred. |
| `PROVIDER / REMOTE_ACCEPT` | The synthetic adapter observed acceptance, refusal or UNKNOWN at that boundary. |
| `LOCAL_PERSISTENCE / LOCAL_RESULT_RECORD` | Local result recording is known or UNKNOWN independently of Provider acceptance. |

Acceptance is never `REMOTE_TERMINAL` or proof of user delivery. Provider ACK
loss remains UNKNOWN. A known acceptance is retained in the immediate response
when result recording is UNKNOWN; after restart, missing local evidence remains
unknown until the same original Effect can be observed. Historical known facts
that were saved are not erased by another unknown boundary. Every result keeps
`Gate=NOT_QUALIFIED`, user-delivery and production-qualification obligations.

`GET /v3/notification-effects/{effect}/{attempt}` requires the existing
`notifications.read` permission plus fresh trusted owner scope/currentness. Its
header must contain the original CC07 tuple. POST uses existing
`notifications.manage`. Wrong channel/Attempt/content/generation is refused.
Inspect reads only: no dispatch, intent write, reservation release, retry,
repair, new Attempt, hold release or old Authority reuse. Absence of a journal
entry is not evidence that an external action was not performed.

## Evidence map

All listed tests are mandatory in `scripts/ci/ws5-required-tests.txt`. The new
test-only `v3-notification-effect-checks` job preserves the existing CI and adds
native, Race and CGO-free required roots, full Go regression/vet/build, two Linux
cross-build targets, pin invariance and SourceBoundary checks. Cross-builds are
not native arm64 execution or an environment qualification.

| Scenario | Required roots |
| --- | --- |
| SC-OPS-006 / SC-CC-07 | `TestWS5EffectBoundaries`, `TestWS5EffectRefusal`, `TestWS5IntentRevocationBarrier`, `TestWS5EffectConcurrentClaim` |
| SC-OPS-006 / SC-CC-08 | `TestWS5EffectACKAndJournalUnknown`, `TestWS5EffectRestartNoRedispatch`, `TestWS5EffectIndependentProcessRestart`, `TestWS5EffectInspectPure` |
| SC-CC-07 / SC-CC-08 | `TestWS5EffectSecretIsolation`, `TestWS5FixedConsumerVectors` |
| SC-OPS-006 / SC-CC-08 | `TestWS5ExplicitUnconfiguredDoesNotFallback`, `TestWS5NotificationHTTPBoundaries`, `TestWS5NotificationHTTPCorrelation`, `TestWS5NotificationHTTPAuth` |

The independent inputs and expected boundary vectors are in
`internal/notifications/testdata`. Expected facts were specified from the frozen
contract, not generated from the candidate reducer. The real routed HTTP fixture
root can export actual observations for the CP renderer only when the test-only
`WS5_CROSS_RESULT_DIR` is supplied. It asserts the literal boundary oracle before
writing the three CC08 outputs with exclusive file creation.

## First-release blockers retained

Real SMTP/Webhook/provider delivery and lookup, qualified production intent
storage, workload authentication, provider retention/idempotency evidence, all
notification channels, remediation and actual user delivery remain unconnected
or unqualified. Fixture dispatch is not actual notification delivery or real
Evidence. No production Effect path is activated, and no automatic recovery,
replay, force-ready, new stop authority or post-v3 feature deferral is introduced.
