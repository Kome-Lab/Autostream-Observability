package remediation

import (
	"errors"
	"strings"
	"testing"
)

func TestApplyLocalTransitionUsesRevisionFenceAndIdempotency(t *testing.T) {
	state := LocalTransitionState{Revision: 7, Fence: 3, StaleWarning: true}
	transition := LocalTransition{
		ActionID:           "action-1",
		ActionType:         LocalRefreshServiceStatus,
		ExpectedRevision:   7,
		Fence:              4,
		IdempotencyKey:     "incident-1:refresh:7",
		AuditCorrelationID: "audit-1",
	}
	result, err := ApplyLocalTransition(state, transition)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.State.Revision != 8 || result.State.Fence != 4 || result.State.StatusRefreshRevision != 1 || !result.State.StaleWarning {
		t.Fatalf("unexpected local transition state: %#v", result)
	}
	replay, err := ApplyLocalTransition(result.State, transition)
	if err != nil || !replay.Replayed || !reflectLocalStateEqual(replay.State, result.State) {
		t.Fatalf("identical idempotent replay changed state: result=%#v err=%v", replay, err)
	}

	conflict := transition
	conflict.ActionType = LocalRerunDiagnostics
	if _, err := ApplyLocalTransition(result.State, conflict); !errors.Is(err, ErrLocalIdempotencyConflict) {
		t.Fatalf("same idempotency key with another request must conflict: %v", err)
	}
	second := LocalTransition{ActionID: "action-2", ActionType: LocalRerunDiagnostics, ExpectedRevision: 8, Fence: 5, IdempotencyKey: "incident-1:diagnose:8", AuditCorrelationID: "audit-2"}
	secondResult, err := ApplyLocalTransition(result.State, second)
	if err != nil {
		t.Fatal(err)
	}
	olderReplay, err := ApplyLocalTransition(secondResult.State, transition)
	if err != nil || !olderReplay.Replayed || !reflectLocalStateEqual(olderReplay.State, secondResult.State) {
		t.Fatalf("older idempotency key was not retained: result=%#v err=%v", olderReplay, err)
	}
}

func TestApplyLocalTransitionRejectsStaleRevisionAndFence(t *testing.T) {
	state := LocalTransitionState{Revision: 5, Fence: 9}
	base := LocalTransition{ActionID: "action-1", ActionType: LocalRerunDiagnostics, ExpectedRevision: 4, Fence: 10, IdempotencyKey: "retry-1", AuditCorrelationID: "audit-1"}
	if _, err := ApplyLocalTransition(state, base); !errors.Is(err, ErrLocalRevisionConflict) {
		t.Fatalf("stale revision was not rejected: %v", err)
	}
	base.ExpectedRevision = 5
	base.Fence = 9
	if _, err := ApplyLocalTransition(state, base); !errors.Is(err, ErrLocalStaleFence) {
		t.Fatalf("stale fence was not rejected: %v", err)
	}
}

func TestLocalTransitionValidateUsesUnicodeCharacterLength(t *testing.T) {
	base := LocalTransition{
		ActionID:           "action-1",
		ActionType:         LocalRerunDiagnostics,
		ExpectedRevision:   1,
		Fence:              1,
		AuditCorrelationID: "audit-1",
	}
	tests := []struct {
		name           string
		idempotencyKey string
		wantValid      bool
	}{
		{name: "ASCII 128 characters", idempotencyKey: strings.Repeat("a", 128), wantValid: true},
		{name: "ASCII 129 characters", idempotencyKey: strings.Repeat("a", 129), wantValid: false},
		{name: "multibyte 128 characters", idempotencyKey: strings.Repeat("界", 128), wantValid: true},
		{name: "multibyte 129 characters", idempotencyKey: strings.Repeat("界", 129), wantValid: false},
		{name: "empty", idempotencyKey: "", wantValid: false},
		{name: "ASCII control character", idempotencyKey: "valid\ninvalid", wantValid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transition := base
			transition.IdempotencyKey = test.idempotencyKey
			err := transition.Validate()
			if (err == nil) != test.wantValid {
				t.Fatalf("Validate() error = %v, want valid = %t", err, test.wantValid)
			}
		})
	}
}

func TestApplyLocalTransitionEffectsAreEnumerated(t *testing.T) {
	tests := []struct {
		action LocalAction
		check  func(LocalTransitionState) bool
	}{
		{LocalRefreshServiceStatus, func(state LocalTransitionState) bool { return state.StatusRefreshRevision == 1 }},
		{LocalRerunDiagnostics, func(state LocalTransitionState) bool { return state.DiagnosticsRevision == 1 }},
		{LocalClearStaleWarning, func(state LocalTransitionState) bool { return !state.StaleWarning }},
	}
	for index, test := range tests {
		state := LocalTransitionState{Revision: 1, StaleWarning: true}
		result, err := ApplyLocalTransition(state, LocalTransition{
			ActionID:           "action-1",
			ActionType:         test.action,
			ExpectedRevision:   1,
			Fence:              1,
			IdempotencyKey:     "key-" + string(rune('a'+index)),
			AuditCorrelationID: "audit-1",
		})
		if err != nil || !test.check(result.State) {
			t.Fatalf("local action %q did not apply its bounded transition: result=%#v err=%v", test.action, result, err)
		}
	}
	for _, forbidden := range []LocalAction{"host.systemd", "host.docker", "package.install", "filesystem.write", "host.port", "host.self_update", "configure", "migration", "updater.call"} {
		invalid := LocalTransition{ActionID: "action-1", ActionType: forbidden, ExpectedRevision: 1, Fence: 1, IdempotencyKey: "key-z", AuditCorrelationID: "audit-1"}
		if _, err := ApplyLocalTransition(LocalTransitionState{Revision: 1}, invalid); err == nil {
			t.Fatalf("%q must not be representable as a local transition", forbidden)
		}
	}
}

func reflectLocalStateEqual(left, right LocalTransitionState) bool {
	return left.Revision == right.Revision &&
		left.Fence == right.Fence &&
		left.StatusRefreshRevision == right.StatusRefreshRevision &&
		left.DiagnosticsRevision == right.DiagnosticsRevision &&
		left.StaleWarning == right.StaleWarning &&
		reflectAppliedRequestsEqual(left.appliedRequests, right.appliedRequests)
}

func reflectAppliedRequestsEqual(left, right map[string][32]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for key, digest := range left {
		if right[key] != digest {
			return false
		}
	}
	return true
}
