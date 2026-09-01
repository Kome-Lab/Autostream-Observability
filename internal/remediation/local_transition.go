package remediation

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type LocalAction string

const (
	LocalRefreshServiceStatus LocalAction = "refresh_service_status"
	LocalRerunDiagnostics     LocalAction = "rerun_diagnostics"
	LocalClearStaleWarning    LocalAction = "clear_stale_warning"
)

var (
	ErrLocalRevisionConflict    = errors.New("local remediation revision conflict")
	ErrLocalStaleFence          = errors.New("local remediation fence is stale")
	ErrLocalIdempotencyConflict = errors.New("local remediation idempotency conflict")
	idempotencyPattern          = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
)

// LocalTransition is the complete Observability-local execution surface. Its
// closed LocalAction enum cannot encode host, process, filesystem, package,
// port, self-update, shell, argv, path, or environment operations.
type LocalTransition struct {
	ActionID           string      `json:"action_id"`
	ActionType         LocalAction `json:"action_type"`
	ExpectedRevision   int64       `json:"expected_revision"`
	Fence              int64       `json:"fence"`
	IdempotencyKey     string      `json:"idempotency_key"`
	AuditCorrelationID string      `json:"audit_correlation_id"`
}

type LocalTransitionState struct {
	Revision              int64 `json:"revision"`
	Fence                 int64 `json:"fence"`
	StatusRefreshRevision int64 `json:"status_refresh_revision"`
	DiagnosticsRevision   int64 `json:"diagnostics_revision"`
	StaleWarning          bool  `json:"stale_warning"`

	appliedRequests map[string][sha256.Size]byte
}

type LocalTransitionResult struct {
	State    LocalTransitionState
	Replayed bool
}

func (transition LocalTransition) Validate() error {
	if !boundedIDPattern.MatchString(transition.ActionID) || !boundedIDPattern.MatchString(transition.AuditCorrelationID) {
		return errors.New("local remediation correlation identity is invalid")
	}
	if !validLocalAction(transition.ActionType) {
		return errors.New("local remediation action is unsupported")
	}
	if transition.ExpectedRevision < 1 || transition.Fence < 1 {
		return errors.New("local remediation revision or fence is invalid")
	}
	idempotencyKeyLength := utf8.RuneCountInString(transition.IdempotencyKey)
	if idempotencyKeyLength == 0 || idempotencyKeyLength > 128 || !idempotencyPattern.MatchString(transition.IdempotencyKey) {
		return errors.New("local remediation idempotency key is invalid")
	}
	return nil
}

// ApplyLocalTransition is a pure CAS transition. The Observability-local owner
// must atomically persist the returned state; no host or cross-service side
// effect is performed here.
func ApplyLocalTransition(state LocalTransitionState, transition LocalTransition) (LocalTransitionResult, error) {
	if err := transition.Validate(); err != nil {
		return LocalTransitionResult{State: state}, err
	}
	digest := localTransitionDigest(transition)
	if previousDigest, ok := state.appliedRequests[transition.IdempotencyKey]; ok {
		if digest != previousDigest {
			return LocalTransitionResult{State: state}, ErrLocalIdempotencyConflict
		}
		return LocalTransitionResult{State: state, Replayed: true}, nil
	}
	if transition.ExpectedRevision != state.Revision {
		return LocalTransitionResult{State: state}, ErrLocalRevisionConflict
	}
	if transition.Fence <= state.Fence {
		return LocalTransitionResult{State: state}, ErrLocalStaleFence
	}

	next := state
	switch transition.ActionType {
	case LocalRefreshServiceStatus:
		next.StatusRefreshRevision++
	case LocalRerunDiagnostics:
		next.DiagnosticsRevision++
	case LocalClearStaleWarning:
		next.StaleWarning = false
	default:
		return LocalTransitionResult{State: state}, errors.New("local remediation action is unsupported")
	}
	next.Revision++
	next.Fence = transition.Fence
	next.appliedRequests = make(map[string][sha256.Size]byte, len(state.appliedRequests)+1)
	for key, appliedDigest := range state.appliedRequests {
		next.appliedRequests[key] = appliedDigest
	}
	next.appliedRequests[transition.IdempotencyKey] = digest
	return LocalTransitionResult{State: next}, nil
}

func IsLocalTransition(action string) bool {
	_, ok := LocalActionForLegacyAction(action)
	return ok
}

func LocalActionForLegacyAction(action string) (LocalAction, bool) {
	switch strings.TrimSpace(action) {
	case string(LocalRefreshServiceStatus):
		return LocalRefreshServiceStatus, true
	case string(LocalRerunDiagnostics):
		return LocalRerunDiagnostics, true
	case string(LocalClearStaleWarning):
		return LocalClearStaleWarning, true
	default:
		return "", false
	}
}

func validLocalAction(action LocalAction) bool {
	switch action {
	case LocalRefreshServiceStatus, LocalRerunDiagnostics, LocalClearStaleWarning:
		return true
	default:
		return false
	}
}

func localTransitionDigest(transition LocalTransition) [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		transition.ActionID,
		string(transition.ActionType),
		strconv.FormatInt(transition.ExpectedRevision, 10),
		strconv.FormatInt(transition.Fence, 10),
		transition.IdempotencyKey,
		transition.AuditCorrelationID,
	}, "\n")))
}
