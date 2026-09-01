package remediation

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/diagnostics"
	"github.com/example/autostream-observability/internal/store"
)

func TestNewApplicationRetryProposalUsesBoundedTypedEvidence(t *testing.T) {
	observedAt := time.Date(2026, time.August, 31, 12, 30, 0, 0, time.UTC)
	proposal, err := NewApplicationRetryProposal(
		store.RemediationAction{ID: "action-1", IncidentID: "incident-1", Action: "retry_gdrive_upload"},
		store.Incident{
			ID:              "incident-1",
			ServiceID:       "encoder-1",
			SignalID:        "signal-1",
			OccurrenceCount: 3,
			Report: diagnostics.Report{Evidence: []string{
				"SENSITIVE_MARKER",
				"https://updater.invalid/internal",
				"C:/host/private/config",
			}},
		},
		"observability-1",
		observedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.ActionType != ProposalRetryGDriveUpload || proposal.RequiredCapability != proposal.ActionType || proposal.ProposalRevision != 3 {
		t.Fatalf("unexpected typed proposal: %#v", proposal)
	}
	if proposal.Detector.ServiceType != ServiceTypeObservability || proposal.Target.ServiceType != ServiceTypeEncoder || !proposal.ControlPanelAuthorizationRequired {
		t.Fatalf("proposal authority identities are invalid: %#v", proposal)
	}
	if len(proposal.Evidence) != 3 {
		t.Fatalf("expected detect, diagnose, and eligibility evidence: %#v", proposal.Evidence)
	}
	for _, evidence := range proposal.Evidence {
		if evidence.ObservedRevision != 3 || !digestPattern.MatchString(evidence.EvidenceDigest) {
			t.Fatalf("unbounded proposal evidence: %#v", evidence)
		}
	}
	body, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"SENSITIVE_MARKER", "updater.invalid", "host/private", "executor", "authorization_id", "grant", "stdout", "stderr", "argv", "environment"} {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(forbidden)) {
			t.Fatalf("proposal represented forbidden data %q: %s", forbidden, body)
		}
	}
}

func TestApplicationRetryProposalRejectsUnknownLegacyAction(t *testing.T) {
	_, err := NewApplicationRetryProposal(
		store.RemediationAction{ID: "action-1", IncidentID: "incident-1", Action: "run_arbitrary_command"},
		store.Incident{ID: "incident-1", ServiceID: "encoder-1", SignalID: "signal-1", OccurrenceCount: 1},
		"observability-1",
		time.Now(),
	)
	if err == nil {
		t.Fatal("unknown legacy action must fail closed")
	}
	_, err = NewApplicationRetryProposal(
		store.RemediationAction{ID: "action-1", IncidentID: "different-incident", Action: "retry_gdrive_upload"},
		store.Incident{ID: "incident-1", ServiceID: "encoder-1", SignalID: "signal-1", OccurrenceCount: 1},
		"observability-1",
		time.Now(),
	)
	if err == nil {
		t.Fatal("mismatched action and incident correlation must fail closed")
	}
}

func TestProposalValidationSeparatesHostAndApplicationTargets(t *testing.T) {
	observedAt := time.Date(2026, time.August, 31, 12, 30, 0, 0, time.UTC)
	base := Proposal{
		ProposalID:                        "proposal-1",
		IncidentID:                        "incident-1",
		Detector:                          ProposalDetectorIdentity{ServiceID: "observability-1", ServiceType: ServiceTypeObservability},
		Target:                            ProposalTargetIdentity{ServiceID: "worker-1", ServiceType: ServiceTypeWorker},
		ActionType:                        ProposalHostSystemd,
		ProposalRevision:                  1,
		RequiredCapability:                ProposalHostSystemd,
		Evidence:                          []ProposalEvidence{{EvidenceCode: EvidenceHostSymptomConfirmed, ObservedAt: observedAt, ObservedRevision: 1}},
		AuditCorrelationID:                "audit-1",
		ObservedAt:                        observedAt,
		ControlPanelAuthorizationRequired: true,
	}
	if err := base.Validate(); err == nil {
		t.Fatal("host proposal without host identity must be rejected")
	}
	base.Target.HostID = "host-1"
	if err := base.Validate(); err != nil {
		t.Fatalf("bounded host proposal should validate: %v", err)
	}
	base.Evidence[0].ObservedRevision = 2
	if err := base.Validate(); err == nil {
		t.Fatal("evidence from another proposal revision must be rejected")
	}
	base.Evidence[0].ObservedRevision = 1
	base.ActionType = ProposalRetryPackageRemux
	base.RequiredCapability = ProposalRetryPackageRemux
	if err := base.Validate(); err == nil {
		t.Fatal("application retry aimed at Worker must be rejected")
	}
}

func TestLegacyActionClassificationIsClosed(t *testing.T) {
	tests := map[string]LegacyActionClass{
		"refresh_service_status": LegacyActionLocalTransition,
		"rerun_diagnostics":      LegacyActionLocalTransition,
		"clear_stale_warning":    LegacyActionLocalTransition,
		"retry_gdrive_upload":    LegacyActionApplicationProposal,
		"retry_package_remux":    LegacyActionApplicationProposal,
		"restart_worker":         LegacyActionHostProposalOnly,
		"delete_archives":        LegacyActionForbidden,
		"configure":              LegacyActionUnknown,
		"migration":              LegacyActionUnknown,
		"run_arbitrary_command":  LegacyActionUnknown,
	}
	for action, want := range tests {
		if got := ClassifyLegacyAction(action); got != want {
			t.Fatalf("ClassifyLegacyAction(%q) = %v, want %v", action, got, want)
		}
	}
	if HostExecutionAuthority || UpdaterDirectCall {
		t.Fatal("Observability must have zero host execution and direct Updater authority")
	}
}

func TestProposalShapeCannotCarryExecutionMaterial(t *testing.T) {
	shapes := map[reflect.Type][]string{
		reflect.TypeOf(Proposal{}):                 {"proposal_id", "incident_id", "detector", "target", "action_type", "proposal_revision", "required_capability", "evidence", "audit_correlation_id", "observed_at", "control_panel_authorization_required"},
		reflect.TypeOf(ProposalDetectorIdentity{}): {"service_id", "service_type"},
		reflect.TypeOf(ProposalTargetIdentity{}):   {"service_id", "service_type", "host_id,omitempty"},
		reflect.TypeOf(ProposalEvidence{}):         {"evidence_code", "observed_at", "observed_revision", "evidence_digest,omitempty"},
		reflect.TypeOf(LocalTransition{}):          {"action_id", "action_type", "expected_revision", "fence", "idempotency_key", "audit_correlation_id"},
	}
	for typ, expectedFields := range shapes {
		if typ.NumField() != len(expectedFields) {
			t.Fatalf("%s gained an unreviewed field: got %d want %d", typ.Name(), typ.NumField(), len(expectedFields))
		}
		for index, expected := range expectedFields {
			if got := typ.Field(index).Tag.Get("json"); got != expected {
				t.Fatalf("%s field %d JSON name = %q, want %q", typ.Name(), index, got, expected)
			}
		}
	}
}
