package remediation

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

// These constants make the Observability authority boundary explicit in code.
// Proposal values may describe host symptoms, but this process cannot execute a
// host mutation or call Updater directly.
const (
	HostExecutionAuthority = false
	UpdaterDirectCall      = false
)

type ServiceType string

const (
	ServiceTypeControlPanel  ServiceType = "control_panel"
	ServiceTypeWorker        ServiceType = "worker"
	ServiceTypeEncoder       ServiceType = "encoder_recorder"
	ServiceTypeDiscordBot    ServiceType = "discord_bot"
	ServiceTypeObservability ServiceType = "observability"
)

type ProposalAction string

const (
	ProposalHostSystemd       ProposalAction = "host.systemd"
	ProposalHostDocker        ProposalAction = "host.docker"
	ProposalHostUpdate        ProposalAction = "host.update"
	ProposalHostBootstrap     ProposalAction = "host.bootstrap"
	ProposalHostPort          ProposalAction = "host.port"
	ProposalHostSelfUpdate    ProposalAction = "host.self_update"
	ProposalRetryGDriveUpload ProposalAction = "application.retry_gdrive_upload"
	ProposalRetryPackageRemux ProposalAction = "application.retry_package_remux"
)

type EvidenceCode string

const (
	EvidenceIncidentDetected     EvidenceCode = "incident_detected"
	EvidenceDiagnosticConfirmed  EvidenceCode = "diagnostic_confirmed"
	EvidenceRetryEligible        EvidenceCode = "retry_eligible"
	EvidenceHostSymptomConfirmed EvidenceCode = "host_symptom_confirmed"
)

type ProposalEvidence struct {
	EvidenceCode     EvidenceCode `json:"evidence_code"`
	ObservedAt       time.Time    `json:"observed_at"`
	ObservedRevision int64        `json:"observed_revision"`
	EvidenceDigest   string       `json:"evidence_digest,omitempty"`
}

type ProposalDetectorIdentity struct {
	ServiceID   string      `json:"service_id"`
	ServiceType ServiceType `json:"service_type"`
}

type ProposalTargetIdentity struct {
	ServiceID   string      `json:"service_id"`
	ServiceType ServiceType `json:"service_type"`
	HostID      string      `json:"host_id,omitempty"`
}

// Proposal deliberately has no executor, authorization/grant, URL, command,
// argv, environment, path, configuration, log, stdout, or stderr fields. It is
// evidence for Control Panel authorization, never execution authority.
type Proposal struct {
	ProposalID                        string                   `json:"proposal_id"`
	IncidentID                        string                   `json:"incident_id"`
	Detector                          ProposalDetectorIdentity `json:"detector"`
	Target                            ProposalTargetIdentity   `json:"target"`
	ActionType                        ProposalAction           `json:"action_type"`
	ProposalRevision                  int64                    `json:"proposal_revision"`
	RequiredCapability                ProposalAction           `json:"required_capability"`
	Evidence                          []ProposalEvidence       `json:"evidence"`
	AuditCorrelationID                string                   `json:"audit_correlation_id"`
	ObservedAt                        time.Time                `json:"observed_at"`
	ControlPanelAuthorizationRequired bool                     `json:"control_panel_authorization_required"`
}

var (
	boundedIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hostIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func (p Proposal) Validate() error {
	if !boundedIDPattern.MatchString(p.ProposalID) || !boundedIDPattern.MatchString(p.IncidentID) {
		return errors.New("proposal correlation identity is invalid")
	}
	if !boundedIDPattern.MatchString(p.Detector.ServiceID) || p.Detector.ServiceType != ServiceTypeObservability {
		return errors.New("proposal detector identity is invalid")
	}
	if !boundedIDPattern.MatchString(p.Target.ServiceID) || !validTargetServiceType(p.Target.ServiceType) {
		return errors.New("proposal target identity is invalid")
	}
	if p.Target.HostID != "" && !hostIDPattern.MatchString(p.Target.HostID) {
		return errors.New("proposal host identity is invalid")
	}
	if !validProposalAction(p.ActionType) || p.RequiredCapability != p.ActionType {
		return errors.New("proposal action or capability is invalid")
	}
	if isHostProposal(p.ActionType) && p.Target.HostID == "" {
		return errors.New("host proposal requires a host identity")
	}
	if isApplicationRetryProposal(p.ActionType) && p.Target.ServiceType != ServiceTypeEncoder {
		return errors.New("application retry proposal target is invalid")
	}
	if p.ProposalRevision < 1 || p.ObservedAt.IsZero() || !p.ControlPanelAuthorizationRequired {
		return errors.New("proposal revision or authorization boundary is invalid")
	}
	if !boundedIDPattern.MatchString(p.AuditCorrelationID) {
		return errors.New("proposal audit correlation identity is invalid")
	}
	if len(p.Evidence) == 0 || len(p.Evidence) > 32 {
		return errors.New("proposal evidence count is invalid")
	}
	for _, evidence := range p.Evidence {
		if !validEvidenceCode(evidence.EvidenceCode) || evidence.ObservedAt.IsZero() || evidence.ObservedRevision != p.ProposalRevision {
			return errors.New("proposal evidence is invalid")
		}
		if evidence.EvidenceDigest != "" && !digestPattern.MatchString(evidence.EvidenceDigest) {
			return errors.New("proposal evidence digest is invalid")
		}
	}
	return nil
}

// NewApplicationRetryProposal adapts the two retained application retry
// semantics into the typed v2 authority boundary. The proposal remains a
// request for Control Panel authorization; it is not a grant or execution.
func NewApplicationRetryProposal(action store.RemediationAction, incident store.Incident, detectorServiceID string, observedAt time.Time) (Proposal, error) {
	if strings.TrimSpace(action.ID) == "" || strings.TrimSpace(action.IncidentID) == "" || strings.TrimSpace(action.IncidentID) != strings.TrimSpace(incident.ID) {
		return Proposal{}, errors.New("remediation action and incident correlation is invalid")
	}
	if !IsBoundedCorrelationID(action.ID) || !IsBoundedCorrelationID(incident.ID) || !IsBoundedCorrelationID(incident.ServiceID) || !IsBoundedCorrelationID(incident.SignalID) || !IsBoundedCorrelationID(detectorServiceID) {
		return Proposal{}, errors.New("remediation proposal correlation is invalid")
	}
	actionType, ok := proposalActionForLegacyRetry(action.Action)
	if !ok {
		return Proposal{}, errors.New("legacy remediation action is not an application retry proposal")
	}
	if observedAt.IsZero() {
		observedAt = incident.UpdatedAt
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedAt = observedAt.UTC()
	revision := int64(incident.OccurrenceCount)
	if revision < 1 {
		revision = 1
	}
	proposal := Proposal{
		ProposalID: action.ID,
		IncidentID: incident.ID,
		Detector: ProposalDetectorIdentity{
			ServiceID:   strings.TrimSpace(detectorServiceID),
			ServiceType: ServiceTypeObservability,
		},
		Target: ProposalTargetIdentity{
			ServiceID:   strings.TrimSpace(incident.ServiceID),
			ServiceType: ServiceTypeEncoder,
		},
		ActionType:                        actionType,
		ProposalRevision:                  revision,
		RequiredCapability:                actionType,
		AuditCorrelationID:                action.ID,
		ObservedAt:                        observedAt,
		ControlPanelAuthorizationRequired: true,
	}
	proposal.Evidence = []ProposalEvidence{
		newProposalEvidence(EvidenceIncidentDetected, proposal, incident.SignalID),
		newProposalEvidence(EvidenceDiagnosticConfirmed, proposal, incident.SignalID),
		newProposalEvidence(EvidenceRetryEligible, proposal, incident.SignalID),
	}
	if err := proposal.Validate(); err != nil {
		return Proposal{}, err
	}
	return proposal, nil
}

func IsBoundedCorrelationID(value string) bool {
	return boundedIDPattern.MatchString(strings.TrimSpace(value))
}

func newProposalEvidence(code EvidenceCode, proposal Proposal, signalID string) ProposalEvidence {
	canonical := strings.Join([]string{
		string(code),
		proposal.ProposalID,
		proposal.IncidentID,
		proposal.Target.ServiceID,
		string(proposal.ActionType),
		strconv.FormatInt(proposal.ProposalRevision, 10),
		strings.TrimSpace(signalID),
	}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return ProposalEvidence{
		EvidenceCode:     code,
		ObservedAt:       proposal.ObservedAt,
		ObservedRevision: proposal.ProposalRevision,
		EvidenceDigest:   fmt.Sprintf("sha256:%x", digest),
	}
}

func proposalActionForLegacyRetry(action string) (ProposalAction, bool) {
	switch strings.TrimSpace(action) {
	case "retry_gdrive_upload":
		return ProposalRetryGDriveUpload, true
	case "retry_package_remux":
		return ProposalRetryPackageRemux, true
	default:
		return "", false
	}
}

func LegacyRetryAction(action ProposalAction) (string, bool) {
	switch action {
	case ProposalRetryGDriveUpload:
		return "retry_gdrive_upload", true
	case ProposalRetryPackageRemux:
		return "retry_package_remux", true
	default:
		return "", false
	}
}

func validProposalAction(action ProposalAction) bool {
	switch action {
	case ProposalHostSystemd, ProposalHostDocker, ProposalHostUpdate, ProposalHostBootstrap, ProposalHostPort, ProposalHostSelfUpdate,
		ProposalRetryGDriveUpload, ProposalRetryPackageRemux:
		return true
	default:
		return false
	}
}

func isHostProposal(action ProposalAction) bool {
	switch action {
	case ProposalHostSystemd, ProposalHostDocker, ProposalHostUpdate, ProposalHostBootstrap, ProposalHostPort, ProposalHostSelfUpdate:
		return true
	default:
		return false
	}
}

func isApplicationRetryProposal(action ProposalAction) bool {
	return action == ProposalRetryGDriveUpload || action == ProposalRetryPackageRemux
}

func validTargetServiceType(serviceType ServiceType) bool {
	switch serviceType {
	case ServiceTypeControlPanel, ServiceTypeWorker, ServiceTypeEncoder, ServiceTypeDiscordBot, ServiceTypeObservability:
		return true
	default:
		return false
	}
}

func validEvidenceCode(code EvidenceCode) bool {
	switch code {
	case EvidenceIncidentDetected, EvidenceDiagnosticConfirmed, EvidenceRetryEligible, EvidenceHostSymptomConfirmed:
		return true
	default:
		return false
	}
}

type LegacyActionClass uint8

const (
	LegacyActionUnknown LegacyActionClass = iota
	LegacyActionLocalTransition
	LegacyActionApplicationProposal
	LegacyActionHostProposalOnly
	LegacyActionForbidden
)

// ClassifyLegacyAction is the single closed bridge from persisted v1 action
// strings to the v2 boundary. Unknown values fail closed.
func ClassifyLegacyAction(action string) LegacyActionClass {
	action = strings.TrimSpace(action)
	if IsDangerous(action) {
		return LegacyActionForbidden
	}
	if IsLocalTransition(action) {
		return LegacyActionLocalTransition
	}
	if _, ok := proposalActionForLegacyRetry(action); ok {
		return LegacyActionApplicationProposal
	}
	switch action {
	case "restart_service", "restart_encoder_recorder", "restart_youtube_rtmps_output", "reconnect_discord_voice", "restart_discord_bot", "restart_worker":
		return LegacyActionHostProposalOnly
	default:
		return LegacyActionUnknown
	}
}
