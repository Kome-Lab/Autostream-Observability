package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/remediation"
	"github.com/example/autostream-observability/internal/store"
)

type controlExecutor interface {
	ExecuteRemediationProposal(ctx context.Context, proposal remediation.Proposal, streamID string) error
}

type envControlExecutor struct{}

func (envControlExecutor) ExecuteRemediationProposal(ctx context.Context, proposal remediation.Proposal, streamID string) error {
	return control.FromEnv().ExecuteRemediationProposal(ctx, proposal, streamID)
}

func (s *Server) listRemediationActions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationRead) {
		return
	}
	actions, err := s.store.ListRemediationActions(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_remediation_actions_failed"})
		return
	}
	writeJSON(w, http.StatusOK, actions)
}

type remediationDispatchContextResponse struct {
	ActionID       string `json:"action_id"`
	Action         string `json:"action"`
	ActionStatus   string `json:"action_status"`
	IncidentID     string `json:"incident_id"`
	IncidentStatus string `json:"incident_status"`
	StreamID       string `json:"stream_id"`
	Executable     bool   `json:"executable"`
}

func (s *Server) getRemediationDispatchContext(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationRead) {
		return
	}
	action, err := s.store.GetRemediationAction(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_remediation_action_failed"})
		return
	}
	incident, err := s.store.GetIncident(r.Context(), action.IncidentID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "incident_context_missing"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_incident_failed"})
		return
	}
	if strings.TrimSpace(incident.StreamID) == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "stream_context_missing"})
		return
	}
	if remediation.IsTerminalStatus(action.Status) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "remediation_action_terminal"})
		return
	}
	if !remediationActionDispatchExecutable(action) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "remediation_action_not_executable"})
		return
	}
	writeJSON(w, http.StatusOK, remediationDispatchContextResponse{
		ActionID:       action.ID,
		Action:         action.Action,
		ActionStatus:   action.Status,
		IncidentID:     incident.ID,
		IncidentStatus: incident.Status,
		StreamID:       incident.StreamID,
		Executable:     true,
	})
}

func remediationActionDispatchExecutable(action store.RemediationAction) bool {
	if remediation.IsTerminalStatus(action.Status) || remediation.IsDangerous(action.Action) || !requiresControlPanelDispatch(action.Action) {
		return false
	}
	mode := remediation.NormalizeMode(action.Mode)
	if mode == remediation.ModeDisabled || mode == remediation.ModeSuggestOnly {
		return false
	}
	if mode == remediation.ModeManualApproval && action.Status != "approved" {
		return false
	}
	if action.RequiresApproval && action.Status != "approved" {
		return false
	}
	return action.SafeAuto || action.RequiresApproval
}

func (s *Server) approveRemediationAction(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationApprove) {
		return
	}
	action, err := s.store.GetRemediationAction(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_remediation_action_failed"})
		return
	}
	action = remediation.Approve(action)
	action, err = s.store.UpdateRemediationAction(r.Context(), action)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "approve_remediation_action_failed"})
		return
	}
	writeJSON(w, http.StatusOK, action)
}

func (s *Server) executeRemediationAction(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationExecute) {
		return
	}
	action, err := s.store.GetRemediationAction(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_remediation_action_failed"})
		return
	}
	if remediation.IsTerminalStatus(action.Status) {
		action.Result = "remediation action is already terminal"
		writeJSON(w, http.StatusConflict, action)
		return
	}
	action = remediation.Execute(action)
	if action.Status == "executed" && requiresControlPanelDispatch(action.Action) {
		incident, err := s.store.GetIncident(r.Context(), action.IncidentID)
		if err != nil {
			action.Status = "blocked"
			action.Result = "incident context is required for control panel dispatch"
			action.ExecutedAt = nil
		} else if strings.TrimSpace(incident.StreamID) == "" {
			action.Status = "blocked"
			action.Result = "stream_id is required for control panel dispatch"
			action.ExecutedAt = nil
		} else if err := s.dispatchApplicationRetryProposal(r.Context(), action, incident); err != nil {
			action.Status = "blocked"
			action.Result = "control panel dispatch failed"
			action.ExecutedAt = nil
		} else {
			action.Result = "control_panel_dispatch_executed"
			if action.ExecutedAt == nil {
				now := time.Now().UTC()
				action.ExecutedAt = &now
			}
		}
	}
	action, err = s.store.UpdateRemediationAction(r.Context(), action)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "execute_remediation_action_failed"})
		return
	}
	if action.Status == "executed" {
		if incident, incidentErr := s.store.GetIncident(r.Context(), action.IncidentID); incidentErr == nil {
			s.notifyIncidentEvent(r, "remediation.executed", incident)
		}
	}
	status := http.StatusOK
	if action.Status == "blocked" {
		status = http.StatusForbidden
	}
	writeJSON(w, status, action)
}

func (s *Server) dispatchApplicationRetryProposal(ctx context.Context, action store.RemediationAction, incident store.Incident) error {
	if s.executor == nil {
		return errors.New("control panel proposal dispatch is not configured")
	}
	identity, err := s.updaterIdentity.ResolveFromEnv()
	if err != nil {
		return err
	}
	proposal, err := remediation.NewApplicationRetryProposal(action, incident, identity.ServiceID, time.Now().UTC())
	if err != nil {
		return err
	}
	return s.executor.ExecuteRemediationProposal(ctx, proposal, incident.StreamID)
}

func requiresControlPanelDispatch(action string) bool {
	return remediation.ClassifyLegacyAction(action) == remediation.LegacyActionApplicationProposal
}

func (s *Server) createRemediationActions(r *http.Request, incident store.Incident) error {
	for _, action := range remediation.BuildActions(incident, remediation.ModeFromEnv()) {
		_, err := s.store.CreateRemediationAction(r.Context(), action)
		if err != nil {
			return err
		}
		// The incident.opened notification already contains the diagnostic
		// report and recommended actions. Do not emit one identical webhook per
		// generated remediation action; explicit /notification-events callers
		// can still request diagnostic.created or remediation.pending_approval.
	}
	return nil
}
