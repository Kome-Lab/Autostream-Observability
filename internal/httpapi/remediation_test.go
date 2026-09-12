package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/remediation"
	"github.com/example/autostream-observability/internal/store"
)

func TestApprovedHostSymptomPreservesRecordedNoopWithoutDispatch(t *testing.T) {
	st := store.NewMemoryStore()
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: "inc-1", Action: "restart_encoder_recorder", Mode: "manual_approval", Status: "pending_approval", RequiresApproval: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	approveReq := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/approve", nil)
	approveReq.Header.Set("Authorization", "Bearer service-token")
	approveRes := httptest.NewRecorder()
	handler.ServeHTTP(approveRes, approveReq)
	if approveRes.Code != http.StatusOK {
		t.Fatalf("approve status = %d body = %s", approveRes.Code, approveRes.Body.String())
	}
	execReq := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	execReq.Header.Set("Authorization", "Bearer service-token")
	execRes := httptest.NewRecorder()
	handler.ServeHTTP(execRes, execReq)
	if execRes.Code != http.StatusOK {
		t.Fatalf("execute status = %d body = %s", execRes.Code, execRes.Body.String())
	}
	if !strings.Contains(execRes.Body.String(), `"status":"executed"`) || !strings.Contains(execRes.Body.String(), `"result":"recorded_noop"`) {
		t.Fatalf("host symptom compatibility changed: %s", execRes.Body.String())
	}
}

func TestExecuteBlocksDangerousRemediationAction(t *testing.T) {
	st := store.NewMemoryStore()
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: "inc-1", Action: "delete_archives", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "archive/path") {
		t.Fatalf("unexpected sensitive content: %s", res.Body.String())
	}
}

func TestHostSystemAndUnknownActionsNeverDispatch(t *testing.T) {
	tests := []struct {
		action     store.RemediationAction
		wantStatus int
	}{
		{store.RemediationAction{IncidentID: "inc-1", Action: "restart_worker", Mode: "manual_approval", Status: "approved", RequiresApproval: true}, http.StatusOK},
		{store.RemediationAction{IncidentID: "inc-1", Action: "host.systemd", Mode: "safe_auto", Status: "suggested", SafeAuto: true}, http.StatusForbidden},
		{store.RemediationAction{IncidentID: "inc-1", Action: "run_arbitrary_command", Mode: "safe_auto", Status: "suggested", SafeAuto: true}, http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(strings.ReplaceAll(test.action.Action, ".", "_"), func(t *testing.T) {
			st := store.NewMemoryStore()
			action, err := st.CreateRemediationAction(t.Context(), test.action)
			if err != nil {
				t.Fatal(err)
			}
			executor := &fakeControlExecutor{}
			handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
			req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
			req.Header.Set("Authorization", "Bearer service-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != test.wantStatus {
				t.Fatalf("action %q status = %d body = %s", test.action.Action, res.Code, res.Body.String())
			}
			if len(executor.calls) != 0 {
				t.Fatalf("action %q reached Control Panel dispatch: %#v", test.action.Action, executor.calls)
			}
		})
	}
}

func TestExecuteBlocksDisabledRemediationAction(t *testing.T) {
	st := store.NewMemoryStore()
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: "inc-1", Action: "retry_package_remux", Mode: "disabled", Status: "disabled", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("disabled remediation should be forbidden, got %d body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"status":"blocked"`) || !strings.Contains(res.Body.String(), "remediation is disabled") {
		t.Fatalf("expected disabled remediation to be blocked: %s", res.Body.String())
	}
}

func TestExecuteBlocksSuggestOnlyRemediationAction(t *testing.T) {
	st := store.NewMemoryStore()
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: "inc-1", Action: "retry_package_remux", Mode: "suggest_only", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("suggest_only remediation should be forbidden, got %d body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"status":"blocked"`) || !strings.Contains(res.Body.String(), "suggest_only") {
		t.Fatalf("expected suggest_only remediation to be blocked: %s", res.Body.String())
	}
}

func TestExecuteArchiveRemediationDispatchesToControlPanel(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if len(executor.calls) != 1 || executor.calls[0].Proposal.ProposalID != action.ID || executor.calls[0].Proposal.IncidentID != incident.ID || executor.calls[0].Proposal.ActionType != remediation.ProposalRetryPackageRemux || executor.calls[0].StreamID != "stream-01" {
		t.Fatalf("unexpected executor calls: %#v", executor.calls)
	}
	proposal := executor.calls[0].Proposal
	if !proposal.ControlPanelAuthorizationRequired || proposal.Detector.ServiceType != remediation.ServiceTypeObservability || proposal.Target.ServiceType != remediation.ServiceTypeEncoder || len(proposal.Evidence) != 3 {
		t.Fatalf("dispatch did not cross the typed proposal boundary: %#v", proposal)
	}
	if !strings.Contains(res.Body.String(), "control_panel_dispatch_executed") {
		t.Fatalf("expected dispatch result: %s", res.Body.String())
	}
}

func TestApplicationProposalBindsDetectorAfterStagedIdentityAppears(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "node.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", configPath)

	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
	writeNodeListenerCredentialForVerifierTest(t, configPath, control.ServiceType, "1")
	config := `panel:
  url: "https://panel.example.jp"
node:
  id: "observability-staged-1"
  name: "Observability Staged"
  type: "observability"
listener:
  credential: "node-listener.json"
api:
  host: "observability.example.jp"
  port: 8443
  ssl_enabled: true
auth:
  token_id: "test-token-id"
  token: "test-runtime-secret"
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if len(executor.calls) != 1 || executor.calls[0].Proposal.Detector.ServiceID != "observability-staged-1" {
		t.Fatalf("proposal did not bind the staged authoritative identity: %#v", executor.calls)
	}
}

func TestGetRemediationDispatchContextVerifiesActionIncidentAndStream(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodGet, "/remediation-actions/"+action.ID+"/dispatch-context", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"action_id":"`+action.ID+`"`) || !strings.Contains(res.Body.String(), `"incident_id":"`+incident.ID+`"`) || !strings.Contains(res.Body.String(), `"stream_id":"stream-01"`) || !strings.Contains(res.Body.String(), `"executable":true`) {
		t.Fatalf("unexpected dispatch context: %s", res.Body.String())
	}
}

func TestGetRemediationDispatchContextRejectsTerminalAction(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "executed", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodGet, "/remediation-actions/"+action.ID+"/dispatch-context", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "remediation_action_terminal") {
		t.Fatalf("expected terminal action rejection, got %d body = %s", res.Code, res.Body.String())
	}
}

func TestGetRemediationDispatchContextRejectsNotExecutableAction(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "suggest_only", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	req := httptest.NewRequest(http.MethodGet, "/remediation-actions/"+action.ID+"/dispatch-context", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "remediation_action_not_executable") {
		t.Fatalf("expected not executable rejection, got %d body = %s", res.Code, res.Body.String())
	}
}

func TestExecuteArchiveRemediationRejectsAlreadyExecutedAction(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "executed", SafeAuto: true, Result: "control_panel_dispatch_executed"})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("already executed remediation should return conflict, got %d body = %s", res.Code, res.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor must not be called for already executed action: %#v", executor.calls)
	}
	var got store.RemediationAction
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "executed" || got.Result != "remediation action is already terminal" {
		t.Fatalf("expected terminal action response without redispatch, got %#v", got)
	}
}

func TestExecuteArchiveRemediationInManualApprovalModeRequiresApproval(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "manual_approval", Status: "pending_approval", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("manual approval safe-auto remediation should be forbidden until approved, got %d body = %s", res.Code, res.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor should not be called before manual approval: %#v", executor.calls)
	}
	var got store.RemediationAction
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "blocked" || got.Result != "manual approval is required" || got.ExecutedAt != nil {
		t.Fatalf("expected blocked unapproved remediation without executed_at, got %#v", got)
	}
}

func TestExecuteArchiveRemediationClearsExecutedAtOnDispatchFailure(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{err: errors.New("dispatch unavailable")}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected dispatch failure to be forbidden, got %d body = %s", res.Code, res.Body.String())
	}
	var got store.RemediationAction
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "blocked" || got.ExecutedAt != nil {
		t.Fatalf("expected blocked remediation without executed_at, got %#v", got)
	}
}

func TestIngestTokenCannotExecuteRemediation(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", StreamID: "victim-stream", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), nil, executor)

	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer ingest-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("ingest token must not execute remediation, got %d body = %s", res.Code, res.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor should not be called by ingest token: %#v", executor.calls)
	}

	adminReq := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	adminReq.Header.Set("Authorization", "Bearer admin-token")
	adminRes := httptest.NewRecorder()
	handler.ServeHTTP(adminRes, adminReq)
	if adminRes.Code != http.StatusOK {
		t.Fatalf("admin execute status = %d body = %s", adminRes.Code, adminRes.Body.String())
	}
	if len(executor.calls) != 1 || executor.calls[0].Proposal.ProposalID != action.ID || executor.calls[0].Proposal.IncidentID != incident.ID || executor.calls[0].StreamID != "victim-stream" {
		t.Fatalf("expected one admin-dispatched remediation, got %#v", executor.calls)
	}
}

func TestExecuteArchiveRemediationBlocksWithoutStreamContext(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "archive_package_failed", Severity: "error", Status: "open", SummaryJA: "Package failed.", ServiceID: "enc-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{IncidentID: incident.ID, Action: "retry_package_remux", Mode: "safe_auto", Status: "suggested", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeControlExecutor{}
	handler := NewServerWithStoreAuthNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil, executor)
	req := httptest.NewRequest(http.MethodPost, "/remediation-actions/"+action.ID+"/execute", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body = %s", res.Code, res.Body.String())
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor should not be called: %#v", executor.calls)
	}
	if !strings.Contains(res.Body.String(), "stream_id is required") {
		t.Fatalf("expected stream context failure: %s", res.Body.String())
	}
}

type remediationProposalCall struct {
	Proposal remediation.Proposal
	StreamID string
}

type fakeControlExecutor struct {
	calls []remediationProposalCall
	err   error
}

func (f *fakeControlExecutor) ExecuteRemediationProposal(ctx context.Context, proposal remediation.Proposal, streamID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, remediationProposalCall{Proposal: proposal, StreamID: streamID})
	return nil
}
