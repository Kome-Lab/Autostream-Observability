package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/diagnostics"
	"github.com/example/autostream-observability/internal/store"
)

func TestRerunIncidentDiagnosticsReevaluatesSavedSignalWithoutSideEffects(t *testing.T) {
	st := store.NewMemoryStore()
	saved, err := st.SaveSignal(t.Context(), store.Signal{
		ID:          "sig-rerun-01",
		Type:        "error",
		Name:        "encoder.process.exited",
		ServiceID:   "enc-01",
		ServiceType: "encoder_recorder",
		StreamID:    "stream-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{
		Rule:      "encoder_process_exited",
		Severity:  "critical",
		Status:    "acknowledged",
		SummaryJA: "Encoder stopped.",
		ServiceID: "enc-01",
		StreamID:  "stream-01",
		SignalID:  saved.ID,
		Report:    diagnostics.JapaneseReport("encoder_process_exited", []string{"stale=true"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := st.CreateRemediationAction(t.Context(), store.RemediationAction{
		IncidentID: incident.ID,
		Action:     "rerun_diagnostics",
		Mode:       "suggest_only",
		Status:     "executed",
		Result:     "recorded_noop",
	})
	if err != nil {
		t.Fatal(err)
	}
	notifier := &eventRecordingNotifier{}
	executor := &fakeControlExecutor{}
	admin := auth.WithRawTokenScopes(auth.Verifier{}, "diagnostics-token", "diagnostics.run")
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.Verifier{}, admin, notifier, executor)

	req := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/diagnostics/rerun", nil)
	req.Header.Set("Authorization", "Bearer diagnostics-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	updated, err := st.GetIncident(t.Context(), incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "acknowledged" || updated.ResolvedAt != nil {
		t.Fatalf("diagnostic rerun changed incident lifecycle: %#v", updated)
	}
	if !strings.Contains(strings.Join(updated.Report.Evidence, "\n"), "signal_id=sig-rerun-01") {
		t.Fatalf("rerun did not rebuild diagnostics from saved signal: %#v", updated.Report)
	}
	if strings.Contains(strings.Join(updated.Report.Evidence, "\n"), "stale=true") {
		t.Fatalf("rerun kept stale diagnostic evidence: %#v", updated.Report)
	}
	updatedAction, err := st.GetRemediationAction(t.Context(), action.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedAction.Status != "executed" || updatedAction.Result != "recorded_noop" || updatedAction.ExecutedAt != nil {
		t.Fatalf("diagnostic rerun changed remediation state: %#v", updatedAction)
	}
	if len(notifier.events) != 0 {
		t.Fatalf("diagnostic rerun must not notify: %#v", notifier.events)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("diagnostic rerun must not dispatch remediation: %#v", executor.calls)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 0 {
		t.Fatalf("diagnostic rerun must not create notification deliveries: %#v", deliveries)
	}
}

func TestRerunIncidentDiagnosticsRequiresDiagnosticsRunScope(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder stopped.", ServiceID: "enc-01", SignalID: "sig-01"})
	if err != nil {
		t.Fatal(err)
	}
	admin := auth.WithRawTokenScopes(auth.Verifier{}, "read-token", adminScopeRead)
	handler := NewServerWithStoreAuthz("observability", st, auth.Verifier{}, admin)
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/diagnostics/rerun", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "missing_admin_scope") {
		t.Fatalf("diagnostics.run scope must be required: status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestRerunIncidentDiagnosticsKeepsExistingReportWhenSavedSignalNoLongerMatches(t *testing.T) {
	st := store.NewMemoryStore()
	value := 60.0
	saved, err := st.SaveSignal(t.Context(), store.Signal{
		ID:          "sig-rerun-inconclusive",
		Type:        "metric",
		Name:        "encoder.output_fps",
		ServiceID:   "enc-01",
		ServiceType: "encoder_recorder",
		StreamID:    "stream-01",
		Value:       &value,
	})
	if err != nil {
		t.Fatal(err)
	}
	originalReport := diagnostics.JapaneseReport("encoder_process_exited", []string{"original=true"})
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{
		Rule:      "encoder_process_exited",
		Severity:  "critical",
		Status:    "acknowledged",
		SummaryJA: "Encoder stopped.",
		ServiceID: "enc-01",
		StreamID:  "stream-01",
		SignalID:  saved.ID,
		Report:    originalReport,
	})
	if err != nil {
		t.Fatal(err)
	}
	notifier := &eventRecordingNotifier{}
	admin := auth.WithRawTokenScopes(auth.Verifier{}, "diagnostics-token", "diagnostics.run")
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.Verifier{}, admin, notifier, &fakeControlExecutor{})
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/diagnostics/rerun", nil)
	req.Header.Set("Authorization", "Bearer diagnostics-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var response diagnosticRerunResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Outcome != "inconclusive" || response.Reason != "saved_signal_no_longer_matches_rule" {
		t.Fatalf("unexpected inconclusive response: %#v", response)
	}
	updated, err := st.GetIncident(t.Context(), incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != incident.Status || !updated.UpdatedAt.Equal(incident.UpdatedAt) || strings.Join(updated.Report.Evidence, "\n") != strings.Join(originalReport.Evidence, "\n") {
		t.Fatalf("inconclusive rerun mutated incident: %#v", updated)
	}
	if len(notifier.events) != 0 {
		t.Fatalf("inconclusive rerun must not notify: %#v", notifier.events)
	}
}

func TestRerunIncidentDiagnosticsDoesNotOverwriteNewerSignalReport(t *testing.T) {
	memory := store.NewMemoryStore()
	staleSignal, err := memory.SaveSignal(t.Context(), store.Signal{
		ID:          "sig-rerun-stale",
		Type:        "error",
		Name:        "encoder.process.exited",
		ServiceID:   "enc-01",
		ServiceType: "encoder_recorder",
		StreamID:    "stream-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	newerSignal, err := memory.SaveSignal(t.Context(), store.Signal{
		ID:          "sig-rerun-newer",
		Type:        "error",
		Name:        "encoder.process.exited",
		ServiceID:   "enc-01",
		ServiceType: "encoder_recorder",
		StreamID:    "stream-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	incident, _, err := memory.UpsertIncident(t.Context(), store.Incident{
		Rule:      "encoder_process_exited",
		Severity:  "critical",
		Status:    "open",
		SummaryJA: "Encoder stopped.",
		ServiceID: "enc-01",
		StreamID:  "stream-01",
		SignalID:  staleSignal.ID,
		Report:    diagnostics.JapaneseReport("encoder_process_exited", []string{"signal_id=" + staleSignal.ID}),
	})
	if err != nil {
		t.Fatal(err)
	}
	st := &diagnosticRaceStore{MemoryStore: memory, incident: incident, newerSignal: newerSignal}
	admin := auth.WithRawTokenScopes(auth.Verifier{}, "diagnostics-token", "diagnostics.run")
	handler := NewServerWithStoreAuthz("observability", st, auth.Verifier{}, admin)
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/diagnostics/rerun", nil)
	req.Header.Set("Authorization", "Bearer diagnostics-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var response diagnosticRerunResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Outcome != "inconclusive" || response.Reason != "incident_updated_during_rerun" {
		t.Fatalf("stale diagnostic rerun must be inconclusive: %#v", response)
	}
	updated, err := memory.GetIncident(t.Context(), incident.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.SignalID != newerSignal.ID || !strings.Contains(strings.Join(updated.Report.Evidence, "\n"), "signal_id="+newerSignal.ID) {
		t.Fatalf("stale diagnostic rerun overwrote newer report: %#v", updated)
	}
}

type diagnosticRaceStore struct {
	*store.MemoryStore
	incident    store.Incident
	newerSignal store.Signal
}

func (s *diagnosticRaceStore) UpdateIncidentDiagnostic(ctx context.Context, id, expectedSignalID string, report diagnostics.Report) (store.Incident, bool, error) {
	_, _, err := s.MemoryStore.UpsertIncident(ctx, store.Incident{
		Rule:      s.incident.Rule,
		Severity:  s.incident.Severity,
		Status:    s.incident.Status,
		SummaryJA: s.incident.SummaryJA,
		ServiceID: s.incident.ServiceID,
		StreamID:  s.incident.StreamID,
		SignalID:  s.newerSignal.ID,
		Report:    diagnostics.JapaneseReport(s.incident.Rule, []string{"signal_id=" + s.newerSignal.ID}),
	})
	if err != nil {
		return store.Incident{}, false, err
	}
	return s.MemoryStore.UpdateIncidentDiagnostic(ctx, id, expectedSignalID, report)
}
