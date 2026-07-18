package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

func TestSignalIngestRequiresAuthorization(t *testing.T) {
	handler := NewServerWithStoreAndAuth("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("service-token"))
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{}`))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestAdminAuthReadsNodeRuntimeTokenAfterStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	handler := NewServerWithStoreAuthz("observability", store.NewMemoryStore(), auth.Verifier{}, auth.Verifier{})

	req := httptest.NewRequest(http.MethodGet, "/signals", nil)
	req.Header.Set("Authorization", "Bearer runtime-secret")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("runtime token should not verify before config exists, got %d body = %s", res.Code, res.Body.String())
	}

	writeNodeConfigForVerifierTest(t, path, "observability")
	req = httptest.NewRequest(http.MethodGet, "/signals", nil)
	req.Header.Set("Authorization", "Bearer runtime-secret")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("runtime token should verify after config is written, got %d body = %s", res.Code, res.Body.String())
	}
}

func TestRootAndStatusUseNodeConfigServiceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	t.Setenv("AUTOSTREAM_NODE_CONFIG", path)
	body := `panel:
  url: "https://panel.example.jp"
node:
  id: "o11y-lab-web-kagoya-01"
  name: "Kome-Lab Web Observability"
  type: "observability"
api:
  host: "ass-o11y.studio-kometubu.jp"
  port: 443
  ssl_enabled: true
auth:
  token_id: "token-id"
  token: "runtime-secret"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	handler := NewServerWithStoreAuthz("observability", store.NewMemoryStore(), auth.Verifier{}, auth.Verifier{})

	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootRes := httptest.NewRecorder()
	handler.ServeHTTP(rootRes, rootReq)
	if rootRes.Code != http.StatusOK {
		t.Fatalf("root status = %d body = %s", rootRes.Code, rootRes.Body.String())
	}
	if !strings.Contains(rootRes.Body.String(), `"service_id":"o11y-lab-web-kagoya-01"`) || !strings.Contains(rootRes.Body.String(), `"/metrics"`) || !strings.Contains(rootRes.Body.String(), `"auth_required":true`) {
		t.Fatalf("root response should expose safe operator status and protected metrics endpoint: %s", rootRes.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	statusRes := httptest.NewRecorder()
	handler.ServeHTTP(statusRes, statusReq)
	if statusRes.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", statusRes.Code, statusRes.Body.String())
	}
	if !strings.Contains(statusRes.Body.String(), `"service_id":"o11y-lab-web-kagoya-01"`) {
		t.Fatalf("status response should use node config service_id: %s", statusRes.Body.String())
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRes := httptest.NewRecorder()
	handler.ServeHTTP(metricsRes, metricsReq)
	if metricsRes.Code != http.StatusUnauthorized {
		t.Fatalf("metrics should remain token protected, got %d body = %s", metricsRes.Code, metricsRes.Body.String())
	}
}

func TestMetricsIncludesObservabilityRuntimeMetrics(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var metrics []store.MetricSnapshot
	if err := json.NewDecoder(res.Body).Decode(&metrics); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, metric := range metrics {
		if metric.ServiceType == control.ServiceType && metric.Name == "observability.goroutines" && metric.Value != nil {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("observability runtime metrics were not returned: %#v", metrics)
	}
}

func TestSignalIngestCreatesIncidentAndJapaneseDiagnostic(t *testing.T) {
	st := store.NewMemoryStore()
	handler := newTestServer(st)
	body := `{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","attributes":{"error":"exit status 1"}}`
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var response IngestResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Incidents) != 1 || response.Incidents[0].Rule != "encoder_process_exited" {
		t.Fatalf("unexpected incidents: %#v", response.Incidents)
	}
	if !strings.Contains(response.Incidents[0].Report.Summary, "Encoder") {
		t.Fatalf("expected Japanese diagnostic summary: %#v", response.Incidents[0].Report)
	}
}

func TestSignalIngestRejectsBoundTokenServiceIdentityMismatch(t *testing.T) {
	st := store.NewMemoryStore()
	verifier := auth.NewVerifierWithSubjects(map[string]auth.Subject{
		"encoder-token": {ServiceType: "encoder_recorder", ServiceID: "enc-01"},
	})
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, verifier, auth.NewVerifierFromRawTokens("admin-token"), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"event","name":"encoder.process.exited","service_id":"worker-01","service_type":"worker","stream_id":"stream-01"}`))
	req.Header.Set("Authorization", "Bearer encoder-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "service_identity_mismatch") {
		t.Fatalf("bound token mismatch should be forbidden, got %d body = %s", res.Code, res.Body.String())
	}
	signals, err := st.ListSignals(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Fatalf("mismatched bound token persisted signal: %#v", signals)
	}
}

func TestSignalIngestAcceptsBoundTokenServiceIdentity(t *testing.T) {
	st := store.NewMemoryStore()
	verifier := auth.NewVerifierWithSubjects(map[string]auth.Subject{
		"encoder-token": {ServiceType: "encoder_recorder", ServiceID: "enc-01"},
	})
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, verifier, auth.NewVerifierFromRawTokens("admin-token"), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60}`))
	req.Header.Set("Authorization", "Bearer encoder-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("bound token signal should be accepted, got %d body = %s", res.Code, res.Body.String())
	}
}

func TestSignalIngestAllowsAdminTokenWithIngestScope(t *testing.T) {
	st := store.NewMemoryStore()
	admin := auth.Verifier{
		TokenHashes: []string{auth.HashToken("admin-token"), auth.HashToken("read-token")},
		TokenScopes: map[string]map[string]bool{
			auth.HashToken("admin-token"): {"observability.ingest": true, "observability.read": true},
			auth.HashToken("read-token"):  {"observability.read": true},
		},
		ScopeBindingRequired: true,
	}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("legacy-ingest"), admin, nil, nil)
	body := `{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60}`
	deniedReq := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	deniedReq.Header.Set("Authorization", "Bearer read-token")
	deniedRes := httptest.NewRecorder()
	handler.ServeHTTP(deniedRes, deniedReq)
	if deniedRes.Code != http.StatusForbidden {
		t.Fatalf("read-only admin token should be forbidden, got %d body = %s", deniedRes.Code, deniedRes.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("admin ingest token should be accepted, got %d body = %s", res.Code, res.Body.String())
	}
}

func TestSignalIngestDeduplicatesIncident(t *testing.T) {
	st := store.NewMemoryStore()
	handler := newTestServer(st)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
		}
	}
	incidents, err := st.ListIncidents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 {
		t.Fatalf("expected deduped incident, got %#v", incidents)
	}
}

func TestIncidentAcknowledgeAndResolve(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder stopped.", ServiceID: "enc-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	ackReq := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/acknowledge", nil)
	ackReq.Header.Set("Authorization", "Bearer service-token")
	ackRes := httptest.NewRecorder()
	handler.ServeHTTP(ackRes, ackReq)
	if ackRes.Code != http.StatusOK || !strings.Contains(ackRes.Body.String(), "acknowledged") {
		t.Fatalf("ack status = %d body = %s", ackRes.Code, ackRes.Body.String())
	}
	resolveReq := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/resolve", nil)
	resolveReq.Header.Set("Authorization", "Bearer service-token")
	resolveRes := httptest.NewRecorder()
	handler.ServeHTTP(resolveRes, resolveReq)
	if resolveRes.Code != http.StatusOK || !strings.Contains(resolveRes.Body.String(), "resolved_at") {
		t.Fatalf("resolve status = %d body = %s", resolveRes.Code, resolveRes.Body.String())
	}
}

func TestSignalIngestSendsNotificationOnlyForNewIncident(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &fakeNotifier{}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), notifier)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
		}
	}
	if notifier.count != 1 {
		t.Fatalf("expected one notification for deduped incident, got %d", notifier.count)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 || deliveries[0].Status != "success" || deliveries[0].EventType != "incident.opened" {
		t.Fatalf("unexpected deliveries: %#v", deliveries)
	}
}

func TestSignalIngestCreatesRemediationActions(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil)
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	actions, err := st.ListRemediationActions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 4 {
		t.Fatalf("expected remediation actions from diagnostic report, got %#v", actions)
	}
}

func TestSignalIngestRejectsTrailingJSON(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil)
	body := `{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}{"type":"metric","name":"host.cpu_percent","service_id":"enc-01","service_type":"encoder_recorder"}`
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected trailing JSON to be rejected, got status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestArchivePackageUploadFailureUsesGDriveIncidentAndSafeEvidence(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil)
	body := `{"type":"error","name":"archive.package.failed","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","attributes":{"failure_phase":"upload","error_class":"archive_upload_failed","error":"transient_upload_failure","upload_attempts":3}}`
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var response IngestResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Incidents) != 1 || response.Incidents[0].Rule != "gdrive_upload_failed" {
		t.Fatalf("unexpected incidents: %#v", response.Incidents)
	}
	evidence := strings.Join(response.Incidents[0].Report.Evidence, "\n")
	if !strings.Contains(evidence, "failure_phase=upload") || !strings.Contains(evidence, "error_class=archive_upload_failed") || !strings.Contains(evidence, "upload_attempts=3") {
		t.Fatalf("expected safe attribute evidence, got %s", evidence)
	}
	if strings.Contains(evidence, "secret-token") || strings.Contains(evidence, "https://example.com/upload") {
		t.Fatalf("raw error leaked in evidence: %s", evidence)
	}
}

func TestSignalIngestRejectsSecretLikeAttributes(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil)
	for _, body := range []string{
		`{"type":"error","name":"archive.package.failed","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","attributes":{"failure_phase":"https://drive.example.com/upload?token=secret-token","upload_attempts":2}}`,
		`{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60,"attributes":{"target":"https://discord.com/api/webhooks/id/raw-secret-token","safe_number":12}}`,
		`{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60,"attributes":{"nested":{"access_token":"raw-secret-token","ok":true}}}`,
		`{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60,"attributes":{"message":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}}`,
		`{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60,"attributes":{"message":"AIzaABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"}}`,
		`{"type":"metric","name":"encoder.output_fps","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01","value":60,"attributes":{"message":"M12345678901234567890123.abcdef.abcdefghijklmnopqrstuvwxyzA"}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_signal_attributes") {
			t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
		}
		if strings.Contains(res.Body.String(), "raw-secret-token") || strings.Contains(res.Body.String(), "secret-token") || strings.Contains(res.Body.String(), "discord.com/api/webhooks") || strings.Contains(res.Body.String(), "eyJhbGci") || strings.Contains(res.Body.String(), "AIza") || strings.Contains(res.Body.String(), "M123456") {
			t.Fatalf("unsafe attribute leaked in rejection response: %s", res.Body.String())
		}
	}
	signals, err := st.ListSignals(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Fatalf("unsafe signals were persisted: %#v", signals)
	}
}

func TestWorkerEventSendFailuresCreateIncident(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), nil)
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"metric","name":"worker.event_send_failures_total","service_id":"worker-01","service_type":"worker","stream_id":"stream-01","value":1}`))
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	var response IngestResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Incidents) != 1 || response.Incidents[0].Rule != "worker_event_send_failed" || response.Incidents[0].Severity != "warning" {
		t.Fatalf("unexpected incidents: %#v", response.Incidents)
	}
	if !strings.Contains(response.Incidents[0].Report.Summary, "Worker") {
		t.Fatalf("expected Worker diagnostic report: %#v", response.Incidents[0].Report)
	}
	actions, err := st.ListRemediationActions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var sawRestartWorker bool
	for _, action := range actions {
		if action.Action == "restart_worker" && action.RequiresApproval {
			sawRestartWorker = true
		}
	}
	if !sawRestartWorker {
		t.Fatalf("expected restart_worker remediation candidate: %#v", actions)
	}
}

func TestApproveAndExecuteRemediationAction(t *testing.T) {
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
	if !strings.Contains(execRes.Body.String(), `"status":"executed"`) {
		t.Fatalf("expected executed action: %s", execRes.Body.String())
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
	if len(executor.calls) != 1 || executor.calls[0].ActionID != action.ID || executor.calls[0].IncidentID != incident.ID || executor.calls[0].Action != "retry_package_remux" || executor.calls[0].StreamID != "stream-01" {
		t.Fatalf("unexpected executor calls: %#v", executor.calls)
	}
	if !strings.Contains(res.Body.String(), "control_panel_dispatch_executed") {
		t.Fatalf("expected dispatch result: %s", res.Body.String())
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
	if len(executor.calls) != 1 || executor.calls[0].ActionID != action.ID || executor.calls[0].IncidentID != incident.ID || executor.calls[0].StreamID != "victim-stream" {
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

func TestAdminTokenScopesSeparateReadFromSensitiveWrites(t *testing.T) {
	st := store.NewMemoryStore()
	readToken := "read-token"
	adminVerifier := auth.NewVerifierFromRawTokens(readToken)
	adminVerifier.TokenScopes = map[string]map[string]bool{
		auth.HashToken(readToken): {
			adminScopeRead:              true,
			adminScopeNotificationsRead: true,
			adminScopeRemediationRead:   true,
		},
	}
	adminVerifier.ScopeBindingRequired = true
	handler := NewServerWithStoreAuthzNotifierAndExecutor(
		"observability",
		st,
		auth.NewVerifierFromRawTokens("ingest-token"),
		adminVerifier,
		nil,
		nil,
	)

	readReq := httptest.NewRequest(http.MethodGet, "/incidents", nil)
	readReq.Header.Set("Authorization", "Bearer "+readToken)
	readRes := httptest.NewRecorder()
	handler.ServeHTTP(readRes, readReq)
	if readRes.Code != http.StatusOK {
		t.Fatalf("read-only admin token should list incidents: status=%d body=%s", readRes.Code, readRes.Body.String())
	}

	manageReq := httptest.NewRequest(http.MethodPost, "/notification-channels", strings.NewReader(`{}`))
	manageReq.Header.Set("Authorization", "Bearer "+readToken)
	manageRes := httptest.NewRecorder()
	handler.ServeHTTP(manageRes, manageReq)
	if manageRes.Code != http.StatusForbidden || !strings.Contains(manageRes.Body.String(), "missing_admin_scope") {
		t.Fatalf("read-only admin token must not manage notification channels: status=%d body=%s", manageRes.Code, manageRes.Body.String())
	}

	executeReq := httptest.NewRequest(http.MethodPost, "/remediation-actions/action-01/execute", nil)
	executeReq.Header.Set("Authorization", "Bearer "+readToken)
	executeRes := httptest.NewRecorder()
	handler.ServeHTTP(executeRes, executeReq)
	if executeRes.Code != http.StatusForbidden || !strings.Contains(executeRes.Body.String(), "missing_admin_scope") {
		t.Fatalf("read-only admin token must not execute remediation: status=%d body=%s", executeRes.Code, executeRes.Body.String())
	}
}

func TestListNotificationDeliveriesRequiresAuthorization(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestCreateNotificationEventAcceptsExactControlPanelPayload(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","severity":"info","status":"success","action":"oauth_accounts.update","resource_type":"oauth_account","resource_id":"acct-01","actor_username":"ops","summary":"OAuth connected account updated","timestamp":"2026-07-18T01:32:00Z"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if len(notifier.events) != 1 || notifier.events[0] != "admin.audit" {
		t.Fatalf("unexpected event notifier calls: %#v", notifier.events)
	}
	if len(notifier.incidents) != 1 {
		t.Fatalf("notification incident was not recorded: %#v", notifier.incidents)
	}
	notificationIncident := notifier.incidents[0]
	if notificationIncident.SummaryJA != "OAuth接続アカウントを更新\n対象: OAuth接続アカウント (acct-01)\n実行者: ops\n詳細: OAuth connected account updated" {
		t.Fatalf("admin audit summary is not readable: %q", notificationIncident.SummaryJA)
	}
	if notificationIncident.SourceSummary != "OAuth connected account updated / oauth_account acct-01 / actor=ops" {
		t.Fatalf("admin audit source summary was not preserved: %q", notificationIncident.SourceSummary)
	}
	if notificationIncident.UpdatedAt.Format(time.RFC3339) != "2026-07-18T01:32:00Z" {
		t.Fatalf("admin audit occurrence timestamp was lost: %s", notificationIncident.UpdatedAt)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("expected one saved delivery, got %#v", deliveries)
	}
	delivery := deliveries[0]
	if delivery.EventType != "admin.audit" || delivery.IncidentID != "" || delivery.Status != "success" {
		t.Fatalf("unexpected saved delivery: %#v", delivery)
	}
	if delivery.Metadata["severity"] != "info" || delivery.Metadata["action"] != "oauth_accounts.update" || delivery.Metadata["rule"] != "oauth_accounts.update" || delivery.Metadata["summary"] != notificationIncident.SummaryJA || delivery.Metadata["occurred_at"] != "2026-07-18T01:32:00Z" {
		t.Fatalf("unexpected delivery metadata: %#v", delivery.Metadata)
	}
	if strings.Contains(res.Body.String(), "acct-01") || strings.Contains(res.Body.String(), "ops") {
		t.Fatalf("notification event response should only include sanitized delivery results: %s", res.Body.String())
	}
}

func TestNotificationIncidentPreservesSafeResourceTypeAndValidatesTimestamp(t *testing.T) {
	for _, timestamp := range []string{"2026-07-18T10:32:00+09:00", "2026-07-18T01:32:00.123Z"} {
		incident, err := notificationIncidentFromRequest(notificationEventRequest{
			EventType:    "admin.audit",
			Severity:     "warning",
			Status:       "success",
			Action:       "secrets.update",
			ResourceType: "secret",
			ResourceID:   "DISCORD_BOT_TOKEN",
			Timestamp:    timestamp,
		}, "observability")
		if err != nil {
			t.Fatalf("valid timestamp %q was rejected: %v", timestamp, err)
		}
		if !strings.Contains(incident.SummaryJA, "対象: シークレット") {
			t.Fatalf("safe secret resource type was removed: %q", incident.SummaryJA)
		}
		if incident.UpdatedAt.IsZero() {
			t.Fatalf("valid timestamp %q was lost", timestamp)
		}
	}
	legacySecretSummary := "管理イベント: secrets.update / success"
	incident, err := notificationIncidentFromRequest(notificationEventRequest{
		EventType: "admin.audit",
		Status:    "success",
		Action:    "secrets.update",
		Summary:   legacySecretSummary,
	}, "observability")
	if err != nil {
		t.Fatal(err)
	}
	if incident.SourceSummary != legacySecretSummary {
		t.Fatalf("validated legacy admin summary was not preserved: %q", incident.SourceSummary)
	}

	if _, err := notificationIncidentFromRequest(notificationEventRequest{
		EventType: "admin.audit",
		Status:    "success",
		Action:    "streams.start",
		Timestamp: "18 July 2026 10:32 JST",
	}, "observability"); err == nil {
		t.Fatal("invalid notification timestamp was accepted")
	}
}

func TestCreateNotificationEventRejectsInvalidTimestamp(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","severity":"info","status":"success","action":"streams.start","timestamp":"not-rfc3339"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_event") {
		t.Fatalf("invalid timestamp status = %d body = %s", res.Code, res.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("invalid timestamp must not send a notification: %#v", notifier.events)
	}
}

func TestCreateNotificationEventValidatesKnownEventType(t *testing.T) {
	for _, eventType := range []string{
		"incident.opened",
		"incident.updated",
		"incident.resolved",
		"diagnostic.created",
		"remediation.pending_approval",
		"remediation.executed",
		"admin.audit",
	} {
		if !validNotificationEventType(eventType) {
			t.Fatalf("known event type rejected: %q", eventType)
		}
	}

	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit.typo","severity":"info","status":"success","action":"oauth_accounts.update"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_event") {
		t.Fatalf("unknown event type status = %d body = %s", res.Code, res.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("unknown event type should not notify: %#v", notifier.events)
	}
}

func TestCreateNotificationEventUsesStrictAuditActionIdentifier(t *testing.T) {
	valid := []string{
		"secrets.update",
		"users.reset_password",
		"nodes.configure_token.rotate",
		"nodes.registration_token.create",
		"nodes.runtime_token.rotate",
	}
	for _, action := range valid {
		t.Run("valid_"+strings.ReplaceAll(action, ".", "_"), func(t *testing.T) {
			st := store.NewMemoryStore()
			notifier := &eventRecordingNotifier{}
			handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
			body, err := json.Marshal(notificationEventRequest{EventType: "admin.audit", Severity: "info", Status: "success", Action: action})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusAccepted || len(notifier.events) != 1 {
				t.Fatalf("valid action %q status = %d body = %s events=%#v", action, res.Code, res.Body.String(), notifier.events)
			}
		})
	}

	invalid := []string{
		"raw-secret-token",
		"secrets..update",
		".secrets.update",
		"secrets.update.",
		strings.Repeat("a", 129),
	}
	for index, action := range invalid {
		t.Run("invalid_"+strconv.Itoa(index), func(t *testing.T) {
			st := store.NewMemoryStore()
			notifier := &eventRecordingNotifier{}
			handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
			body, err := json.Marshal(notificationEventRequest{EventType: "admin.audit", Severity: "info", Status: "success", Action: action})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_event") {
				t.Fatalf("invalid action status = %d body = %s", res.Code, res.Body.String())
			}
			if len(notifier.events) != 0 {
				t.Fatalf("invalid action should not notify: %#v", notifier.events)
			}
			if strings.Contains(res.Body.String(), action) {
				t.Fatalf("invalid action leaked in response: %s", res.Body.String())
			}
		})
	}
}

func TestCreateNotificationEventAdminAuditFansOutToAllEnabledChannelsAndSavesDeliveries(t *testing.T) {
	var callsMu sync.Mutex
	calls := map[string]int{}
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls[r.URL.Path]++
		callsMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookServer.Close()

	st := store.NewMemoryStore()
	channels := []store.NotificationChannel{
		{Name: "critical opened", Type: "generic", Enabled: true, WebhookURL: webhookServer.URL + "/critical-opened", SeverityFilter: []string{"critical"}, EventTypeFilter: []string{"incident.opened"}},
		{Name: "warning resolved", Type: "generic", Enabled: true, WebhookURL: webhookServer.URL + "/warning-resolved", SeverityFilter: []string{"warning"}, EventTypeFilter: []string{"incident.resolved"}},
		{Name: "disabled audit", Type: "generic", Enabled: false, WebhookURL: webhookServer.URL + "/disabled", SeverityFilter: []string{"info"}, EventTypeFilter: []string{"admin.audit"}},
	}
	for _, channel := range channels {
		if _, err := st.CreateNotificationChannel(t.Context(), channel); err != nil {
			t.Fatal(err)
		}
	}
	notifier := notifications.ChannelNotifier{Store: st, Timeout: time.Second, AllowPrivate: true}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","severity":"info","status":"success","action":"nodes.runtime_token.rotate","resource_type":"node","resource_id":"node-01","actor_username":"ops","summary":"Node runtime token rotated","timestamp":"2026-07-18T01:32:00Z"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}

	callsMu.Lock()
	gotCalls := map[string]int{}
	for path, count := range calls {
		gotCalls[path] = count
	}
	callsMu.Unlock()
	if gotCalls["/critical-opened"] != 1 || gotCalls["/warning-resolved"] != 1 || gotCalls["/disabled"] != 0 {
		t.Fatalf("unexpected admin audit fanout: %#v", gotCalls)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected two saved deliveries, got %#v", deliveries)
	}
	for _, delivery := range deliveries {
		if delivery.EventType != "admin.audit" || delivery.IncidentID != "" || delivery.Status != "success" || delivery.Metadata["rule"] != "nodes.runtime_token.rotate" {
			t.Fatalf("unexpected saved admin audit delivery: %#v", delivery)
		}
	}
}

func TestNotificationChannelCRUDDoesNotExposeWebhookURL(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"discord main","type":"discord","enabled":true,"webhook_url":"https://discord.com/api/webhooks/id/secret-token","severity_filter":["critical"],"event_type_filter":["incident.opened"]}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "secret-token") || strings.Contains(createRes.Body.String(), `"webhook_url"`) {
		t.Fatalf("webhook URL leaked in create response: %s", createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), `"smtp_tls"`) || strings.Contains(createRes.Body.String(), `"smtp_password"`) {
		t.Fatalf("SMTP fields leaked into webhook channel response: %s", createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-channels", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK || strings.Contains(listRes.Body.String(), "secret-token") {
		t.Fatalf("list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	getReq := httptest.NewRequest(http.MethodGet, "/notification-channels/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer service-token")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK || strings.Contains(getRes.Body.String(), "secret-token") || strings.Contains(getRes.Body.String(), `"webhook_url"`) {
		t.Fatalf("get status = %d body = %s", getRes.Code, getRes.Body.String())
	}
	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"discord updated","type":"discord","enabled":false,"webhook_url":"https://discord.com/api/webhooks/id/new-secret-token"}`))
	updateReq.Header.Set("Authorization", "Bearer service-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK || !strings.Contains(updateRes.Body.String(), "discord updated") {
		t.Fatalf("update status = %d body = %s", updateRes.Code, updateRes.Body.String())
	}
	if strings.Contains(updateRes.Body.String(), "new-secret-token") || strings.Contains(updateRes.Body.String(), `"webhook_url"`) {
		t.Fatalf("webhook URL leaked in update response: %s", updateRes.Body.String())
	}
	if strings.Contains(updateRes.Body.String(), `"smtp_tls"`) || strings.Contains(updateRes.Body.String(), `"smtp_password"`) {
		t.Fatalf("SMTP fields leaked into webhook channel update response: %s", updateRes.Body.String())
	}
	deleteReq := httptest.NewRequest(http.MethodDelete, "/notification-channels/"+created.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer service-token")
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK {
		t.Fatalf("delete status = %d body = %s", deleteRes.Code, deleteRes.Body.String())
	}
}

func TestNotificationChannelCanonicalizesDiscordAliasesBeforePersistence(t *testing.T) {
	st := store.NewMemoryStore()
	handler := newTestServer(st)
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"discord ptb","type":"discord","enabled":true,"webhook_url":"https://ptb.discord.com/api/webhooks/id/secret-token?wait=true"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WebhookURL != "https://discord.com/api/webhooks/id/secret-token?wait=true" {
		t.Fatalf("stored create URL = %q", stored.WebhookURL)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"discord legacy canary","type":"discord","enabled":true,"webhook_url":"https://canary.discordapp.com/api/webhooks/id/new-secret-token"}`))
	updateReq.Header.Set("Authorization", "Bearer service-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("update status = %d body = %s", updateRes.Code, updateRes.Body.String())
	}
	stored, err = st.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WebhookURL != "https://discord.com/api/webhooks/id/new-secret-token" {
		t.Fatalf("stored update URL = %q", stored.WebhookURL)
	}
}

func TestSlackNotificationChannelCRUDDoesNotExposeWebhookURL(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"slack ops","type":"slack","enabled":true,"webhook_url":"https://hooks.slack.com/services/T000/B000/secret-token","severity_filter":["critical","error"],"event_type_filter":["incident.opened"]}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create slack channel status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	for _, leaked := range []string{"secret-token", "hooks.slack.com/services", `"webhook_url"`} {
		if strings.Contains(createRes.Body.String(), leaked) {
			t.Fatalf("slack webhook detail leaked in create response: %s", createRes.Body.String())
		}
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Type != "slack" || created.MaskedWebhookURL != "https://hooks.slack.com/<WEBHOOK_PATH>" {
		t.Fatalf("slack public channel markers missing: %#v", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/notification-channels", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list slack channels status=%d body=%s", listRes.Code, listRes.Body.String())
	}
	for _, leaked := range []string{"secret-token", "hooks.slack.com/services", `"webhook_url"`} {
		if strings.Contains(listRes.Body.String(), leaked) {
			t.Fatalf("slack webhook detail leaked in list response: %s", listRes.Body.String())
		}
	}
	if !strings.Contains(listRes.Body.String(), `"masked_webhook_url":"https://hooks.slack.com/\u003cWEBHOOK_PATH\u003e"`) {
		t.Fatalf("slack masked webhook URL was not preserved: %s", listRes.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/notification-channels/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer service-token")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("get slack channel status=%d body=%s", getRes.Code, getRes.Body.String())
	}
	for _, leaked := range []string{"secret-token", "hooks.slack.com/services", `"webhook_url"`} {
		if strings.Contains(getRes.Body.String(), leaked) {
			t.Fatalf("slack webhook detail leaked in get response: %s", getRes.Body.String())
		}
	}
}

func TestSlackNotificationChannelRejectsNonSlackWebhookHost(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"slack wrong host","type":"slack","enabled":true,"webhook_url":"https://example.com/services/T000/B000/secret-token"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_webhook_url") {
		t.Fatalf("expected invalid_webhook_url, status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "secret-token") || strings.Contains(createRes.Body.String(), "example.com/services") {
		t.Fatalf("slack webhook detail leaked in validation error: %s", createRes.Body.String())
	}
}

func TestEmailNotificationChannelCRUDDoesNotExposeSMTPPassword(t *testing.T) {
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil)
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com","smtp_port":587,"smtp_tls":true,"smtp_from":"autostream@example.com","smtp_username":"autostream","smtp_password":"raw-smtp-password","severity_filter":["critical"],"event_type_filter":["incident.opened"]}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create email channel status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	for _, raw := range []string{"raw-smtp-password", "ops@example.com", "smtp.example.com", "autostream@example.com", `"smtp_password"`, `"email_recipients"`, `"smtp_host"`, `"smtp_from"`, `"smtp_username"`} {
		if strings.Contains(createRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in create response: %s", createRes.Body.String())
		}
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !created.SMTPPasswordConfigured || created.MaskedEmailTarget == "" {
		t.Fatalf("email channel status fields missing: %#v", created)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-channels", nil)
	listReq.Header.Set("Authorization", "Bearer admin-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list response status=%d body=%s", listRes.Code, listRes.Body.String())
	}
	for _, raw := range []string{"raw-smtp-password", "ops@example.com", "smtp.example.com", "autostream@example.com", `"smtp_password"`, `"email_recipients"`, `"smtp_host"`, `"smtp_from"`, `"smtp_username"`} {
		if strings.Contains(listRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in list response: %s", listRes.Body.String())
		}
	}
	getReq := httptest.NewRequest(http.MethodGet, "/notification-channels/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer admin-token")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("get response status=%d body=%s", getRes.Code, getRes.Body.String())
	}
	for _, raw := range []string{"raw-smtp-password", "ops@example.com", "smtp.example.com", "autostream@example.com", `"smtp_password"`, `"email_recipients"`, `"smtp_host"`, `"smtp_from"`, `"smtp_username"`} {
		if strings.Contains(getRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in get response: %s", getRes.Body.String())
		}
	}
}

func TestGlobalSMTPEmailChannelCreateUpdateAndLegacyClear(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"global email","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":["ops@example.com"],"severity_filter":["critical"]}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("global email create status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !created.UseGlobalSMTP || created.ID == "" {
		t.Fatalf("global SMTP marker missing from create response: %#v", created)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"global email renamed","type":"email","enabled":true,"uses_global_smtp":true}`))
	updateReq.Header.Set("Authorization", "Bearer admin-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("global email update status=%d body=%s", updateRes.Code, updateRes.Body.String())
	}
	stored, err := mem.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.UseGlobalSMTP || len(stored.EmailRecipients) != 1 || stored.EmailRecipients[0] != "ops@example.com" {
		t.Fatalf("update did not preserve omitted recipients: %#v", stored)
	}

	legacy, err := mem.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "legacy", Type: "email", Enabled: true, EmailRecipients: []string{"legacy@example.com"},
		SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPTLS: true, SMTPFrom: "autostream@example.com", SMTPUsername: "autostream", SMTPPassword: "raw-smtp-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	clearReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+legacy.ID, bytes.NewBufferString(`{"name":"legacy","type":"email","enabled":true,"uses_global_smtp":true}`))
	clearReq.Header.Set("Authorization", "Bearer admin-token")
	clearRes := httptest.NewRecorder()
	handler.ServeHTTP(clearRes, clearReq)
	if clearRes.Code != http.StatusOK {
		t.Fatalf("legacy clear update status=%d body=%s", clearRes.Code, clearRes.Body.String())
	}
	cleared, err := mem.GetNotificationChannel(t.Context(), legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !cleared.UseGlobalSMTP || cleared.SMTPHost != "" || cleared.SMTPFrom != "" || cleared.SMTPPassword != "" || cleared.SMTPPasswordConfigured {
		t.Fatalf("legacy SMTP fields were not cleared: %#v", cleared)
	}
}

func TestGlobalSMTPEmailChannelRejectsEmptyRecipients(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"global email","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":[]}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("empty recipients must be rejected, status=%d body=%s", createRes.Code, createRes.Body.String())
	}
}

func TestGlobalSMTPEmailChannelRejectsMixedLegacySMTPFields(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"mixed email","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com"}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("global and legacy SMTP fields must not be mixed, status=%d body=%s", createRes.Code, createRes.Body.String())
	}
}

func TestNotificationChannelRejectsGlobalSMTPForNonEmailTypes(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})

	for _, tt := range []struct {
		channelType string
		webhookURL  string
	}{
		{channelType: "generic", webhookURL: "https://example.com/hook/token"},
		{channelType: "discord", webhookURL: "https://discord.com/api/webhooks/id/token"},
		{channelType: "slack", webhookURL: "https://hooks.slack.com/services/id/token"},
	} {
		t.Run("create_"+tt.channelType, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"name":             tt.channelType + " invalid global SMTP",
				"type":             tt.channelType,
				"enabled":          true,
				"uses_global_smtp": true,
				"webhook_url":      tt.webhookURL,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_channel") {
				t.Fatalf("non-email global SMTP create must fail, status=%d body=%s", res.Code, res.Body.String())
			}
		})
	}

	generic, err := mem.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "generic", Type: "generic", Enabled: true, WebhookURL: "https://example.com/hook/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	explicitReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+generic.ID, bytes.NewBufferString(`{"name":"generic","type":"generic","enabled":true,"uses_global_smtp":true}`))
	explicitReq.Header.Set("Authorization", "Bearer admin-token")
	explicitRes := httptest.NewRecorder()
	handler.ServeHTTP(explicitRes, explicitReq)
	if explicitRes.Code != http.StatusBadRequest || !strings.Contains(explicitRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("explicit non-email global SMTP update must fail, status=%d body=%s", explicitRes.Code, explicitRes.Body.String())
	}

	globalEmail, err := mem.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "global email", Type: "email", Enabled: true, UseGlobalSMTP: true, UseGlobalSMTPSet: true, EmailRecipients: []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inheritedReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+globalEmail.ID, bytes.NewBufferString(`{"name":"generic conversion","type":"generic","enabled":true,"webhook_url":"https://example.com/hook/token"}`))
	inheritedReq.Header.Set("Authorization", "Bearer admin-token")
	inheritedRes := httptest.NewRecorder()
	handler.ServeHTTP(inheritedRes, inheritedReq)
	if inheritedRes.Code != http.StatusBadRequest || !strings.Contains(inheritedRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("effective non-email global SMTP update must fail, status=%d body=%s", inheritedRes.Code, inheritedRes.Body.String())
	}
}

func TestPublicNotificationChannelProjectionOmitsInternalSecrets(t *testing.T) {
	channel := store.NotificationChannel{
		ID:                     "chn-secret",
		Name:                   "ops email",
		Type:                   "email",
		Enabled:                true,
		WebhookURL:             "https://discord.com/api/webhooks/id/raw-webhook-token",
		MaskedWebhookURL:       "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>",
		EmailRecipients:        []string{"ops@example.com"},
		SMTPHost:               "smtp.example.com",
		SMTPPort:               587,
		SMTPTLS:                true,
		SMTPFrom:               "autostream@example.com",
		SMTPUsername:           "smtp-user",
		SMTPPassword:           "raw-smtp-password",
		SMTPPasswordConfigured: true,
		MaskedEmailTarget:      "o***s@<EMAIL_DOMAIN>",
		SeverityFilter:         []string{"critical"},
		EventTypeFilter:        []string{"incident.opened"},
	}
	body, err := json.Marshal(publicNotificationChannel(channel))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(body)
	for _, leaked := range []string{
		"raw-webhook-token",
		"raw-smtp-password",
		"ops@example.com",
		"smtp.example.com",
		"autostream@example.com",
		"smtp-user",
		"email_recipients",
		"smtp_host",
		"smtp_from",
		"smtp_username",
	} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("public notification channel projection leaked %q: %s", leaked, raw)
		}
	}
	if strings.Contains(raw, `"webhook_url"`) {
		t.Fatalf("public notification channel projection leaked raw webhook field: %s", raw)
	}
	if strings.Contains(raw, `"smtp_password"`) {
		t.Fatalf("public notification channel projection leaked raw SMTP password field: %s", raw)
	}
	for _, want := range []string{`"smtp_password_configured":true`, `"masked_email_target":"o***s@\u003cEMAIL_DOMAIN\u003e"`, `"severity_filter":["critical"]`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("public notification channel projection missing %s: %s", want, raw)
		}
	}
}

func TestEmailNotificationChannelRejectsUnsafeSMTPConfig(t *testing.T) {
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil)
	cases := map[string]struct {
		body string
		code string
	}{
		"private_host":     {body: `{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com"],"smtp_host":"127.0.0.1","smtp_port":587,"smtp_tls":true,"smtp_from":"autostream@example.com"}`, code: "invalid_smtp_channel"},
		"auth_without_tls": {body: `{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com","smtp_port":587,"smtp_tls":false,"smtp_from":"autostream@example.com","smtp_username":"autostream","smtp_password":"raw-smtp-password"}`, code: "invalid_smtp_channel"},
		"header_injection": {body: `{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com\r\nBcc: bad@example.com"],"smtp_host":"smtp.example.com","smtp_port":587,"smtp_tls":true,"smtp_from":"autostream@example.com"}`, code: "invalid_notification_channel"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(tc.body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), tc.code) {
				t.Fatalf("create status=%d body=%s", res.Code, res.Body.String())
			}
			if strings.Contains(res.Body.String(), "raw-smtp-password") || strings.Contains(res.Body.String(), "127.0.0.1") {
				t.Fatalf("SMTP secret/target leaked in error response: %s", res.Body.String())
			}
		})
	}
}

func TestEmailNotificationChannelUpdateRejectsTLSDowngradeWithExistingCredentials(t *testing.T) {
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil)
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com","smtp_port":587,"smtp_tls":true,"smtp_from":"autostream@example.com","smtp_username":"autostream","smtp_password":"raw-smtp-password"}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create email channel status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com","smtp_port":587,"smtp_tls":false,"smtp_from":"autostream@example.com"}`))
	updateReq.Header.Set("Authorization", "Bearer admin-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusBadRequest || !strings.Contains(updateRes.Body.String(), "invalid_smtp_channel") {
		t.Fatalf("expected TLS downgrade to be rejected, status=%d body=%s", updateRes.Code, updateRes.Body.String())
	}
	if strings.Contains(updateRes.Body.String(), "raw-smtp-password") {
		t.Fatalf("SMTP password leaked in TLS downgrade response: %s", updateRes.Body.String())
	}
}

func TestEmailNotificationChannelUpdateKeepsTLSWhenOmitted(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil)
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"email ops","type":"email","enabled":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com","smtp_port":587,"smtp_tls":true,"smtp_from":"autostream@example.com","smtp_username":"autostream","smtp_password":"raw-smtp-password"}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create email channel status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"email ops renamed","type":"email","enabled":true}`))
	updateReq.Header.Set("Authorization", "Bearer admin-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("update without smtp_tls should preserve TLS, status=%d body=%s", updateRes.Code, updateRes.Body.String())
	}
	for _, raw := range []string{"raw-smtp-password", "ops@example.com", "smtp.example.com", "autostream@example.com", `"smtp_password"`, `"email_recipients"`, `"smtp_host"`, `"smtp_from"`, `"smtp_username"`} {
		if strings.Contains(updateRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in update response: %s", updateRes.Body.String())
		}
	}
	var updated store.NotificationChannel
	if err := json.NewDecoder(updateRes.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if !updated.SMTPPasswordConfigured || updated.Name != "email ops renamed" {
		t.Fatalf("email channel public update status missing: %#v", updated)
	}
	stored, err := mem.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.SMTPTLS || stored.SMTPPassword == "" || stored.SMTPHost != "smtp.example.com" || stored.SMTPFrom != "autostream@example.com" {
		t.Fatalf("email channel update did not preserve stored SMTP settings: %#v", stored)
	}
}

func TestNotificationChannelTestDoesNotExposeWebhookURL(t *testing.T) {
	t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-token", http.StatusForbidden)
	}))
	defer upstream.Close()

	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"generic main","type":"generic","enabled":true,"webhook_url":"`+upstream.URL+`/hook/secret-token"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+created.ID+"/test", nil)
	testReq.Header.Set("Authorization", "Bearer service-token")
	testRes := httptest.NewRecorder()
	handler.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusAccepted {
		t.Fatalf("test status = %d body = %s", testRes.Code, testRes.Body.String())
	}
	body := testRes.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, `"webhook_url"`) {
		t.Fatalf("webhook URL leaked in test response: %s", body)
	}
}

func TestEmailNotificationChannelTestDoesNotExposeSMTPDetails(t *testing.T) {
	st := store.NewMemoryStore()
	channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:              "ops email",
		Type:              "email",
		Enabled:           true,
		EmailRecipients:   []string{"ops@example.com"},
		MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+channel.ID+"/test", nil)
	testReq.Header.Set("Authorization", "Bearer service-token")
	testRes := httptest.NewRecorder()
	handler.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusAccepted {
		t.Fatalf("test status = %d body = %s", testRes.Code, testRes.Body.String())
	}
	body := testRes.Body.String()
	for _, raw := range []string{"ops@example.com", "smtp.example.com", "raw-smtp-password", `"email_recipients"`, `"smtp_host"`, `"smtp_from"`, `"smtp_username"`, `"smtp_password"`} {
		if strings.Contains(body, raw) {
			t.Fatalf("email notification test response leaked SMTP detail %q: %s", raw, body)
		}
	}
	if !strings.Contains(body, `o***s@\u003cEMAIL_DOMAIN\u003e`) || !strings.Contains(body, "send_failed") {
		t.Fatalf("email notification test response should include masked target and sanitized error: %s", body)
	}
}

func TestGlobalSMTPNotificationChannelTestUsesRelay(t *testing.T) {
	st := store.NewMemoryStore()
	channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "global email", Type: "email", Enabled: true, UseGlobalSMTP: true, EmailRecipients: []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeEmailRelay{}
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, relay)
	testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+channel.ID+"/test", nil)
	testReq.Header.Set("Authorization", "Bearer admin-token")
	testRes := httptest.NewRecorder()
	handler.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusAccepted || relay.calls != 1 || !strings.Contains(testRes.Body.String(), `"status":"success"`) {
		t.Fatalf("global relay test failed: calls=%d status=%d body=%s", relay.calls, testRes.Code, testRes.Body.String())
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil || len(deliveries) != 1 || deliveries[0].Status != "success" || deliveries[0].Channel != "email" {
		t.Fatalf("successful channel test was not saved to delivery history: deliveries=%#v err=%v", deliveries, err)
	}
}

func TestGlobalSMTPNotificationChannelTestReturnsSafeFailureCodes(t *testing.T) {
	for _, code := range []string{"smtp_not_configured", "rate_limited"} {
		t.Run(code, func(t *testing.T) {
			st := store.NewMemoryStore()
			channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
				Name: "global email", Type: "email", Enabled: true, UseGlobalSMTP: true, EmailRecipients: []string{"ops@example.com"},
			})
			if err != nil {
				t.Fatal(err)
			}
			relay := &fakeEmailRelay{err: fakeSafeEmailError(code)}
			handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, relay)
			testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+channel.ID+"/test", nil)
			testReq.Header.Set("Authorization", "Bearer admin-token")
			testRes := httptest.NewRecorder()
			handler.ServeHTTP(testRes, testReq)
			body := testRes.Body.String()
			if testRes.Code != http.StatusAccepted || relay.calls != 1 || !strings.Contains(body, `"status":"failure"`) || !strings.Contains(body, `"error":"`+code+`"`) || strings.Contains(body, "ops@example.com") {
				t.Fatalf("unexpected safe global relay failure: calls=%d status=%d body=%s", relay.calls, testRes.Code, body)
			}
			deliveries, err := st.ListNotificationDeliveries(t.Context())
			if err != nil || len(deliveries) != 1 || deliveries[0].Status != "failure" || deliveries[0].Error != code || deliveries[0].Channel != "email" {
				t.Fatalf("failed channel test was not safely saved to delivery history: deliveries=%#v err=%v", deliveries, err)
			}
		})
	}
}

func TestNotificationChannelRejectsNonHTTPWebhookURL(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"bad","type":"generic","enabled":true,"webhook_url":"ftp://example.com/hook/secret-token"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "secret-token") {
		t.Fatalf("webhook URL leaked in error response: %s", createRes.Body.String())
	}
}

func TestNotificationChannelRejectsPrivateWebhookURLByDefault(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"metadata","type":"generic","enabled":true,"webhook_url":"http://169.254.169.254/latest/meta-data"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_webhook_url") {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "169.254.169.254") {
		t.Fatalf("private target leaked in error response: %s", createRes.Body.String())
	}
}

func TestNotificationChannelRejectsPrivateWebhookURLInProductionEvenWhenEnvAllows(t *testing.T) {
	t.Setenv("OBSERVABILITY_ENV", "production")
	t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")

	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"local","type":"generic","enabled":true,"webhook_url":"http://127.0.0.1:8080/hook"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_webhook_url") {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "127.0.0.1") {
		t.Fatalf("private target leaked in error response: %s", createRes.Body.String())
	}
}

func TestNotificationDeliveryHistoryDoesNotExposeWebhookErrorSecrets(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), failingNotifier{})
	ingestReq := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
	ingestReq.Header.Set("Authorization", "Bearer service-token")
	ingestRes := httptest.NewRecorder()
	handler.ServeHTTP(ingestRes, ingestReq)
	if ingestRes.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d body = %s", ingestRes.Code, ingestRes.Body.String())
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	body := listRes.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, "discord.com/api/webhooks") {
		t.Fatalf("webhook secret leaked in delivery history: %s", body)
	}
	if !strings.Contains(body, "notification webhook delivery failed") {
		t.Fatalf("expected sanitized delivery error: %s", body)
	}
}

func TestDeliverNotificationEventOutlivesRequestCancellationWithinBoundedDeadline(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	server := &Server{serviceType: "observability", store: st, notifier: notifier}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	request := httptest.NewRequest(http.MethodPost, "/signals", nil).WithContext(requestContext)

	results := server.deliverNotificationEvent(request, "incident.opened", store.Incident{ID: "inc-detached", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder stopped."})
	if len(results) != 1 || results[0].Status != "success" || len(notifier.events) != 1 {
		t.Fatalf("request cancellation stopped notification delivery: results=%#v events=%#v", results, notifier.events)
	}
	if !notifier.hasDeadline {
		t.Fatal("detached notification delivery has no bounded deadline")
	}
	remaining := time.Until(notifier.deadline)
	if remaining <= 0 || remaining > notificationFanoutTimeout {
		t.Fatalf("unexpected detached delivery deadline: remaining=%s", remaining)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil || len(deliveries) != 1 || deliveries[0].IncidentID != "inc-detached" {
		t.Fatalf("detached delivery history was not saved: deliveries=%#v err=%v", deliveries, err)
	}
}

func TestSaveNotificationDeliveryResultsLogsSafeFailureAndContinues(t *testing.T) {
	const (
		targetSecret   = "https://discord.com/api/webhooks/id/target-secret"
		bodySecret     = "notification body contains body-secret"
		databaseSecret = "database connection failed with db-secret"
	)
	st := &failingNotificationDeliveryStore{
		Store: store.NewMemoryStore(),
		err:   errors.New(databaseSecret),
	}
	var output bytes.Buffer
	server := &Server{store: st, logger: log.New(&output, "", 0)}

	server.saveNotificationDeliveryResults(t.Context(), "incident.opened", store.Incident{
		ID:        "incident-secret-id",
		Rule:      "encoder_down",
		Severity:  "critical",
		SummaryJA: bodySecret,
	}, []notifications.DeliveryResult{
		{EventType: "admin.audit", Channel: "email", Target: targetSecret, Status: "success", Error: "smtp_auth_failed"},
		{Channel: "discord", Target: "https://example.com/second-target-secret", Status: "success"},
	})

	if st.attempts != 2 {
		t.Fatalf("notification delivery save attempts = %d, want 2", st.attempts)
	}
	logged := output.String()
	for _, want := range []string{
		`event_type="admin.audit" channel="email" status="failure"`,
		`event_type="incident.opened" channel="discord" status="success"`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("safe save failure log missing %q: %s", want, logged)
		}
	}
	for _, forbidden := range []string{targetSecret, "second-target-secret", bodySecret, databaseSecret, "smtp_auth_failed", "incident-secret-id"} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("notification delivery save failure log leaked %q: %s", forbidden, logged)
		}
	}
}

func TestNotificationDeliveryHistoryRedactsSecretsAfterSafeMarkers(t *testing.T) {
	st := store.NewMemoryStore()
	if _, err := st.SaveNotificationDelivery(t.Context(), store.NotificationDelivery{
		EventType: "admin.audit",
		Channel:   "discord",
		Status:    "success",
		Metadata: map[string]any{
			"action":  "raw.secret.token",
			"rule":    "secrets.ast_svc_raw_token",
			"summary": "<redacted> / opaque-value-that-must-not-survive",
		},
	}); err != nil {
		t.Fatal(err)
	}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), &eventRecordingNotifier{})
	req := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", res.Code, res.Body.String())
	}
	for _, raw := range []string{"raw.secret.token", "ast_svc_raw_token", "opaque-value-that-must-not-survive"} {
		if strings.Contains(res.Body.String(), raw) {
			t.Fatalf("compound marker secret %q leaked in delivery history: %s", raw, res.Body.String())
		}
	}
}

func TestNotificationPartialFailureKeepsSuccessfulDeliveries(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), partialFailureNotifier{})
	ingestReq := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
	ingestReq.Header.Set("Authorization", "Bearer service-token")
	ingestRes := httptest.NewRecorder()
	handler.ServeHTTP(ingestRes, ingestReq)
	if ingestRes.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d body = %s", ingestRes.Code, ingestRes.Body.String())
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	body := listRes.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, "discord.com/api/webhooks") || strings.Contains(body, "smtp-password") {
		t.Fatalf("notification secret leaked in delivery history: %s", body)
	}
	var deliveries []store.NotificationDelivery
	if err := json.Unmarshal(listRes.Body.Bytes(), &deliveries); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected success and failure deliveries to be preserved, got %#v", deliveries)
	}
	seen := map[string]string{}
	for _, delivery := range deliveries {
		seen[delivery.Channel] = delivery.Status
		if delivery.EventType != "incident.opened" || delivery.IncidentID == "" {
			t.Fatalf("unexpected delivery metadata: %#v", delivery)
		}
	}
	if seen["email"] != "success" || seen["discord"] != "failure" {
		t.Fatalf("expected email success and discord failure deliveries, got %#v", deliveries)
	}
}

func TestSignalIngestDoesNotEchoAuthorizationToken(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"bad":true}`))
	req.Header.Set("Authorization", "Bearer secret-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if strings.Contains(res.Body.String(), "secret-token") {
		t.Fatalf("token leaked in response: %s", res.Body.String())
	}
}

func TestSignalIngestRejectsSecretLikeTopLevelFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "service_id webhook URL", body: `{"type":"event","name":"encoder.process.exited","service_id":"https://discord.com/api/webhooks/id/secret-token","service_type":"encoder_recorder"}`},
		{name: "stream_id token", body: `{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"ast_ingest_v1.secret-token"}`},
		{name: "name token query", body: `{"type":"event","name":"encoder.process.exited?token=secret","service_id":"enc-01","service_type":"encoder_recorder"}`},
		{name: "status bearer", body: `{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","status":"Bearer secret-token"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := store.NewMemoryStore()
			handler := newTestServer(st)
			req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(tc.body))
			req.Header.Set("Authorization", "Bearer service-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_signal_identifier") {
				t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
			}
			if strings.Contains(res.Body.String(), "secret-token") || strings.Contains(res.Body.String(), "discord.com/api/webhooks") {
				t.Fatalf("unsafe top-level field leaked in response: %s", res.Body.String())
			}
			signals, err := st.ListSignals(t.Context(), 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(signals) != 0 {
				t.Fatalf("unsafe signal was persisted: %#v", signals)
			}
		})
	}
}

func TestSignalIngestRejectsUnknownFieldsAndOversizedBodies(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	for _, body := range []string{
		`{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","unexpected":true}`,
		`{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","attributes":{"padding":"` + strings.Repeat("x", maxJSONBodyBytes) + `"}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("oversized or unknown-field signal should be rejected: status=%d body=%s", res.Code, res.Body.String())
		}
	}
}

func TestSignalIngestRejectsWrongToken(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"event","name":"x","service_id":"svc","service_type":"worker"}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestSensitivePostEndpointsAreRateLimitedByClientAndEndpoint(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	body := `{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("request %d status = %d body = %s", i+1, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("third request status = %d body = %s", res.Code, res.Body.String())
	}

	otherClient := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	otherClient.RemoteAddr = "203.0.113.11:12345"
	otherClient.Header.Set("Authorization", "Bearer service-token")
	otherClientRes := httptest.NewRecorder()
	handler.ServeHTTP(otherClientRes, otherClient)
	if otherClientRes.Code != http.StatusAccepted {
		t.Fatalf("different client should have a separate rate bucket: status=%d body=%s", otherClientRes.Code, otherClientRes.Body.String())
	}
}

func TestSensitivePostRateLimitSharesBucketAcrossInvalidBearerValues(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	body := `{"type":"event","name":"x","service_id":"svc","service_type":"worker"}`
	for i, token := range []string{"wrong-token-1", "wrong-token-2"} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("invalid token request %d status = %d body = %s", i+1, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer wrong-token-3")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("third invalid-token request status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestSensitivePostRateLimitNormalizesDynamicActionPaths(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	for i, id := range []string{"one", "two"} {
		req := httptest.NewRequest(http.MethodPost, "/notification-channels/"+id+"/test", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("Authorization", "Bearer wrong-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("invalid notification test %d status = %d body = %s", i+1, res.Code, res.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/notification-channels/three/test", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer wrong-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("third dynamic-path request status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestSensitiveStateChangingEndpointsAreRateLimited(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/heartbeat"},
		{http.MethodPost, "/incidents/incident-1/acknowledge"},
		{http.MethodPost, "/incidents/incident-1/resolve"},
		{http.MethodPost, "/notification-channels"},
		{http.MethodPost, "/notification-events"},
		{http.MethodPut, "/notification-channels/channel-1"},
		{http.MethodDelete, "/notification-channels/channel-1"},
		{http.MethodPost, "/notification-channels/channel-1/test"},
		{http.MethodPost, "/remediation-actions/action-1/approve"},
		{http.MethodPost, "/remediation-actions/action-1/execute"},
	}
	for i, tc := range cases {
		remoteAddr := "203.0.113." + strconv.Itoa(30+i) + ":12345"
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = remoteAddr
			req.Header.Set("Authorization", "Bearer wrong-token-"+strconv.Itoa(requestIndex))
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s request %d status = %d body = %s", tc.method, tc.path, requestIndex+1, res.Code, res.Body.String())
			}
		}
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer wrong-token-3")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s third request status = %d body = %s", tc.method, tc.path, res.Code, res.Body.String())
		}
	}
}

func TestAuthenticatedReadEndpointsAreRateLimited(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	cases := []string{
		"/signals",
		"/metrics",
		"/diagnostics",
		"/incidents",
		"/incidents/incident-1",
		"/notification-deliveries",
		"/notification-channels",
		"/notification-channels/channel-1",
		"/remediation-actions",
	}
	for i, path := range cases {
		remoteAddr := "203.0.113." + strconv.Itoa(90+i) + ":12345"
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = remoteAddr
			req.Header.Set("Authorization", "Bearer wrong-token-"+strconv.Itoa(requestIndex))
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("GET %s request %d status = %d body = %s", path, requestIndex+1, res.Code, res.Body.String())
			}
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer wrong-token-3")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("GET %s third request status = %d body = %s", path, res.Code, res.Body.String())
		}
	}
}

func TestSensitiveRateLimitNormalizesAdditionalDynamicPaths(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "2")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	handler := newTestServer(store.NewMemoryStore())
	cases := []struct {
		method string
		paths  []string
	}{
		{http.MethodPost, []string{"/incidents/one/acknowledge", "/incidents/two/acknowledge", "/incidents/three/acknowledge"}},
		{http.MethodPost, []string{"/incidents/one/resolve", "/incidents/two/resolve", "/incidents/three/resolve"}},
		{http.MethodPost, []string{"/remediation-actions/one/approve", "/remediation-actions/two/approve", "/remediation-actions/three/approve"}},
		{http.MethodPost, []string{"/remediation-actions/one/execute", "/remediation-actions/two/execute", "/remediation-actions/three/execute"}},
		{http.MethodPut, []string{"/notification-channels/one", "/notification-channels/two", "/notification-channels/three"}},
		{http.MethodDelete, []string{"/notification-channels/one", "/notification-channels/two", "/notification-channels/three"}},
	}
	for i, tc := range cases {
		remoteAddr := "203.0.113." + strconv.Itoa(60+i) + ":12345"
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			req := httptest.NewRequest(tc.method, tc.paths[requestIndex], nil)
			req.RemoteAddr = remoteAddr
			req.Header.Set("Authorization", "Bearer wrong-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s request %d status = %d body = %s", tc.method, tc.paths[requestIndex], requestIndex+1, res.Code, res.Body.String())
			}
		}
		req := httptest.NewRequest(tc.method, tc.paths[2], nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer wrong-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s third normalized request status = %d body = %s", tc.method, tc.paths[2], res.Code, res.Body.String())
		}
	}
}

func TestRateLimitClientIPOnlyTrustsForwardedForFromTrustedProxy(t *testing.T) {
	t.Setenv("OBSERVABILITY_TRUSTED_PROXIES", "10.0.0.0/8")

	untrusted := httptest.NewRequest(http.MethodGet, "/signals", nil)
	untrusted.RemoteAddr = "198.51.100.10:54321"
	untrusted.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := clientIP(untrusted); got != "198.51.100.10" {
		t.Fatalf("untrusted proxy X-Forwarded-For should be ignored, got %q", got)
	}

	trusted := httptest.NewRequest(http.MethodGet, "/signals", nil)
	trusted.RemoteAddr = "10.1.2.3:54321"
	trusted.Header.Set("X-Forwarded-For", "203.0.113.99, 10.1.2.3")
	if got := clientIP(trusted); got != "203.0.113.99" {
		t.Fatalf("trusted proxy X-Forwarded-For should be used, got %q", got)
	}

	spoofedLeftmost := httptest.NewRequest(http.MethodGet, "/signals", nil)
	spoofedLeftmost.RemoteAddr = "10.1.2.3:54321"
	spoofedLeftmost.Header.Set("X-Forwarded-For", "198.51.100.66, 203.0.113.25")
	if got := clientIP(spoofedLeftmost); got != "203.0.113.25" {
		t.Fatalf("leftmost spoof before an untrusted client hop must be ignored, got %q", got)
	}

	malformed := httptest.NewRequest(http.MethodGet, "/signals", nil)
	malformed.RemoteAddr = "10.1.2.3:54321"
	malformed.Header.Set("X-Forwarded-For", "not-an-ip, 203.0.113.25")
	if got := clientIP(malformed); got != "10.1.2.3" {
		t.Fatalf("malformed forwarded chain must fall back to the peer address, got %q", got)
	}
}

func TestRateLimitClientIPDoesNotImplicitlyTrustLoopback(t *testing.T) {
	t.Setenv("OBSERVABILITY_TRUSTED_PROXIES", "")
	t.Setenv("AUTOSTREAM_TRUSTED_PROXIES", "")

	request := httptest.NewRequest(http.MethodGet, "/signals", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := clientIP(request); got != "127.0.0.1" {
		t.Fatalf("loopback proxy must be explicitly configured, got %q", got)
	}
}

func TestRateLimitMaxBucketsFailClosed(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BURST", "10")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", "60")
	t.Setenv("OBSERVABILITY_RATE_LIMIT_MAX_BUCKETS", "1")
	handler := newTestServer(store.NewMemoryStore())
	body := `{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`

	first := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	first.RemoteAddr = "203.0.113.10:12345"
	first.Header.Set("Authorization", "Bearer service-token")
	firstRes := httptest.NewRecorder()
	handler.ServeHTTP(firstRes, first)
	if firstRes.Code != http.StatusAccepted {
		t.Fatalf("first bucket status = %d body = %s", firstRes.Code, firstRes.Body.String())
	}

	second := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
	second.RemoteAddr = "203.0.113.11:12345"
	second.Header.Set("Authorization", "Bearer service-token")
	secondRes := httptest.NewRecorder()
	handler.ServeHTTP(secondRes, second)
	if secondRes.Code != http.StatusTooManyRequests {
		t.Fatalf("new bucket over max should be rate limited, status = %d body = %s", secondRes.Code, secondRes.Body.String())
	}
}

func TestRateLimitStoreBackendIsUsedWhenConfigured(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BACKEND", "store")
	st := &fakeRateLimitStore{MemoryStore: store.NewMemoryStore(), allowed: false}
	handler := NewServerWithStoreAndAuth("observability", st, auth.NewVerifierFromRawTokens("service-token"))

	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("store-backed limiter should reject request, status = %d body = %s", res.Code, res.Body.String())
	}
	if st.calls != 1 || len(st.keys) != 1 || !strings.Contains(st.keys[0], "203.0.113.10") {
		t.Fatalf("store-backed limiter was not called with client key: calls=%d keys=%#v", st.calls, st.keys)
	}
}

func TestRateLimitStoreBackendMissingFailsClosed(t *testing.T) {
	t.Setenv("OBSERVABILITY_RATE_LIMIT_BACKEND", "store")
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"event","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder"}`))
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), "rate_limit_unavailable") {
		t.Fatalf("missing shared limiter should fail closed, status = %d body = %s", res.Code, res.Body.String())
	}
}

func newTestServer(st store.Store) http.Handler {
	return NewServerWithStoreAndAuth("observability", st, auth.NewVerifierFromRawTokens("service-token"))
}

type failingNotificationDeliveryStore struct {
	store.Store
	err      error
	attempts int
}

func (s *failingNotificationDeliveryStore) SaveNotificationDelivery(context.Context, store.NotificationDelivery) (store.NotificationDelivery, error) {
	s.attempts++
	return store.NotificationDelivery{}, s.err
}

type fakeRateLimitStore struct {
	*store.MemoryStore
	allowed bool
	err     error
	calls   int
	keys    []string
}

func (s *fakeRateLimitStore) AllowRateLimit(ctx context.Context, bucketKey string, window time.Duration, burst int, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.calls++
	s.keys = append(s.keys, bucketKey)
	if s.err != nil {
		return false, s.err
	}
	return s.allowed, nil
}

type fakeNotifier struct {
	count int
}

type fakeEmailRelay struct {
	calls int
	err   error
}

type fakeSafeEmailError string

func (e fakeSafeEmailError) Error() string            { return string(e) }
func (e fakeSafeEmailError) SafeDeliveryCode() string { return string(e) }

func (f *fakeEmailRelay) SendNotificationEmail(_ context.Context, _ []string, _, _ string) error {
	f.calls++
	return f.err
}

func (n *fakeNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.count++
	return []notifications.DeliveryResult{{EventType: "incident.opened", Channel: "generic", Target: "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>", Status: "success"}}, nil
}

type eventRecordingNotifier struct {
	events      []string
	incidents   []store.Incident
	deadline    time.Time
	hasDeadline bool
}

func (n *eventRecordingNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	return n.NotifyIncidentEvent(ctx, "incident.opened", incident)
}

func (n *eventRecordingNotifier) NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.deadline, n.hasDeadline = ctx.Deadline()
	n.events = append(n.events, eventType)
	n.incidents = append(n.incidents, incident)
	return []notifications.DeliveryResult{{EventType: eventType, Channel: "slack", Target: "https://hooks.slack.com/<WEBHOOK_PATH>", Status: "success"}}, nil
}

type failingNotifier struct{}

func (f failingNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("Post \"https://discord.com/api/webhooks/id/secret-token\": forbidden")
}

type partialFailureNotifier struct{}

func (p partialFailureNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]notifications.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []notifications.DeliveryResult{
		{EventType: "incident.opened", Channel: "email", Target: "o***s@<EMAIL_DOMAIN>", Status: "success"},
		{EventType: "incident.opened", Channel: "discord", Target: "https://discord.com/api/webhooks/id/secret-token", Status: "failure", Error: "Post \"https://discord.com/api/webhooks/id/secret-token\": forbidden with smtp-password"},
	}, errors.New("partial notification failure")
}

type fakeControlExecutor struct {
	calls []control.RemediationRequest
	err   error
}

func (f *fakeControlExecutor) ExecuteRemediation(ctx context.Context, req control.RemediationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, req)
	return nil
}

func writeNodeConfigForVerifierTest(t *testing.T, path, nodeType string) {
	t.Helper()
	body := `panel:
  url: "https://panel.example.jp"
node:
  id: "observability-01"
  name: "Observability 01"
  type: "` + nodeType + `"
api:
  host: "observability.example.jp"
  port: 8443
  ssl_enabled: true
auth:
  token_id: "token-id"
  token: "runtime-secret"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
