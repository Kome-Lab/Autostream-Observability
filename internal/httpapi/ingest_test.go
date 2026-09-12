package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
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

func TestSignalRecoveryResolvesActiveIncidentWithoutOpeningRecoveryIncident(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor(
		"observability",
		st,
		auth.NewVerifierFromRawTokens("service-token"),
		auth.NewVerifierFromRawTokens("service-token"),
		notifier,
		nil,
	)
	baseline := `{"type":"metric","name":"discord.audio_forward_errors_total","service_id":"bot-01","service_type":"discord_bot","stream_id":"stream-01","value":0,"attributes":{"stream_live":true,"discord.audio_forwarded_total":20,"discord.audio_last_forward_age_sec":1}}`
	failed := `{"type":"metric","name":"discord.audio_forward_errors_total","service_id":"bot-01","service_type":"discord_bot","stream_id":"stream-01","value":3,"attributes":{"stream_live":true,"discord.audio_forwarded_total":20,"discord.audio_last_forward_age_sec":9}}`
	recovered := `{"type":"metric","name":"discord.audio_forward_errors_total","service_id":"bot-01","service_type":"discord_bot","stream_id":"stream-01","value":3,"attributes":{"stream_live":true,"discord.audio_forwarded_total":21,"discord.audio_last_forward_age_sec":1}}`
	for _, body := range []string{baseline, failed, recovered} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("signal status = %d body = %s", res.Code, res.Body.String())
		}
	}
	incidents, err := st.ListIncidents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].Rule != "discord_audio_forward_failed" || incidents[0].Status != "resolved" {
		t.Fatalf("recovery did not converge incident lifecycle: %#v", incidents)
	}
	if incidents[0].ResolvedBySignalID == "" || incidents[0].ResolutionReason != "recent_forward_succeeded" {
		t.Fatalf("recovery provenance is missing: %#v", incidents[0])
	}
	if len(notifier.events) != 2 || notifier.events[0] != "incident.opened" || notifier.events[1] != "incident.resolved" {
		t.Fatalf("unexpected lifecycle notifications: %#v", notifier.events)
	}
}

func TestSignalIncidentSeverityEscalationSendsOneUpdatedNotification(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), notifier)
	for _, body := range []string{
		`{"type":"metric","name":"discord.audio_forward_errors_total","service_id":"bot-01","service_type":"discord_bot","stream_id":"stream-01","value":0,"attributes":{"stream_live":true}}`,
		`{"type":"metric","name":"discord.audio_forward_errors_total","service_id":"bot-01","service_type":"discord_bot","stream_id":"stream-01","value":1,"attributes":{"stream_live":true}}`,
		`{"type":"metric","name":"discord.audio_forward_errors_total","service_id":"bot-01","service_type":"discord_bot","stream_id":"stream-01","value":100,"attributes":{"stream_live":true}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("signal status = %d body = %s", res.Code, res.Body.String())
		}
	}
	incidents, err := st.ListIncidents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].Severity != "error" {
		t.Fatalf("severity escalation did not converge active incident: %#v", incidents)
	}
	if len(notifier.events) != 2 || notifier.events[0] != "incident.opened" || notifier.events[1] != "incident.updated" {
		t.Fatalf("unexpected severity lifecycle notifications: %#v", notifier.events)
	}
}

func TestCumulativeCounterBaselineUnchangedAndResetDoNotCreateIncidents(t *testing.T) {
	st := store.NewMemoryStore()
	handler := newTestServer(st)
	for _, value := range []int{42, 42, 1} {
		body := fmt.Sprintf(`{"type":"metric","name":"worker.event_send_failures_total","service_id":"worker-01","service_type":"worker","value":%d}`, value)
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("signal status = %d body = %s", res.Code, res.Body.String())
		}
	}
	incidents, err := st.ListIncidents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 0 {
		t.Fatalf("baseline, unchanged total, or process reset must not create incidents: %#v", incidents)
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
	var res *httptest.ResponseRecorder
	for _, value := range []int{0, 1} {
		req := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(fmt.Sprintf(`{"type":"metric","name":"worker.event_send_failures_total","service_id":"worker-01","service_type":"worker","stream_id":"stream-01","value":%d}`, value)))
		req.Header.Set("Authorization", "Bearer service-token")
		res = httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusAccepted {
			t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
		}
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

func TestSignalIncidentSendsOneConsolidatedNotification(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), notifier)
	request := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
	request.Header.Set("Authorization", "Bearer service-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("signal status = %d body = %s", response.Code, response.Body.String())
	}
	if len(notifier.events) != 1 || notifier.events[0] != "incident.opened" {
		t.Fatalf("one incident must produce one consolidated notification: %#v", notifier.events)
	}
	if len(notifier.incidents) != 1 || len(notifier.incidents[0].Report.RecommendedActions) == 0 {
		t.Fatalf("consolidated notification lost diagnostics or actions: %#v", notifier.incidents)
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
