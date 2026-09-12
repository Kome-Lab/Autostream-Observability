package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/store"
)

func TestRepeatedManualResolveDoesNotDuplicateNotification(t *testing.T) {
	st := store.NewMemoryStore()
	incident, _, err := st.UpsertIncident(t.Context(), store.Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), notifier)
	for range 2 {
		req := httptest.NewRequest(http.MethodPost, "/incidents/"+incident.ID+"/resolve", nil)
		req.Header.Set("Authorization", "Bearer service-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("resolve status = %d body = %s", res.Code, res.Body.String())
		}
	}
	if len(notifier.events) != 1 || notifier.events[0] != "incident.resolved" {
		t.Fatalf("idempotent resolve duplicated lifecycle notification: %#v", notifier.events)
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
