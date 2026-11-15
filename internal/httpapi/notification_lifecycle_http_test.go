package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	lc "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle"
	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

func TestWS5ExplicitUnconfiguredDoesNotFallback(t *testing.T) {
	notifier := &eventRecordingNotifier{}
	server := &Server{serviceType: "observability", store: store.NewMemoryStore(), adminAuth: auth.NewVerifierFromRawTokens("fixture-admin"), notifier: notifier}
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","action":"streams.start","resource_type":"stream","resource_id":"fixture-stream"}`))
	req.Header.Set("Authorization", "Bearer fixture-admin")
	req.Header.Set("X-Autostream-Lifecycle", "{}")
	res := httptest.NewRecorder()
	server.createNotificationEvent(res, req)
	if res.Code != http.StatusServiceUnavailable || len(notifier.events) != 0 {
		t.Fatalf("explicit v3 request fell back: status=%d calls=%d", res.Code, len(notifier.events))
	}
}

type httpEffectGate struct {
	frame notifications.CurrentEffectFrame
}

func (g httpEffectGate) WithCurrent(ctx context.Context, _ lc.Record, fn func(notifications.CurrentEffectFrame) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(g.frame)
}

type httpEffectProvider struct {
	calls   atomic.Int32
	ackLost bool
}

func (p *httpEffectProvider) Dispatch(_ context.Context, r lc.Record) (lc.BoundaryObservation, error) {
	p.calls.Add(1)
	if p.ackLost {
		return lc.BoundaryObservation{}, errors.New("synthetic provider ACK lost")
	}
	v := lc.SuccessAtBoundary
	return lc.BoundaryObservation{Address: lc.BoundaryAddress{Kind: lc.Provider, OwnerID: r.Effect.Target.OwnerID, Resource: r.Effect.Target, SubBoundary: lc.RemoteAccept}, Knowledge: lc.Known, Presence: lc.Present, Outcome: lc.Fact[lc.Outcome]{State: lc.Observed, Value: &v, Observation: &lc.ObservationContext{OwnerID: r.Effect.Target.OwnerID, FrameRef: "provider-frame-fixture-1", Scope: r.Header.DomainRef.DomainID, SourceRevision: 1}}}, nil
}
func newWS5HTTPFixture(t *testing.T) (*httptest.Server, lc.Record, *httpEffectProvider, *eventRecordingNotifier, string) {
	return newWS5HTTPFixtureMode(t, "provider-accepted-local-known")
}

type httpEffectFaultJournal struct {
	notifications.EffectJournal
	updates atomic.Int32
}

func (j *httpEffectFaultJournal) Update(ctx context.Context, id lc.ID, fn func(*notifications.StoredEffect) (notifications.StoredEffect, error)) (notifications.StoredEffect, error) {
	e, err := j.EffectJournal.Update(ctx, id, fn)
	if j.updates.Add(1) == 3 && err == nil {
		return e, notifications.ErrEffectCommitUnknown
	}
	return e, err
}
func newWS5HTTPFixtureMode(t *testing.T, mode string) (*httptest.Server, lc.Record, *httpEffectProvider, *eventRecordingNotifier, string) {
	t.Helper()
	var profile lc.ComparisonProfile
	b, err := os.ReadFile("../notifications/testdata/effect-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &profile); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("../notifications/testdata/effect-request.json")
	if err != nil {
		t.Fatal(err)
	}
	r, result := lc.DecodeRecord(b, profile)
	if result.Kind != lc.StructurallyCoherent {
		t.Fatalf("fixed input invalid: %+v", result)
	}
	journalPath := filepath.Join(t.TempDir(), "notification-effects.fixture.json")
	j, err := notifications.NewFixtureEffectJournal(journalPath, notifications.EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	provider := &httpEffectProvider{ackLost: mode == "provider-ack-unknown"}
	var journal notifications.EffectJournal = j
	if mode == "provider-accepted-local-unknown" {
		journal = &httpEffectFaultJournal{EffectJournal: j}
	}
	dispatcher, err := notifications.NewFixtureEffectDispatcher(profile, journal, httpEffectGate{notifications.CurrentEffectFrame{ReadFrame: lc.SourceFrame{FrameRef: "trusted-owner-read-frame-1", OwnerID: "notification-owner", Scope: "notification-domain", SourceRevision: 1}, ImmutableRequest: r, Domain: r.Header.DomainRef, Producer: r.Header.ProducerRef, Target: r.Effect.Target, Vector: r.Effect.SourceVector, Allowed: true}}, provider, notifications.EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &eventRecordingNotifier{}
	handler := NewServerWithFixtureNotificationEffects("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("fixture-ingest"), auth.NewVerifierFromRawTokens("fixture-admin"), legacy, dispatcher)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, r, provider, legacy, journalPath
}
func ws5HTTPRequest(t *testing.T, server *httptest.Server, method, path string, r lc.Record, authorized bool) (int, []byte) {
	t.Helper()
	header, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, strings.NewReader(`{"summary":"fixture-private-body","webhook_url":"https://fixture.invalid/private","credential":"fixture-private-credential"}`))
	if err != nil {
		t.Fatal(err)
	}
	if authorized {
		req.Header.Set("Authorization", "Bearer fixture-admin")
	}
	req.Header.Set(notificationLifecycleHeader, string(header))
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, data
}
func TestWS5NotificationHTTPBoundaries(t *testing.T) {
	server, r, provider, legacy, journalPath := newWS5HTTPFixture(t)
	status, data := ws5HTTPRequest(t, server, http.MethodPost, "/notification-events", r, true)
	if status != http.StatusOK || provider.calls.Load() != 1 || len(legacy.events) != 0 {
		t.Fatalf("real caller status=%d typed calls=%d legacy=%d", status, provider.calls.Load(), len(legacy.events))
	}
	var result lc.Record
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Inspection == nil || result.Header.Correlation != r.Header.Correlation || result.Inspection.Observations.Gate != lc.NotQualified {
		t.Fatal("wrong typed response")
	}
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = ws5HTTPRequest(t, server, http.MethodGet, "/v3/notification-effects/"+string(r.Effect.EffectID)+"/"+string(r.Header.Correlation.AttemptID), r, true)
	if status != http.StatusOK || provider.calls.Load() != 1 {
		t.Fatal("Inspect sent again")
	}
	after, _ := os.ReadFile(journalPath)
	if !bytes.Equal(before, after) {
		t.Fatal("HTTP Inspect changed journal")
	}
	for _, secret := range []string{"fixture-private-body", "fixture.invalid", "fixture-private-credential"} {
		if bytes.Contains(after, []byte(secret)) || bytes.Contains(data, []byte(secret)) {
			t.Fatal("raw notification data escaped")
		}
	}
	for _, name := range []string{"provider-accepted-local-known", "provider-ack-unknown", "provider-accepted-local-unknown"} {
		t.Run(name, func(t *testing.T) {
			server, r, provider, legacy, _ := newWS5HTTPFixtureMode(t, name)
			status, data := ws5HTTPRequest(t, server, http.MethodPost, "/notification-events", r, true)
			wantStatus := http.StatusOK
			if name == "provider-accepted-local-unknown" {
				wantStatus = http.StatusServiceUnavailable
			}
			if status != wantStatus || provider.calls.Load() != 1 || len(legacy.events) != 0 {
				t.Fatal("cross result did not traverse real typed Caller exactly once")
			}
			var actual lc.Record
			if err := json.Unmarshal(data, &actual); err != nil {
				t.Fatal(err)
			}
			if actual.Inspection == nil || actual.Header.ContractRef.ContractID != lc.CC08 || actual.Header.ContractRef.ModuleCommitRef != notifications.LifecycleModuleCommit || actual.Inspection.Observations.Gate != lc.NotQualified || actual.Header.Correlation != r.Header.Correlation {
				t.Fatal("cross output changed contract or qualification")
			}
			facts := map[lc.SubBoundary]lc.BoundaryObservation{}
			for _, o := range actual.Inspection.Observations.Observations {
				facts[o.Address.SubBoundary] = o
			}
			providerKnowledge, localKnowledge := lc.Known, lc.Known
			if name == "provider-ack-unknown" {
				providerKnowledge = lc.KnowledgeUnknown
			}
			if name == "provider-accepted-local-unknown" {
				localKnowledge = lc.KnowledgeUnknown
			}
			if facts[lc.Intent].Knowledge != lc.Known || facts[lc.DispatchPossible].Knowledge != lc.Known || facts[lc.RemoteAccept].Knowledge != providerKnowledge || facts[lc.LocalResultRecord].Knowledge != localKnowledge {
				t.Fatal("cross output contradicts independent literal boundary oracle")
			}
			if _, ok := facts[lc.RemoteTerminal]; ok {
				t.Fatal("acceptance became remote delivery proof")
			}
			// Export actual observations only after independent literal assertions;
			// expected fixtures above were authored separately, not from this output.
			if directory := os.Getenv("WS5_CROSS_RESULT_DIR"); directory != "" {
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(filepath.Join(directory, name+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.Write(data)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatal("cross output write failed")
				}
			}
		})
	}
}
func TestWS5NotificationHTTPCorrelation(t *testing.T) {
	server, r, provider, _, _ := newWS5HTTPFixture(t)
	if status, _ := ws5HTTPRequest(t, server, http.MethodPost, "/notification-events", r, true); status != http.StatusOK {
		t.Fatal(status)
	}
	for _, path := range []string{"/v3/notification-effects/wrong/" + string(r.Header.Correlation.AttemptID), "/v3/notification-effects/" + string(r.Effect.EffectID) + "/wrong"} {
		if status, _ := ws5HTTPRequest(t, server, http.MethodGet, path, r, true); status != http.StatusConflict {
			t.Fatal("wrong lookup tuple accepted")
		}
	}
	r.Header.Correlation.AttemptID = "other-attempt"
	if status, _ := ws5HTTPRequest(t, server, http.MethodPost, "/notification-events", r, true); status != http.StatusConflict {
		t.Fatal("new attempt escaped UNKNOWN/old effect")
	}
	if provider.calls.Load() != 1 {
		t.Fatal("correlation test resent")
	}
}
func TestWS5NotificationHTTPAuth(t *testing.T) {
	server, r, provider, legacy, _ := newWS5HTTPFixture(t)
	for _, path := range []string{"/notification-events", "/v3/notification-effects/" + string(r.Effect.EffectID) + "/" + string(r.Header.Correlation.AttemptID)} {
		method := http.MethodPost
		if strings.HasPrefix(path, "/v3/") {
			method = http.MethodGet
		}
		if status, _ := ws5HTTPRequest(t, server, method, path, r, false); status != http.StatusUnauthorized {
			t.Fatal("unauthorized v3 entry accepted")
		}
	}
	if provider.calls.Load() != 0 || len(legacy.events) != 0 {
		t.Fatal("auth refusal dispatched")
	}
}
