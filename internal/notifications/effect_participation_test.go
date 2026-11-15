package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	lc "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle"
)

type effectFixtureGate struct {
	mu          sync.Mutex
	frame       CurrentEffectFrame
	calls       int
	afterIntent func()
}

func (g *effectFixtureGate) WithCurrent(ctx context.Context, _ lc.Record, fn func(CurrentEffectFrame) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	g.calls++
	first := g.calls == 1
	err := fn(clone(g.frame))
	g.mu.Unlock()
	if first && err == nil && g.afterIntent != nil {
		g.afterIntent()
	}
	return err
}

type effectFixtureProvider struct {
	calls       atomic.Int32
	ackLost     bool
	journalPath string
	insideLock  atomic.Bool
}

func (p *effectFixtureProvider) Dispatch(_ context.Context, r lc.Record) (lc.BoundaryObservation, error) {
	p.calls.Add(1)
	if _, err := os.Stat(p.journalPath + ".lock"); err == nil {
		p.insideLock.Store(true)
	}
	if p.ackLost {
		return lc.BoundaryObservation{}, errors.New("fixture-only provider body and credential must never escape")
	}
	v := lc.SuccessAtBoundary
	return lc.BoundaryObservation{Address: boundary(r, lc.Provider, lc.RemoteAccept), Knowledge: lc.Known, Presence: lc.Present, Outcome: lc.Fact[lc.Outcome]{State: lc.Observed, Value: &v, Observation: &lc.ObservationContext{OwnerID: r.Effect.Target.OwnerID, FrameRef: "provider-frame-fixture-1", Scope: r.Header.DomainRef.DomainID, SourceRevision: 1}}}, nil
}

type effectFaultJournal struct {
	EffectJournal
	calls        atomic.Int32
	failAt       int32
	afterCommit  bool
	beginACKLost bool
}

func (j *effectFaultJournal) BeginAttempt(ctx context.Context, r lc.Record) (bool, error) {
	created, err := j.EffectJournal.BeginAttempt(ctx, r)
	if j.beginACKLost && err == nil && created {
		return false, ErrEffectCommitUnknown
	}
	return created, err
}

func (j *effectFaultJournal) Update(ctx context.Context, id lc.ID, fn func(*StoredEffect) (StoredEffect, error)) (StoredEffect, error) {
	call := j.calls.Add(1)
	if call == j.failAt && !j.afterCommit {
		return StoredEffect{}, ErrEffectCommitUnknown
	}
	e, err := j.EffectJournal.Update(ctx, id, fn)
	if call == j.failAt && err == nil {
		return e, ErrEffectCommitUnknown
	}
	return e, err
}
func effectInputs(t *testing.T) (lc.Record, lc.ComparisonProfile) {
	t.Helper()
	var p lc.ComparisonProfile
	b, err := os.ReadFile("testdata/effect-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/effect-request.json")
	if err != nil {
		t.Fatal(err)
	}
	r, result := lc.DecodeRecord(b, p)
	if result.Kind != lc.StructurallyCoherent {
		t.Fatalf("independent input vector: %+v", result)
	}
	return r, p
}
func effectSetup(t *testing.T) (lc.Record, lc.ComparisonProfile, *FixtureEffectJournal, *effectFixtureGate, *effectFixtureProvider, *EffectDispatcher) {
	t.Helper()
	r, p := effectInputs(t)
	path := filepath.Join(t.TempDir(), "notification-effects.fixture.json")
	j, err := NewFixtureEffectJournal(path, EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	g := &effectFixtureGate{frame: CurrentEffectFrame{ReadFrame: lc.SourceFrame{FrameRef: "trusted-owner-read-frame-1", OwnerID: "notification-owner", Scope: "notification-domain", SourceRevision: 1}, ImmutableRequest: clone(r), Domain: clone(r.Header.DomainRef), Producer: r.Header.ProducerRef, Target: r.Effect.Target, Vector: clone(r.Effect.SourceVector), Allowed: true}}
	provider := &effectFixtureProvider{journalPath: path}
	d, err := NewFixtureEffectDispatcher(p, j, g, provider, EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	return r, p, j, g, provider, d
}
func effectObservation(t *testing.T, r lc.Record, kind lc.BoundaryKind, sub lc.SubBoundary) lc.BoundaryObservation {
	t.Helper()
	if r.Inspection == nil {
		t.Fatal("missing CC08")
	}
	for _, o := range r.Inspection.Observations.Observations {
		if o.Address.Kind == kind && o.Address.SubBoundary == sub {
			return o
		}
	}
	t.Fatalf("missing boundary %s/%s", kind, sub)
	return lc.BoundaryObservation{}
}
func TestWS5EffectBoundaries(t *testing.T) {
	r, p, j, _, provider, d := effectSetup(t)
	result, err := d.Dispatch(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 || provider.insideLock.Load() {
		t.Fatal("provider count/transaction boundary")
	}
	for _, b := range p.RequiredBoundaries {
		o := effectObservation(t, result, b.Kind, b.SubBoundary)
		if o.Knowledge != lc.Known || o.Outcome.Value == nil || *o.Outcome.Value != lc.SuccessAtBoundary {
			t.Fatalf("expected known boundary %s: %+v", b.SubBoundary, o)
		}
	}
	if result.Inspection.Observations.Gate != lc.NotQualified || d.ProductionQualified() {
		t.Fatal("fixture qualified production")
	}
	if v := lc.ValidateRecord(result, p); v.Kind != lc.PendingObligation && v.Kind != lc.NeedsEvidence {
		t.Fatalf("invalid result DTO: %+v", v)
	}
	stored, ok, err := j.Read(t.Context(), r.Effect.EffectID)
	if err != nil || !ok || stored.Model.DispatchState != lc.MayDispatch {
		t.Fatal("durable dispatch marker missing")
	}
}

func TestWS5FixedConsumerVectors(t *testing.T) {
	for _, name := range []string{"provider-accepted-local-known", "provider-ack-unknown", "provider-accepted-local-unknown"} {
		t.Run(name, func(t *testing.T) {
			r, p, j, g, provider, d := effectSetup(t)
			data, err := os.ReadFile("testdata/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var expected lc.Record
			if err = json.Unmarshal(data, &expected); err != nil {
				t.Fatal(err)
			}
			validation := lc.ValidateRecord(expected, p)
			if validation.Kind != lc.Unknown && validation.Kind != lc.NeedsEvidence && validation.Kind != lc.PendingObligation {
				t.Fatalf("invalid independent consumer vector: %+v", validation)
			}
			if name == "provider-ack-unknown" {
				provider.ackLost = true
			}
			if name == "provider-accepted-local-unknown" {
				d, err = NewFixtureEffectDispatcher(p, &effectFaultJournal{EffectJournal: j, failAt: 3, afterCommit: true}, g, provider, EffectFixtureProfile)
				if err != nil {
					t.Fatal(err)
				}
			}
			actual, _ := d.Dispatch(t.Context(), r)
			if name == "provider-accepted-local-known" && !reflect.DeepEqual(actual, expected) {
				t.Fatalf("candidate does not match independently authored full CC08 vector: actual=%+v expected=%+v", actual, expected)
			}
			for _, wanted := range expected.Inspection.Observations.Observations {
				got := effectObservation(t, actual, wanted.Address.Kind, wanted.Address.SubBoundary)
				if got.Knowledge != wanted.Knowledge || got.Presence != wanted.Presence || got.Outcome.State != wanted.Outcome.State || (got.Outcome.Value == nil) != (wanted.Outcome.Value == nil) || got.Outcome.Value != nil && *got.Outcome.Value != *wanted.Outcome.Value {
					t.Fatalf("boundary changed: %+v", got)
				}
			}
		})
	}
}
func TestWS5EffectRefusal(t *testing.T) {
	for _, name := range []string{"authority", "target", "generation", "content", "attempt", "profile", "module", "secret-ref", "read-frame", "read-frame-owner", "read-frame-scope"} {
		t.Run(name, func(t *testing.T) {
			r, _, _, g, provider, d := effectSetup(t)
			switch name {
			case "authority":
				g.frame.Allowed = false
			case "target":
				r.Effect.Target.ResourceID = "other-channel"
			case "generation":
				*g.frame.Vector[0].Value.Uint64 = 2
			case "content":
				r.Effect.ContentRef.Ref = "other-content"
			case "attempt":
				r.Header.Correlation.AttemptID = "other-attempt"
			case "profile":
				r.Header.ProfileRef.Revision = 2
			case "module":
				r.Header.ContractRef.ModuleCommitRef = "0000000000000000000000000000000000000000"
			case "secret-ref":
				r.Effect.ContentRef.Ref = "https://fixture.invalid/private"
			case "read-frame":
				g.frame.ReadFrame = lc.SourceFrame{}
			case "read-frame-owner":
				g.frame.ReadFrame.OwnerID = "other-owner"
			case "read-frame-scope":
				g.frame.ReadFrame.Scope = "other-domain"
			}
			result, err := d.Dispatch(t.Context(), r)
			if err == nil || provider.calls.Load() != 0 {
				t.Fatalf("refusal dispatched: %v calls=%d", err, provider.calls.Load())
			}
			if result.Inspection != nil {
				t.Fatal("refusal echoed unverified request as trusted coverage")
			}
		})
	}
}
func TestWS5IntentRevocationBarrier(t *testing.T) {
	for _, change := range []string{"revocation", "generation"} {
		t.Run(change, func(t *testing.T) {
			r, _, j, g, provider, d := effectSetup(t)
			entered, release := make(chan struct{}), make(chan struct{})
			g.afterIntent = func() { close(entered); <-release }
			done := make(chan error, 1)
			go func() { _, err := d.Dispatch(t.Context(), r); done <- err }()
			<-entered
			stored, ok, err := j.Read(t.Context(), r.Effect.EffectID)
			if err != nil || !ok || stored.Model.DispatchState != lc.IntentRecorded {
				t.Fatal("barrier not after committed intent")
			}
			g.mu.Lock()
			if change == "revocation" {
				g.frame.Allowed = false
			} else {
				*g.frame.Vector[0].Value.Uint64 = 2
			}
			g.mu.Unlock()
			close(release)
			if err := <-done; err == nil || provider.calls.Load() != 0 {
				t.Fatal("stale post-intent dispatch")
			}
		})
	}
}
func TestWS5EffectACKAndJournalUnknown(t *testing.T) {
	for _, name := range []string{"provider-ack", "begin-ack", "intent-before", "intent-ack", "dispatch-ack", "result-before", "result-ack"} {
		t.Run(name, func(t *testing.T) {
			r, p, j, g, provider, d := effectSetup(t)
			if name == "provider-ack" {
				provider.ackLost = true
			} else {
				fault := &effectFaultJournal{EffectJournal: j, afterCommit: true}
				switch name {
				case "begin-ack":
					fault.beginACKLost = true
				case "intent-before":
					fault.failAt = 1
					fault.afterCommit = false
				case "intent-ack":
					fault.failAt = 1
				case "dispatch-ack":
					fault.failAt = 2
				case "result-before":
					fault.failAt = 3
					fault.afterCommit = false
				case "result-ack":
					fault.failAt = 3
				}
				var err error
				d, err = NewFixtureEffectDispatcher(p, fault, g, provider, EffectFixtureProfile)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, _ := d.Dispatch(t.Context(), r)
			if name == "begin-ack" || name == "intent-before" || name == "intent-ack" {
				if result.Inspection == nil || result.Inspection.Coverage.State != lc.Unavailable || result.Inspection.Coverage.Observation != nil || len(result.Inspection.SourceFrames) != 1 || result.Inspection.SourceFrames[0] != g.frame.ReadFrame {
					t.Fatal("missing journal invented persisted coverage/frame")
				}
				for _, o := range result.Inspection.Observations.Observations {
					if o.Knowledge != lc.KnowledgeUnknown || o.Outcome.State != lc.Unavailable {
						t.Fatal("missing journal invented known effect state")
					}
				}
				if checked := lc.ValidateRecord(result, p); checked.Kind != lc.Unknown {
					t.Fatalf("unknown result violates frozen DTO: %+v", checked)
				}
			}
			if name == "provider-ack" {
				if o := effectObservation(t, result, lc.Provider, lc.RemoteAccept); o.Knowledge != lc.KnowledgeUnknown {
					t.Fatal("lost provider ACK became success")
				}
			} else if name == "result-before" || name == "result-ack" {
				if o := effectObservation(t, result, lc.Provider, lc.RemoteAccept); o.Knowledge != lc.Known {
					t.Fatal("local uncertainty erased known provider accept")
				}
				if o := effectObservation(t, result, lc.LocalPersistence, lc.LocalResultRecord); o.Knowledge != lc.KnowledgeUnknown {
					t.Fatal("unknown local result became success")
				}
			} else if provider.calls.Load() != 0 {
				t.Fatal("uncertain intent/claim dispatched")
			}
			calls := provider.calls.Load()
			_, _ = d.Dispatch(t.Context(), r)
			_, _ = d.Inspect(t.Context(), r)
			if provider.calls.Load() != calls {
				t.Fatal("UNKNOWN caused re-dispatch")
			}
		})
	}
}
func TestWS5EffectRestartNoRedispatch(t *testing.T) {
	r, p, j, g, provider, d := effectSetup(t)
	provider.ackLost = true
	if _, err := d.Dispatch(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewFixtureEffectJournal(j.path, EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFixtureEffectDispatcher(p, fresh, g, provider, EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = restarted.Dispatch(t.Context(), r)
		_, _ = restarted.Inspect(t.Context(), r)
	}
	if provider.calls.Load() != 1 {
		t.Fatal("restart replayed effect")
	}
	changed := clone(r)
	changed.Header.Correlation.AttemptID = "new-attempt"
	_, err = restarted.Dispatch(t.Context(), changed)
	if !errors.Is(err, ErrEffectConflict) || provider.calls.Load() != 1 {
		t.Fatal("new attempt escaped original UNKNOWN")
	}
	for _, missing := range []string{"journal", "attempt-marker"} {
		t.Run("partial-restore-"+missing, func(t *testing.T) {
			r, p, j, g, provider, _ := effectSetup(t)
			d, err := NewFixtureEffectDispatcher(p, &effectFaultJournal{EffectJournal: j, failAt: 1, afterCommit: true}, g, provider, EffectFixtureProfile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.Dispatch(t.Context(), r); !errors.Is(err, ErrEffectCommitUnknown) {
				t.Fatal("intent ACK failure not injected")
			}
			if missing == "journal" {
				if err = os.Remove(j.path); err != nil {
					t.Fatal(err)
				}
			} else {
				files, err := filepath.Glob(j.path + ".attempt-*")
				if err != nil || len(files) != 1 {
					t.Fatal("missing explicit submission marker")
				}
				if err = os.Remove(files[0]); err != nil {
					t.Fatal(err)
				}
			}
			fresh, err := NewFixtureEffectDispatcher(p, j, g, provider, EffectFixtureProfile)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = fresh.Dispatch(t.Context(), r)
			_, _ = fresh.Inspect(t.Context(), r)
			if provider.calls.Load() != 0 {
				t.Fatal("partial restore authorized an old intent send")
			}
		})
	}
}
func TestWS5EffectConcurrentClaim(t *testing.T) {
	r, p, j, g, provider, d := effectSetup(t)
	other, err := NewFixtureEffectJournal(j.path, EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	independentGate := &effectFixtureGate{frame: clone(g.frame)}
	d2, err := NewFixtureEffectDispatcher(p, other, independentGate, provider, EffectFixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, dispatch := range []*EffectDispatcher{d, d2} {
		wg.Go(func() { <-start; _, _ = dispatch.Dispatch(t.Context(), r) })
	}
	close(start)
	wg.Wait()
	if provider.calls.Load() != 1 {
		t.Fatalf("concurrent actual sends=%d", provider.calls.Load())
	}
}
func TestWS5EffectSecretIsolation(t *testing.T) {
	r, _, j, _, provider, d := effectSetup(t)
	provider.ackLost = true
	result, _ := d.Dispatch(t.Context(), r)
	data, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	for _, forbidden := range []string{"provider body", "credential must", "https://", "webhook_url", "Password", "SummaryJA"} {
		if bytesContains(data, forbidden) || bytesContains(encoded, forbidden) {
			t.Fatalf("secret/raw data escaped: %s", forbidden)
		}
	}
}
func TestWS5EffectInspectPure(t *testing.T) {
	r, _, j, _, provider, d := effectSetup(t)
	if _, err := d.Dispatch(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := d.Inspect(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || provider.calls.Load() != 1 {
		t.Fatal("Inspect mutated or sent")
	}
	missing := clone(r)
	missing.Effect.EffectID = "other-effect"
	if _, err := d.Inspect(t.Context(), missing); err == nil {
		t.Fatal("unrelated effect accepted")
	}
}
func bytesContains(b []byte, s string) bool {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}

func TestWS5EffectIndependentProcessRestart(t *testing.T) {
	if path := os.Getenv("WS5_DISPOSABLE_EFFECT_JOURNAL"); path != "" {
		r, p := effectInputs(t)
		j, err := NewFixtureEffectJournal(path, EffectFixtureProfile)
		if err != nil {
			t.Fatal(err)
		}
		g := &effectFixtureGate{frame: CurrentEffectFrame{ReadFrame: lc.SourceFrame{FrameRef: "trusted-owner-read-frame-1", OwnerID: "notification-owner", Scope: "notification-domain", SourceRevision: 1}, ImmutableRequest: clone(r), Domain: clone(r.Header.DomainRef), Producer: r.Header.ProducerRef, Target: r.Effect.Target, Vector: clone(r.Effect.SourceVector), Allowed: true}}
		provider := &effectFixtureProvider{journalPath: path}
		d, err := NewFixtureEffectDispatcher(p, j, g, provider, EffectFixtureProfile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.Dispatch(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		if _, err = d.Inspect(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		if provider.calls.Load() != 0 {
			t.Fatal("independent process sent old effect")
		}
		return
	}
	r, _, j, _, provider, d := effectSetup(t)
	provider.ackLost = true
	if _, err := d.Dispatch(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestWS5EffectIndependentProcessRestart$", "-test.count=1")
	cmd.Env = append(os.Environ(), "WS5_DISPOSABLE_EFFECT_JOURNAL="+j.path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated process: %v %s", err, output)
	}
	after, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || provider.calls.Load() != 1 {
		t.Fatal("restart changed original state")
	}
}
