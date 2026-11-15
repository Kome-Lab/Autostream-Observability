package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	lc "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle"
)

const LifecycleModuleCommit = "d32ea3514b1c1010391caae0348b0ff9e751f447"
const EffectFixtureProfile = "IU-WS5-SYNTHETIC-ONLY-1"

var (
	ErrEffectUnqualified   = errors.New("notification effect path is not qualified")
	ErrEffectConflict      = errors.New("notification effect immutable identity conflict")
	ErrEffectStale         = errors.New("notification effect current frame changed")
	ErrEffectCommitUnknown = errors.New("notification effect journal commit is unknown")
)

// CurrentEffectFrame comes from the trusted owner adapter, never request JSON.
// WithCurrent must retain its local currentness guard through the callback; it
// must not communicate with a Provider or hold a transaction during dispatch.
type CurrentEffectFrame struct {
	ReadFrame        lc.SourceFrame
	ImmutableRequest lc.Record
	Domain           lc.DomainRef
	Producer         lc.ProducerRef
	Target           lc.ResourceRef
	Vector           lc.RevisionVector
	Allowed          bool
}
type EffectAuthorizer interface {
	WithCurrent(context.Context, lc.Record, func(CurrentEffectFrame) error) error
}

// EffectProvider resolves ContentRef itself. Raw notification content and URLs
// are deliberately absent from the intent journal and this dispatch interface.
// Dispatch performs one attempt; errors do not prove absence or permit a retry.
type EffectProvider interface {
	Dispatch(context.Context, lc.Record) (lc.BoundaryObservation, error)
}
type StoredEffect struct {
	Request lc.Record
	Model   lc.EffectModel
}
type EffectJournal interface {
	BeginAttempt(context.Context, lc.Record) (bool, error)
	Read(context.Context, lc.ID) (StoredEffect, bool, error)
	Update(context.Context, lc.ID, func(*StoredEffect) (StoredEffect, error)) (StoredEffect, error)
}

// EffectDispatcher is an explicitly injected product seam. Normal startup does
// not construct one. No fixture or structural result can qualify production.
type EffectDispatcher struct {
	profile    lc.ComparisonProfile
	journal    EffectJournal
	authorizer EffectAuthorizer
	provider   EffectProvider
}

func NewFixtureEffectDispatcher(profile lc.ComparisonProfile, journal EffectJournal, authorizer EffectAuthorizer, provider EffectProvider, fixture string) (*EffectDispatcher, error) {
	if fixture != EffectFixtureProfile || profile.Ref.ProfileID != lc.EffectOutcome || lc.ValidateProfile(profile).Kind != lc.StructurallyCoherent || journal == nil || authorizer == nil || provider == nil {
		return nil, ErrEffectUnqualified
	}
	return &EffectDispatcher{clone(profile), journal, authorizer, provider}, nil
}

func (d *EffectDispatcher) ProductionQualified() bool { return false }
func (d *EffectDispatcher) Decode(data []byte) (lc.Record, lc.Result) {
	return lc.DecodeRecord(data, d.profile)
}
func (d *EffectDispatcher) validate(r lc.Record) error {
	if r.Effect == nil || r.Header.ContractRef.ContractID != lc.CC07 || r.Header.ContractRef.ModuleCommitRef != LifecycleModuleCommit || r.Header.ProducerRef.ComponentID != "C08" || r.Effect.Target.Kind != lc.NotificationChannel || r.Effect.Target.OwnerID != r.Header.RecordKey.OwnerID || len(r.Effect.SinkRefs) != 1 || r.Effect.SinkRefs[0] != r.Effect.Target || lc.ValidateRecord(r, d.profile).Kind != lc.StructurallyCoherent {
		return ErrEffectUnqualified
	}
	wanted := []lc.BoundaryAddress{boundary(r, lc.LocalPersistence, lc.Intent), boundary(r, lc.LocalPersistence, lc.DispatchPossible), boundary(r, lc.Provider, lc.RemoteAccept), boundary(r, lc.LocalPersistence, lc.LocalResultRecord)}
	if !sameBoundaries(wanted, d.profile.RequiredBoundaries) {
		return ErrEffectUnqualified
	}
	// These are metadata IDs, not payload carriers. Literal values are rejected,
	// never normalized, when they contain URL/credential/private-key syntax.
	b, err := json.Marshal(r)
	if err != nil {
		return ErrEffectUnqualified
	}
	for _, forbidden := range []string{"https://", "http://", "-----BEGIN", "password=", "token=", "Bearer ", "\\\\Users\\\\"} {
		if strings.Contains(string(b), forbidden) {
			return ErrEffectUnqualified
		}
	}
	return nil
}
func (d *EffectDispatcher) withCurrent(ctx context.Context, r lc.Record, fn func(lc.SourceFrame) error) error {
	return d.authorizer.WithCurrent(ctx, clone(r), func(f CurrentEffectFrame) error {
		if !f.Allowed {
			return ErrEffectUnqualified
		}
		if lc.CompareImmutable(f.ImmutableRequest, r, d.profile).Kind != lc.StructurallyCoherent {
			return ErrEffectConflict
		}
		current := clone(r)
		current.Header.DomainRef = f.Domain
		if lc.CompareImmutable(r, current, d.profile).Kind != lc.StructurallyCoherent || f.Producer != r.Header.ProducerRef || f.Target != r.Effect.Target || lc.CompareVectors(r.Effect.SourceVector, f.Vector, d.profile).Kind != lc.StructurallyCoherent {
			return ErrEffectStale
		}
		frame := f.ReadFrame
		if frame.OwnerID != r.Header.RecordKey.OwnerID || frame.Scope != r.Header.DomainRef.DomainID || frame.SourceRevision == 0 || lc.ValidateID(frame.FrameRef, d.profile.Limits).Kind != lc.StructurallyCoherent {
			return ErrEffectUnqualified
		}
		return fn(frame)
	})
}

func (d *EffectDispatcher) storedMatches(entry StoredEffect, r lc.Record) bool {
	m := entry.Model
	if lc.CompareImmutable(entry.Request, r, d.profile).Kind != lc.StructurallyCoherent || m.OwnerID != r.Header.RecordKey.OwnerID || m.EffectID != r.Effect.EffectID || m.Correlation != r.Header.Correlation || m.Target != r.Effect.Target || m.Purpose != r.Effect.Purpose || m.ContentRef != r.Effect.ContentRef || m.Observations.Gate != lc.NotQualified || !sameBoundaries(m.ExpectedBoundaries, d.profile.RequiredBoundaries) {
		return false
	}
	_, check := lc.ReduceEffect(m, lc.EffectEvent{Kind: lc.EffectRestart, ExpectedRevision: m.Revision}, d.profile.Limits)
	return check.Kind == lc.PendingObligation || check.Kind == lc.Unknown || check.Kind == lc.NeedsEvidence || check.Kind == lc.StructurallyCoherent
}

func sameBoundaries(a, b []lc.BoundaryAddress) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if x == y {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (d *EffectDispatcher) Dispatch(ctx context.Context, request lc.Record) (lc.Record, error) {
	if err := d.validate(request); err != nil {
		return lc.Record{}, err
	}
	r := clone(request)
	var entry StoredEffect
	var readFrame lc.SourceFrame
	created := false
	err := d.withCurrent(ctx, r, func(frame lc.SourceFrame) error {
		readFrame = frame
		var err error
		created, err = d.journal.BeginAttempt(ctx, r)
		if err != nil {
			return err
		}
		if !created {
			var found bool
			entry, found, err = d.journal.Read(ctx, r.Effect.EffectID)
			if err != nil {
				entry = StoredEffect{}
				return err
			}
			if !found {
				return ErrEffectCommitUnknown
			}
			if !d.storedMatches(entry, r) {
				return ErrEffectConflict
			}
			return nil
		}
		var committed StoredEffect
		committed, err = d.journal.Update(ctx, r.Effect.EffectID, func(old *StoredEffect) (StoredEffect, error) {
			if old != nil {
				created = false
				if lc.CompareImmutable(old.Request, r, d.profile).Kind != lc.StructurallyCoherent {
					return StoredEffect{}, ErrEffectConflict
				}
				return *old, nil
			}
			m := lc.EffectModel{OwnerID: r.Header.RecordKey.OwnerID, ExpectedBoundaries: clone(d.profile.RequiredBoundaries), EffectID: r.Effect.EffectID, Correlation: r.Header.Correlation, Target: r.Effect.Target, Purpose: r.Effect.Purpose, ContentRef: r.Effect.ContentRef, Revision: 1, DispatchState: lc.NoIntent, Observations: lc.ObservationSet{Gate: lc.NotQualified}}
			next, result := lc.ReduceEffect(m, lc.EffectEvent{Kind: lc.RecordIntentCommit, ExpectedRevision: m.Revision, DurableFact: metadataFact(r, "intent", m.Revision)}, d.profile.Limits)
			if result.Kind != lc.StructurallyCoherent {
				return StoredEffect{}, ErrEffectUnqualified
			}
			return StoredEffect{r, next}, nil
		})
		if err == nil {
			entry = committed
		}
		return err
	})
	if err != nil {
		if effectCurrentRefused(err) {
			return lc.Record{}, err
		}
		return d.unknownResult(r, entry, lc.Intent, readFrame), err
	}
	// An existing intent, including an interrupted pre-dispatch attempt, is only
	// inspected. POST repetition is never interpreted as permission to resume it.
	if !created {
		return d.result(entry), nil
	}
	claimed := false
	err = d.withCurrent(ctx, r, func(frame lc.SourceFrame) error {
		readFrame = frame
		var err error
		var committed StoredEffect
		committed, err = d.journal.Update(ctx, r.Effect.EffectID, func(old *StoredEffect) (StoredEffect, error) {
			if old == nil || old.Model.Revision != entry.Model.Revision || lc.CompareImmutable(old.Request, r, d.profile).Kind != lc.StructurallyCoherent {
				return StoredEffect{}, ErrEffectConflict
			}
			next, result := lc.ReduceEffect(old.Model, lc.EffectEvent{Kind: lc.RecordDispatchCommit, ExpectedRevision: old.Model.Revision, DurableFact: metadataFact(r, "dispatch", old.Model.Revision)}, d.profile.Limits)
			if result.Kind != lc.StructurallyCoherent {
				return StoredEffect{}, ErrEffectConflict
			}
			claimed = true
			return StoredEffect{r, next}, nil
		})
		if err == nil {
			entry = committed
		}
		return err
	})
	if err != nil || !claimed {
		if effectCurrentRefused(err) {
			return lc.Record{}, err
		}
		return d.unknownResult(r, entry, lc.DispatchPossible, readFrame), err
	}
	// Both owner guard and journal transaction ended before crossing Provider.
	observation, providerErr := d.provider.Dispatch(ctx, clone(r))
	if providerErr != nil || observation.Address != boundary(r, lc.Provider, lc.RemoteAccept) || (lc.ValidateBoundaryObservation(observation, d.profile.Limits).Kind != lc.StructurallyCoherent && observation.Knowledge != lc.KnowledgeUnknown) {
		observation = unknownObservation(r, lc.Provider, lc.RemoteAccept, "PROVIDER_ACK_UNKNOWN")
	}
	next, reduced := lc.ReduceEffect(entry.Model, lc.EffectEvent{Kind: lc.AppendEffectObservation, ExpectedRevision: entry.Model.Revision, Observation: observation}, d.profile.Limits)
	if reduced.Kind != lc.StructurallyCoherent {
		return d.unknownResult(r, entry, lc.RemoteAccept, readFrame), ErrEffectConflict
	}
	entry.Model = next
	observed := clone(entry)
	saved, saveErr := d.journal.Update(context.WithoutCancel(ctx), r.Effect.EffectID, func(old *StoredEffect) (StoredEffect, error) {
		if old == nil || old.Model.Revision+1 != observed.Model.Revision || lc.CompareImmutable(old.Request, r, d.profile).Kind != lc.StructurallyCoherent {
			return StoredEffect{}, ErrEffectConflict
		}
		return observed, nil
	})
	if saveErr != nil {
		return d.unknownResult(r, entry, lc.LocalResultRecord, readFrame), saveErr
	}
	return d.result(saved), nil
}

func (d *EffectDispatcher) Inspect(ctx context.Context, request lc.Record) (lc.Record, error) {
	if err := d.validate(request); err != nil {
		return lc.Record{}, err
	}
	r := clone(request)
	var entry StoredEffect
	var readFrame lc.SourceFrame
	err := d.withCurrent(ctx, r, func(frame lc.SourceFrame) error {
		readFrame = frame
		var found bool
		var err error
		entry, found, err = d.journal.Read(ctx, r.Effect.EffectID)
		if err != nil {
			entry = StoredEffect{}
			return err
		}
		if !found {
			return ErrEffectCommitUnknown
		}
		if !d.storedMatches(entry, r) {
			return ErrEffectConflict
		}
		return nil
	})
	if err != nil {
		if effectCurrentRefused(err) {
			return lc.Record{}, err
		}
		return d.unknownResult(r, entry, lc.LocalResultRecord, readFrame), err
	}
	return d.result(entry), nil
}

func effectCurrentRefused(err error) bool {
	return errors.Is(err, ErrEffectUnqualified) || errors.Is(err, ErrEffectStale) || errors.Is(err, ErrEffectConflict)
}

func clone[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic("lifecycle metadata clone encoding failed")
	}
	var out T
	if err = json.Unmarshal(b, &out); err != nil {
		panic("lifecycle metadata clone decoding failed")
	}
	return out
}
func boundary(r lc.Record, kind lc.BoundaryKind, sub lc.SubBoundary) lc.BoundaryAddress {
	return lc.BoundaryAddress{Kind: kind, OwnerID: r.Effect.Target.OwnerID, Resource: r.Effect.Target, SubBoundary: sub}
}
func metadataFact(r lc.Record, label string, revision uint64) lc.Fact[lc.ID] {
	v := lc.ID(label + "-record")
	return lc.Fact[lc.ID]{State: lc.Observed, Value: &v, Observation: &lc.ObservationContext{OwnerID: r.Header.RecordKey.OwnerID, FrameRef: lc.ID(fmt.Sprintf("owner-frame-%d", revision)), Scope: r.Header.DomainRef.DomainID, SourceRevision: revision}}
}
func knownObservation(r lc.Record, sub lc.SubBoundary, revision uint64) lc.BoundaryObservation {
	v := lc.SuccessAtBoundary
	return lc.BoundaryObservation{Address: boundary(r, lc.LocalPersistence, sub), Knowledge: lc.Known, Presence: lc.Present, Outcome: lc.Fact[lc.Outcome]{State: lc.Observed, Value: &v, Observation: &lc.ObservationContext{OwnerID: r.Effect.Target.OwnerID, FrameRef: lc.ID(fmt.Sprintf("owner-frame-%d", revision)), Scope: r.Header.DomainRef.DomainID, SourceRevision: revision}}}
}
func unknownObservation(r lc.Record, kind lc.BoundaryKind, sub lc.SubBoundary, reason lc.ID) lc.BoundaryObservation {
	return lc.BoundaryObservation{Address: boundary(r, kind, sub), Knowledge: lc.KnowledgeUnknown, Presence: lc.NotObserved, Outcome: lc.Fact[lc.Outcome]{State: lc.Unavailable, Unavailable: &lc.UnavailableReason{Code: reason}}}
}
