package notifications

import lc "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle"

func (d *EffectDispatcher) result(entry StoredEffect) lc.Record {
	r := entry.Request
	if r.Effect == nil {
		return lc.Record{}
	}
	m := entry.Model
	observations := []lc.BoundaryObservation{knownObservation(r, lc.Intent, m.Revision)}
	if m.DispatchState == lc.NoIntent {
		observations = []lc.BoundaryObservation{unknownObservation(r, lc.LocalPersistence, lc.Intent, "INTENT_NOT_OBSERVED")}
	}
	if m.DispatchState == lc.MayDispatch {
		observations = append(observations, knownObservation(r, lc.DispatchPossible, m.Revision))
		observations = append(observations, clone(m.Observations.Observations)...)
		if len(m.Observations.Observations) == 0 {
			observations = append(observations, unknownObservation(r, lc.Provider, lc.RemoteAccept, "PROVIDER_RESULT_NOT_RECORDED"))
		}
		if len(m.Observations.Observations) > 0 {
			observations = append(observations, knownObservation(r, lc.LocalResultRecord, m.Revision))
		} else {
			observations = append(observations, unknownObservation(r, lc.LocalPersistence, lc.LocalResultRecord, "LOCAL_RESULT_NOT_RECORDED"))
		}
	} else {
		observations = append(observations, unknownObservation(r, lc.LocalPersistence, lc.DispatchPossible, "DISPATCH_NOT_CLAIMED"), unknownObservation(r, lc.Provider, lc.RemoteAccept, "PROVIDER_NOT_OBSERVED"), unknownObservation(r, lc.LocalPersistence, lc.LocalResultRecord, "LOCAL_RESULT_NOT_RECORDED"))
	}
	return d.inspection(r, m.Revision, observations)
}
func (d *EffectDispatcher) unknownResult(request lc.Record, entry StoredEffect, sub lc.SubBoundary, readFrame lc.SourceFrame) lc.Record {
	if entry.Request.Effect == nil {
		if readFrame.FrameRef == "" || readFrame.SourceRevision == 0 {
			return lc.Record{}
		}
		observations := []lc.BoundaryObservation{unknownObservation(request, lc.LocalPersistence, lc.Intent, "JOURNAL_FRAME_NOT_OBSERVED"), unknownObservation(request, lc.LocalPersistence, lc.DispatchPossible, "JOURNAL_FRAME_NOT_OBSERVED"), unknownObservation(request, lc.Provider, lc.RemoteAccept, "PROVIDER_NOT_OBSERVED"), unknownObservation(request, lc.LocalPersistence, lc.LocalResultRecord, "JOURNAL_FRAME_NOT_OBSERVED")}
		result := d.inspection(request, readFrame.SourceRevision, observations)
		result.Inspection.Coverage = lc.Fact[lc.ID]{State: lc.Unavailable, Unavailable: &lc.UnavailableReason{Code: "JOURNAL_FRAME_NOT_OBSERVED"}}
		// This is the supplied current owner/auth read frame, not a fabricated
		// persisted journal revision or proof that the missing effect is absent.
		result.Inspection.SourceFrames = []lc.SourceFrame{readFrame}
		return result
	}
	result := d.result(entry)
	if result.Inspection == nil {
		return result
	}
	kind := lc.LocalPersistence
	if sub == lc.RemoteAccept {
		kind = lc.Provider
	}
	want := boundary(request, kind, sub)
	replaced := false
	for i, o := range result.Inspection.Observations.Observations {
		if o.Address == want {
			result.Inspection.Observations.Observations[i] = unknownObservation(request, kind, sub, "BOUNDARY_COMMIT_OR_ACK_UNKNOWN")
			replaced = true
		}
	}
	if !replaced {
		result.Inspection.Observations.Observations = append(result.Inspection.Observations.Observations, unknownObservation(request, kind, sub, "BOUNDARY_COMMIT_OR_ACK_UNKNOWN"))
	}
	return result
}
func (d *EffectDispatcher) inspection(r lc.Record, revision uint64, observations []lc.BoundaryObservation) lc.Record {
	h := r.Header
	h.ContractRef.ContractID = lc.CC08
	h.RecordKey.ContractRef = h.ContractRef
	h.RecordKey.RecordID = lc.ID(string(h.RecordKey.RecordID) + ".inspection")
	h.RecordRevision = revision
	coverage := metadataFact(r, "inspection-coverage", revision)
	frames := []lc.SourceFrame{{FrameRef: coverage.Observation.FrameRef, OwnerID: coverage.Observation.OwnerID, Scope: coverage.Observation.Scope, SourceRevision: coverage.Observation.SourceRevision}}
	for _, o := range observations {
		if f := o.Outcome.Observation; f != nil {
			found := false
			for _, old := range frames {
				if old.FrameRef == f.FrameRef {
					found = true
				}
			}
			if !found {
				frames = append(frames, lc.SourceFrame{FrameRef: f.FrameRef, OwnerID: f.OwnerID, Scope: f.Scope, SourceRevision: f.SourceRevision})
			}
		}
	}
	return lc.Record{Header: h, Inspection: &lc.InspectionRecord{Target: lc.QueryTarget{Correlation: r.Header.Correlation, BindingRef: r.Header.RecordKey.RecordID, ExecutionKey: r.Header.Correlation.ExecutionKey, TargetRecordRef: r.Header.RecordKey.RecordID, Scope: r.Header.DomainRef.DomainID, Purpose: lc.PurposeLookup}, Observations: lc.ObservationSet{Observations: observations, RemainingObligations: []lc.ID{"user-delivery-not-proved", "production-provider-store-not-qualified"}, Gate: lc.NotQualified}, ObservedScopes: []lc.ID{r.Header.DomainRef.DomainID}, SourceFrames: frames, Coverage: coverage, HistoricalRefs: []lc.ID{r.Header.RecordKey.RecordID}}}
}
