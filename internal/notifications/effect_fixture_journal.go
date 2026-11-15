package notifications

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	lc "github.com/Kome-Lab/Autostream-Contracts/v3lifecycle"
)

// FixtureEffectJournal is only a disposable synthetic store. It is not a choice
// of production persistence, a storage qualification, or a startup migration.
// Exclusive lockfiles guard independent instances/processes. A crash-held lock
// is never cleared by age or inspection; its continued presence refuses writes.
type FixtureEffectJournal struct{ path string }

// BeginAttempt durably reserves the original Effect before the first journal
// commit. An ambiguous/absent journal cannot turn the same POST into a new send.
// Marker payloads are only frozen non-secret DTOs; they are never auto-released.
func (j *FixtureEffectJournal) BeginAttempt(ctx context.Context, r lc.Record) (bool, error) {
	if ctx.Err() != nil {
		return false, ErrEffectCommitUnknown
	}
	name := j.path + ".attempt-" + base64.RawURLEncoding.EncodeToString([]byte(r.Effect.EffectID))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrEffectCommitUnknown
	}
	b, err := json.Marshal(r)
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return false, ErrEffectCommitUnknown
	}
	return true, nil
}

func NewFixtureEffectJournal(path, fixture string) (*FixtureEffectJournal, error) {
	if fixture != EffectFixtureProfile || !filepath.IsAbs(path) || filepath.Base(path) != "notification-effects.fixture.json" {
		return nil, ErrEffectUnqualified
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrEffectUnqualified
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, ErrEffectUnqualified
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrEffectUnqualified
	}
	return &FixtureEffectJournal{path}, nil
}
func (j *FixtureEffectJournal) load() (map[lc.ID]StoredEffect, error) {
	f, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[lc.ID]StoredEffect{}, nil
	}
	if err != nil {
		return nil, ErrEffectCommitUnknown
	}
	defer f.Close()
	var entries map[lc.ID]StoredEffect
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&entries); err != nil || entries == nil {
		return nil, ErrEffectCommitUnknown
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, ErrEffectCommitUnknown
	}
	return entries, nil
}
func (j *FixtureEffectJournal) Read(ctx context.Context, id lc.ID) (StoredEffect, bool, error) {
	if err := ctx.Err(); err != nil {
		return StoredEffect{}, false, ErrEffectCommitUnknown
	}
	entries, err := j.load()
	if err != nil {
		return StoredEffect{}, false, err
	}
	entry, ok := entries[id]
	return clone(entry), ok, nil
}
func (j *FixtureEffectJournal) Update(ctx context.Context, id lc.ID, fn func(*StoredEffect) (StoredEffect, error)) (StoredEffect, error) {
	if err := ctx.Err(); err != nil {
		return StoredEffect{}, ErrEffectCommitUnknown
	}
	lock, err := os.OpenFile(j.path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return StoredEffect{}, ErrEffectCommitUnknown
	}
	defer func() { _ = lock.Close(); _ = os.Remove(j.path + ".lock") }()
	entries, err := j.load()
	if err != nil {
		return StoredEffect{}, err
	}
	var previous *StoredEffect
	if old, ok := entries[id]; ok {
		x := clone(old)
		previous = &x
	}
	next, err := fn(previous)
	if err != nil {
		return StoredEffect{}, err
	}
	entries[id] = clone(next)
	b, err := json.Marshal(entries)
	if err != nil || len(b) > 4<<20 {
		return StoredEffect{}, ErrEffectCommitUnknown
	}
	f, err := os.CreateTemp(filepath.Dir(j.path), ".notification-effects-fixture-")
	if err != nil {
		return StoredEffect{}, ErrEffectCommitUnknown
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, j.path)
	}
	if err != nil {
		return StoredEffect{}, ErrEffectCommitUnknown
	}
	return clone(next), nil
}
