// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	// logEntryCapacity is the number of events one log entry holds. A full entry is
	// immutable.
	logEntryCapacity = 500

	// DefaultRetention is how long change-log entries are kept.
	DefaultRetention = 400 * 24 * time.Hour

	// defaultSweepLookbackMonths is how many month buckets older than the cutoff
	// month one sweep inspects. A sweep runs far more often than monthly, so every
	// bucket passes through this window; raise it with WithSweepLookbackMonths after
	// a long controller outage.
	defaultSweepLookbackMonths = 12

	monthLayout = "2006-01"
)

// Event operations.
const (
	OpAdded   = "added"
	OpRemoved = "removed"
)

var errLogEntryFull = errors.New("directory membership log entry is full")

// ChangeEvent is one membership change.
type ChangeEvent struct {
	Tenant     string     `json:"tenant"`
	GroupEID   string     `json:"group_eid"`
	GroupID    string     `json:"group_id"`
	MemberEID  string     `json:"member_eid"`
	MemberID   string     `json:"member_id"`
	MemberType MemberType `json:"member_type"`
	MemberName string     `json:"member_name,omitempty"`
	Op         string     `json:"op"`
	ObservedAt time.Time  `json:"observed_at"`
	RecordedAt time.Time  `json:"recorded_at"`
	// Source is the authority the change was read from: directory:<domain> or
	// m365:<guid>.
	Source string `json:"source"`
	// ReportedBy is the reporting steward id (AD only).
	ReportedBy string `json:"reported_by,omitempty"`
	// Baseline marks the group's first observation: the state it was found in, not
	// a change.
	Baseline bool `json:"baseline,omitempty"`
}

type logValue struct {
	Authority    string        `json:"authority"`
	GroupID      string        `json:"group_id"`
	LastRecorded time.Time     `json:"last_recorded"`
	Events       []ChangeEvent `json:"events"`
}

// seqValue is the per-group log sequence counter. Its existence also records that
// the group has been observed.
type seqValue struct {
	Current       uint64    `json:"current"`
	FirstObserved time.Time `json:"first_observed"`
}

func seqKey(tenant, h string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenant, Namespace: NamespaceMembershipSeq, Name: h}
}

func logKey(tenant, h string, seq uint64) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenant, Namespace: NamespaceMembershipLog, Name: fmt.Sprintf("%s-%010d", h, seq)}
}

// groupTag tags a log entry with the group id when it is a bare object id, else
// with the group hash, so no provider has to index arbitrary characters.
func groupTag(group, h string) string {
	if validObjectID(group) {
		return "group:" + group
	}
	return "group:" + h
}

func monthTag(t time.Time) string { return "m:" + t.UTC().Format(monthLayout) }

// groupObserved reports whether the group's sequence counter exists.
func (m *Membership) groupObserved(ctx context.Context, tenant, authority, group string) (bool, error) {
	var sv seqValue
	return getValue(ctx, m.store, seqKey(tenant, groupHash(authority, group)), &sv)
}

// ensureCounter creates the group's counter if absent and returns its current
// sequence.
func (m *Membership) ensureCounter(ctx context.Context, tenant, h string) (uint64, error) {
	var sv seqValue
	if ok, err := getValue(ctx, m.store, seqKey(tenant, h), &sv); err != nil {
		return 0, err
	} else if ok {
		return sv.Current, nil
	}
	key := seqKey(tenant, h)
	err := cfgconfig.AtomicUpdate(ctx, m.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		sv = seqValue{Current: 1, FirstObserved: m.now()}
		if cur != nil {
			if err := unmarshalEntry(cur, &sv); err != nil {
				return nil, err
			}
			return nil, errNoChange
		}
		return newEntry(key, sv, nil, m.now())
	})
	if err != nil && !errors.Is(err, errNoChange) {
		return 0, err
	}
	return sv.Current, nil
}

// advanceSequence moves the counter from seen to seen+1. If another writer already
// advanced it, it does nothing: the sequence only ever moves forward, one step per
// full entry.
func (m *Membership) advanceSequence(ctx context.Context, tenant, h string, seen uint64) error {
	key := seqKey(tenant, h)
	err := cfgconfig.AtomicUpdate(ctx, m.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		sv := seqValue{Current: 1, FirstObserved: m.now()}
		if cur != nil {
			if err := unmarshalEntry(cur, &sv); err != nil {
				return nil, err
			}
		}
		if sv.Current != seen {
			return nil, errNoChange
		}
		sv.Current = seen + 1
		return newEntry(key, sv, nil, m.now())
	})
	if errors.Is(err, errNoChange) {
		return nil
	}
	return err
}

// appendEvents appends events to the group's log, filling the current entry and
// moving to the next sequence when it is full.
func (m *Membership) appendEvents(ctx context.Context, tenant, authority, group string, events []ChangeEvent) error {
	h := groupHash(authority, group)
	for len(events) > 0 {
		seq, err := m.ensureCounter(ctx, tenant, h)
		if err != nil {
			return err
		}
		taken := 0
		key := logKey(tenant, h, seq)
		err = cfgconfig.AtomicUpdate(ctx, m.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			lv := logValue{Authority: authority, GroupID: group}
			if cur != nil {
				if err := unmarshalEntry(cur, &lv); err != nil {
					return nil, err
				}
			}
			// The month bucket follows the newest event, so an entry filled slowly
			// is always found by the sweep once its last event ages out.
			tags := []string{groupTag(group, h), monthTag(m.now())}
			room := logEntryCapacity - len(lv.Events)
			if room <= 0 {
				return nil, errLogEntryFull
			}
			taken = len(events)
			if taken > room {
				taken = room
			}
			lv.Events = append(lv.Events, events[:taken]...)
			lv.LastRecorded = m.now()
			return newEntry(key, lv, tags, m.now())
		})
		switch {
		case errors.Is(err, errLogEntryFull):
			if err := m.advanceSequence(ctx, tenant, h, seq); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			events = events[taken:]
		}
	}
	return nil
}

// ListChanges implements MembershipStore. Events are ordered oldest first.
func (m *Membership) ListChanges(ctx context.Context, tenant string, q ChangeQuery) (ChangePage, error) {
	if err := validScope(tenant, q.Authority, q.GroupID); err != nil {
		return ChangePage{}, err
	}
	h := groupHash(q.Authority, q.GroupID)
	c, err := decodeCursor(q.Cursor, tenant, "changes", h)
	if err != nil {
		return ChangePage{}, err
	}
	var sv seqValue
	if ok, err := getValue(ctx, m.store, seqKey(tenant, h), &sv); err != nil || !ok {
		return ChangePage{}, err
	}
	limit := pageLimit(q.Limit)
	start := c.Seq
	if start == 0 {
		start = 1
	}
	var page ChangePage
	for seq := start; seq <= sv.Current; seq++ {
		var lv logValue
		ok, err := getValue(ctx, m.store, logKey(tenant, h, seq), &lv)
		if err != nil {
			return ChangePage{}, err
		}
		if !ok {
			continue
		}
		from := 0
		if seq == c.Seq {
			from = c.Index
		}
		for i := from; i < len(lv.Events); i++ {
			ev := lv.Events[i]
			if !matchesQuery(ev, q) {
				continue
			}
			if len(page.Events) == limit {
				page.NextCursor = encodeCursor(cursor{Tenant: tenant, Kind: "changes", Subject: h, Seq: seq, Index: i})
				return page, nil
			}
			page.Events = append(page.Events, ev)
		}
	}
	return page, nil
}

func matchesQuery(ev ChangeEvent, q ChangeQuery) bool {
	if ev.Baseline && !q.IncludeBaseline {
		return false
	}
	if q.MemberID != "" && ev.MemberID != q.MemberID {
		return false
	}
	if !q.Since.IsZero() && ev.RecordedAt.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && ev.RecordedAt.After(q.Until) {
		return false
	}
	return true
}

// PeerRegistry answers whether a steward is still registered.
type PeerRegistry interface {
	PeerRegistered(ctx context.Context, peerID string) (bool, error)
}

// SweepResult counts what one retention sweep removed.
type SweepResult struct {
	EntriesDeleted  int
	CountersDeleted int
	PeersDeleted    int
}

// SweepRetention deletes log entries whose newest event is older than the
// retention period. It lists only the month-bucket tags at or before the cutoff
// month, never the whole log namespace, then deletes the sequence counters of
// groups left with no log entries and, when peers is non-nil, the last-known
// authority entry of every deregistered peer.
func (m *Membership) SweepRetention(ctx context.Context, peers PeerRegistry) (SweepResult, error) {
	var res SweepResult
	cutoff := m.now().Add(-m.retention)
	type groupRef struct{ tenant, h string }
	touched := map[groupRef]struct{}{}

	month := time.Date(cutoff.UTC().Year(), cutoff.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i <= m.sweepLookbackMonths; i++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		entries, err := m.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{
			Namespace: NamespaceMembershipLog,
			Tags:      []string{monthTag(month.AddDate(0, -i, 0))},
		})
		if err != nil {
			return res, fmt.Errorf("list directory membership log bucket: %w", err)
		}
		for _, e := range entries {
			var lv logValue
			if err := unmarshalEntry(e, &lv); err != nil {
				return res, err
			}
			if !lv.LastRecorded.Before(cutoff) {
				continue
			}
			if err := m.store.DeleteConfig(ctx, e.Key); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
				return res, fmt.Errorf("delete directory membership log entry: %w", err)
			}
			res.EntriesDeleted++
			touched[groupRef{e.Key.TenantID, groupHash(lv.Authority, lv.GroupID)}] = struct{}{}
		}
	}

	for g := range touched {
		gone, err := m.noLogEntriesRemain(ctx, g.tenant, g.h)
		if err != nil {
			return res, err
		}
		if !gone {
			continue
		}
		if err := m.store.DeleteConfig(ctx, seqKey(g.tenant, g.h)); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return res, fmt.Errorf("delete directory membership counter: %w", err)
		}
		res.CountersDeleted++
	}

	if peers != nil {
		n, err := m.sweepPeers(ctx, peers)
		res.PeersDeleted = n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func (m *Membership) noLogEntriesRemain(ctx context.Context, tenant, h string) (bool, error) {
	var sv seqValue
	ok, err := getValue(ctx, m.store, seqKey(tenant, h), &sv)
	if err != nil || !ok {
		return false, err
	}
	for seq := uint64(1); seq <= sv.Current; seq++ {
		if _, err := m.store.GetConfig(ctx, logKey(tenant, h, seq)); err == nil {
			return false, nil
		} else if !errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return false, fmt.Errorf("read directory membership log entry: %w", err)
		}
	}
	return true, nil
}

func (m *Membership) sweepPeers(ctx context.Context, peers PeerRegistry) (int, error) {
	entries, err := m.store.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: peerTenantID, Namespace: NamespaceMembershipPeer})
	if err != nil {
		return 0, fmt.Errorf("list directory membership peers: %w", err)
	}
	deleted := 0
	for _, e := range entries {
		var pv peerValue
		if err := unmarshalEntry(e, &pv); err != nil {
			return deleted, err
		}
		registered, err := peers.PeerRegistered(ctx, pv.PeerID)
		if err != nil {
			return deleted, fmt.Errorf("check peer registration: %w", err)
		}
		if registered {
			continue
		}
		if err := m.store.DeleteConfig(ctx, e.Key); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return deleted, fmt.Errorf("delete directory membership peer: %w", err)
		}
		deleted++
	}
	return deleted, nil
}

// RunRetention runs one sweep under the singleton job so exactly one controller
// node sweeps per cycle. It returns true when this node ran the sweep. The sweep is
// a background job; it is not a write serializer, and membership writes never wait
// on it.
func (m *Membership) RunRetention(ctx context.Context, job lease.SingletonJob, peers PeerRegistry) bool {
	return job.RunIfLeader(ctx, func(ctx context.Context) {
		res, err := m.SweepRetention(ctx, peers)
		if err != nil {
			m.logger.Warn("directory membership retention sweep failed", "error", logging.SanitizeLogValue(err.Error()))
			return
		}
		m.logger.Info("directory membership retention sweep complete",
			"log_entries_deleted", res.EntriesDeleted,
			"counters_deleted", res.CountersDeleted,
			"peers_deleted", res.PeersDeleted)
	})
}
