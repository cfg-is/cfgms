// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrNotClusterAtomic is returned, with nothing written, when the controller is a
// multi-node cluster and the config store cannot make a read-modify-write atomic
// across nodes. Multi-node deployments need the database provider.
var ErrNotClusterAtomic = cfgconfig.ErrNotClusterAtomic

const (
	// DefaultLargeBatchThreshold is the number of membership changes in one batch
	// above which a warning event is emitted. Nothing is dropped either way.
	DefaultLargeBatchThreshold = 10000

	// DefaultMaxBackdate bounds how far before receipt a steward-supplied observed
	// time is believed.
	DefaultMaxBackdate = 24 * time.Hour

	maxRawIDLen    = 256
	maxObjectIDLen = 64
	maxNameLen     = 512

	directoryAuthorityPrefix = "directory:"

	attrMemberOf          = "member_of"
	attrMemberOfTruncated = "member_of_truncated"
	attrOtherMembers      = "other_members"
	attrDisplayName       = "display_name"
)

var (
	errNoChange   = errors.New("directory membership: no change")
	errEmptyEntry = errors.New("directory membership: entry is empty")
)

// MembershipSink is the write side of the membership state. #5553 is its only
// producer.
type MembershipSink interface {
	// ApplyBatch applies one verified batch of AD user and group fragments from peer.
	// authority is the verifier's answer for the peer ("directory:<domain>"); it is
	// supplied by the caller and never recomputed from fragment contents.
	ApplyBatch(ctx context.Context, peer, authority string, upserts []Fragment, removed []RemovedFragment) (ApplyResult, error)
	// ApplyGroup replaces the full member set of one M365 group (authority
	// "m365:<guid>") and logs the difference.
	ApplyGroup(ctx context.Context, tenant, authority, group string, members []GroupMember, observedAt time.Time) (ApplyResult, error)
}

// DomainOwners answers which tenant owns a directory domain. The domain registry
// (service.DirectoryDomainRegistry) satisfies it.
type DomainOwners interface {
	Owner(ctx context.Context, domain string) (tenantID string, found bool, err error)
}

// Fragment is one upserted directory_user or directory_group fragment, already
// accepted by the authority verifier. Attributes is its decoded payload: the sink
// reads member_of, member_of_truncated, other_members and display_name.
type Fragment struct {
	Kind       string
	ObjectID   string
	Attributes map[string]any
	// ObservedAt is the steward-supplied observation time; it is clamped.
	ObservedAt time.Time
}

// RemovedFragment names a removed directory_user or directory_group fragment.
type RemovedFragment struct {
	Kind     string
	ObjectID string
}

// GroupMember is a non-user, non-group member (or, for ApplyGroup, any member).
type GroupMember struct {
	ID          string
	Type        string
	DisplayName string
}

// ApplyResult counts what one call did. Added and Removed are logged events.
type ApplyResult struct {
	Added            int
	Removed          int
	Baseline         int
	RejectedEntries  int
	RejectedObjects  int
	TruncatedObjects int
	SkippedRemovals  int
}

// Warning is emitted for conditions an operator should see. It carries counts only.
type Warning struct {
	Kind   string
	Tenant string
	Peer   string
	Counts map[string]int
}

// Warning kinds.
const (
	WarningLargeBatch      = "directory_membership_large_change_batch"
	WarningTruncatedObject = "directory_membership_member_of_truncated"
	WarningRejectedEntries = "directory_membership_rejected_entries"
)

// Membership implements MembershipSink and MembershipStore over a ConfigStore.
type Membership struct {
	store  cfgconfig.ConfigStore
	owners DomainOwners
	logger logging.Logger

	now                 func() time.Time
	retention           time.Duration
	sweepLookbackMonths int
	maxBackdate         time.Duration
	largeBatch          int
	warn                func(ctx context.Context, w Warning)
}

var (
	_ MembershipSink  = (*Membership)(nil)
	_ MembershipStore = (*Membership)(nil)
)

// Option configures a Membership.
type Option func(*Membership)

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(m *Membership) { m.now = now } }

// WithRetention sets how long log entries are kept.
func WithRetention(d time.Duration) Option {
	return func(m *Membership) {
		if d > 0 {
			m.retention = d
		}
	}
}

// WithSweepLookbackMonths sets how many month buckets before the cutoff month a
// sweep inspects.
func WithSweepLookbackMonths(n int) Option {
	return func(m *Membership) {
		if n >= 0 {
			m.sweepLookbackMonths = n
		}
	}
}

// WithLargeBatchThreshold sets the change count above which a batch warns.
func WithLargeBatchThreshold(n int) Option {
	return func(m *Membership) {
		if n > 0 {
			m.largeBatch = n
		}
	}
}

// WithWarningEmitter registers the receiver of warning/security events.
func WithWarningEmitter(fn func(ctx context.Context, w Warning)) Option {
	return func(m *Membership) { m.warn = fn }
}

// WithLogger sets the logger.
func WithLogger(l logging.Logger) Option {
	return func(m *Membership) {
		if l != nil {
			m.logger = l
		}
	}
}

// NewMembership returns the membership sink and store over store. owners resolves
// the owning tenant of a directory domain.
func NewMembership(store cfgconfig.ConfigStore, owners DomainOwners, opts ...Option) (*Membership, error) {
	if store == nil {
		return nil, errors.New("directory membership requires a config store")
	}
	m := &Membership{
		store:               store,
		owners:              owners,
		logger:              logging.ForComponent("directory-membership"),
		now:                 func() time.Time { return time.Now().UTC() },
		retention:           DefaultRetention,
		sweepLookbackMonths: defaultSweepLookbackMonths,
		maxBackdate:         DefaultMaxBackdate,
		largeBatch:          DefaultLargeBatchThreshold,
	}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// peerValue is the per-peer last verified authority.
type peerValue struct {
	PeerID    string `json:"peer_id"`
	Authority string `json:"authority"`
}

func unmarshalEntry(e *cfgconfig.ConfigEntry, v any) error {
	if err := json.Unmarshal(e.Data, v); err != nil {
		return fmt.Errorf("decode directory membership entry: %w", err)
	}
	return nil
}

// validRawID accepts an id the caller supplied: non-empty, bounded, printable.
// It is only ever hashed into a key or stored in a value, never used as a path.
func validRawID(s string) bool {
	if s == "" || len(s) > maxRawIDLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validObjectID accepts a bare object id (GUID form for AD, Entra object id for
// M365): at most 64 characters of [A-Za-z0-9._-]. An authority prefix, '/', ':' or
// a control character can never match.
func validObjectID(s string) bool {
	if s == "" || len(s) > maxObjectIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

func cleanName(s string) string {
	if len(s) > maxNameLen {
		s = s[:maxNameLen]
	}
	if !utf8.ValidString(s) {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func (m *Membership) checkCluster() error {
	if cfgconfig.ClusterConfigured() && !cfgconfig.ClusterAtomic(m.store) {
		return ErrNotClusterAtomic
	}
	return nil
}

// ownerOf resolves the registry owner of a directory authority.
func (m *Membership) ownerOf(ctx context.Context, authority string) (string, error) {
	if m.owners == nil || !strings.HasPrefix(authority, directoryAuthorityPrefix) {
		return "", ErrInvalidArgument
	}
	domain, ok := egtypes.NormalizeDirectoryDomain(strings.TrimPrefix(authority, directoryAuthorityPrefix))
	if !ok {
		return "", ErrInvalidArgument
	}
	tenant, found, err := m.owners.Owner(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("resolve directory domain owner: %w", err)
	}
	if !found || tenant == "" {
		return "", ErrUnknownDomainOwner
	}
	return tenant, nil
}

// clampObserved bounds a steward-supplied observation time to
// [recorded-maxBackdate, recorded]; a zero time is the receipt time.
func (m *Membership) clampObserved(supplied, recorded time.Time) time.Time {
	if supplied.IsZero() || supplied.After(recorded) {
		return recorded
	}
	if floor := recorded.Add(-m.maxBackdate); supplied.Before(floor) {
		return floor
	}
	return supplied
}

// scope is who a set of writes belongs to.
type scope struct {
	tenant     string
	authority  string
	reportedBy string
}

// delta is one intended membership change.
type delta struct {
	group    string
	member   string
	mtype    MemberType
	name     string
	add      bool
	observed time.Time
}

// appliedChange is a change a shard update actually made.
type appliedChange struct {
	member   string
	mtype    MemberType
	name     string
	add      bool
	silent   bool // persisted but not an event (a name or type refresh)
	baseline bool
	observed time.Time
}

// byMemberPatch is the update to one by-member entry.
type byMemberPatch struct {
	mtype     MemberType
	name      string
	addGroups map[string]struct{}
	delGroups map[string]struct{}
	truncated *bool
	others    *[]otherMember
}

type patchSet map[string]*byMemberPatch

func (p patchSet) get(member string) *byMemberPatch {
	bp := p[member]
	if bp == nil {
		bp = &byMemberPatch{addGroups: map[string]struct{}{}, delGroups: map[string]struct{}{}}
		p[member] = bp
	}
	return bp
}

func (p patchSet) addGroup(member string, t MemberType, name, group string) {
	bp := p.get(member)
	bp.mtype, bp.name = t, name
	delete(bp.delGroups, group)
	bp.addGroups[group] = struct{}{}
}

func (p patchSet) delGroup(member, group string) {
	bp := p.get(member)
	delete(bp.addGroups, group)
	bp.delGroups[group] = struct{}{}
}

// shardUpdate applies mutate to one shard under AtomicUpdate. mutate runs against a
// fresh copy of the members each attempt. wasEmpty reports the shard held no member
// before the update; with an unobserved group it marks the changes as baseline.
func (m *Membership) shardUpdate(ctx context.Context, sc scope, group string, idx int, observedGroup bool, mutate func(map[string]shardEntry) []appliedChange) ([]appliedChange, error) {
	key := shardKey(sc.tenant, sc.authority, group, idx)
	var changes []appliedChange
	err := cfgconfig.AtomicUpdate(ctx, m.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		changes = nil
		sv := shardValue{}
		if cur != nil {
			if err := unmarshalEntry(cur, &sv); err != nil {
				return nil, err
			}
		}
		if sv.Members == nil {
			sv.Members = map[string]shardEntry{}
		}
		wasEmpty := len(sv.Members) == 0
		changes = mutate(sv.Members)
		if len(changes) == 0 {
			return nil, errNoChange
		}
		for i := range changes {
			changes[i].baseline = !observedGroup && wasEmpty
		}
		sv.Authority, sv.GroupID, sv.Shard = sc.authority, group, idx
		return newEntry(key, sv, nil, m.now())
	})
	if err != nil && !errors.Is(err, errNoChange) {
		return nil, err
	}
	return changes, nil
}

// applyDeltaChanges mutates a shard's members for ds.
func applyDeltaChanges(ds []delta) func(map[string]shardEntry) []appliedChange {
	return func(members map[string]shardEntry) []appliedChange {
		var out []appliedChange
		for _, d := range ds {
			cur, ok := members[d.member]
			switch {
			case d.add && !ok:
				members[d.member] = shardEntry{Type: d.mtype, Name: d.name}
				out = append(out, appliedChange{member: d.member, mtype: d.mtype, name: d.name, add: true, observed: d.observed})
			case d.add && ok:
				next := cur
				next.Type = d.mtype
				if d.name != "" {
					next.Name = d.name
				}
				if next != cur {
					members[d.member] = next
					out = append(out, appliedChange{member: d.member, mtype: next.Type, name: next.Name, add: true, silent: true})
				}
			case !d.add && ok:
				delete(members, d.member)
				out = append(out, appliedChange{member: d.member, mtype: cur.Type, name: cur.Name, observed: d.observed})
			}
		}
		return out
	}
}

// logChanges turns a group's applied changes into change events and appends them.
func (m *Membership) logChanges(ctx context.Context, sc scope, group string, recorded time.Time, changes []appliedChange) (res ApplyResult, err error) {
	var events []ChangeEvent
	for _, c := range changes {
		if c.silent {
			continue
		}
		op := OpRemoved
		if c.add {
			op = OpAdded
		}
		obs := c.observed
		if obs.IsZero() {
			obs = recorded
		}
		events = append(events, ChangeEvent{
			Tenant: sc.tenant, GroupEID: objectEID(sc.authority, MemberTypeGroup, group), GroupID: group,
			MemberEID: objectEID(sc.authority, c.mtype, c.member), MemberID: c.member, MemberType: c.mtype, MemberName: c.name,
			Op: op, ObservedAt: obs, RecordedAt: recorded, Source: sc.authority, ReportedBy: sc.reportedBy, Baseline: c.baseline,
		})
		if c.add {
			res.Added++
		} else {
			res.Removed++
		}
		if c.baseline {
			res.Baseline++
		}
	}
	if len(events) == 0 {
		return res, nil
	}
	return res, m.appendEvents(ctx, sc.tenant, sc.authority, group, events)
}

func (r *ApplyResult) add(o ApplyResult) {
	r.Added += o.Added
	r.Removed += o.Removed
	r.Baseline += o.Baseline
}

// applyDeltas applies ds, touching each shard once, and logs the resulting events.
func (m *Membership) applyDeltas(ctx context.Context, sc scope, recorded time.Time, ds []delta) (ApplyResult, error) {
	var res ApplyResult
	byGroup := map[string]map[int][]delta{}
	groups := []string{}
	for _, d := range ds {
		shards := byGroup[d.group]
		if shards == nil {
			shards = map[int][]delta{}
			byGroup[d.group] = shards
			groups = append(groups, d.group)
		}
		i := shardIndex(d.member)
		shards[i] = append(shards[i], d)
	}
	sort.Strings(groups)
	for _, g := range groups {
		observed, err := m.groupObserved(ctx, sc.tenant, sc.authority, g)
		if err != nil {
			return res, err
		}
		var changes []appliedChange
		for idx := 0; idx < membershipShards; idx++ {
			sd := byGroup[g][idx]
			if len(sd) == 0 {
				continue
			}
			c, err := m.shardUpdate(ctx, sc, g, idx, observed, applyDeltaChanges(sd))
			if err != nil {
				return res, err
			}
			changes = append(changes, c...)
		}
		r, err := m.logChanges(ctx, sc, g, recorded, changes)
		if err != nil {
			return res, err
		}
		res.add(r)
	}
	return res, nil
}

// applyPatches writes each touched by-member entry once.
func (m *Membership) applyPatches(ctx context.Context, sc scope, patches patchSet) error {
	ids := make([]string, 0, len(patches))
	for id := range patches {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		bp := patches[id]
		key := byMemberKey(sc.tenant, sc.authority, id)
		present := false
		err := cfgconfig.AtomicUpdate(ctx, m.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			bv := byMemberValue{}
			if cur != nil {
				if err := unmarshalEntry(cur, &bv); err != nil {
					return nil, err
				}
			}
			before, _ := json.Marshal(bv)
			groups := make(map[string]struct{}, len(bv.Groups)+len(bp.addGroups))
			for _, g := range bv.Groups {
				groups[g] = struct{}{}
			}
			for g := range bp.delGroups {
				delete(groups, g)
			}
			for g := range bp.addGroups {
				groups[g] = struct{}{}
			}
			bv.Groups = bv.Groups[:0:0]
			for g := range groups {
				bv.Groups = append(bv.Groups, g)
			}
			sort.Strings(bv.Groups)
			bv.Authority, bv.MemberID = sc.authority, id
			if bp.mtype != "" {
				bv.Type = bp.mtype
			}
			if bp.name != "" {
				bv.Name = bp.name
			}
			if bp.truncated != nil {
				bv.Truncated = *bp.truncated
			}
			if bp.others != nil {
				bv.OtherMembers = *bp.others
			}
			present = cur != nil
			if len(bv.Groups) == 0 && len(bv.OtherMembers) == 0 && !bv.Truncated {
				return nil, errEmptyEntry
			}
			after, _ := json.Marshal(bv)
			if cur != nil && string(before) == string(after) {
				return nil, errNoChange
			}
			return newEntry(key, bv, nil, m.now())
		})
		if errors.Is(err, errEmptyEntry) {
			// Nothing left to index: drop the entry rather than keep an empty one.
			if !present {
				continue
			}
			if derr := m.store.DeleteConfig(ctx, key); derr != nil && !errors.Is(derr, cfgconfig.ErrConfigNotFound) {
				return fmt.Errorf("delete empty directory membership index entry: %w", derr)
			}
			continue
		}
		if err != nil && !errors.Is(err, errNoChange) {
			return err
		}
	}
	return nil
}

// parseMemberOf reads the member_of attribute: validated, deduplicated bare ids,
// the count of rejected entries, and whether the source reported it truncated.
func parseMemberOf(attrs map[string]any) (groups []string, rejected int, truncated bool) {
	if v, ok := attrs[attrMemberOfTruncated].(bool); ok {
		truncated = v
	}
	var raw []any
	switch v := attrs[attrMemberOf].(type) {
	case nil:
	case []string:
		for _, s := range v {
			raw = append(raw, s)
		}
	case []any:
		raw = v
	case string:
		raw = []any{v}
	default:
		rejected++
	}
	seen := map[string]struct{}{}
	for _, r := range raw {
		s, ok := r.(string)
		if !ok || !validObjectID(s) {
			rejected++
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		groups = append(groups, s)
	}
	return groups, rejected, truncated
}

// parseOtherMembers reads a group fragment's other_members attribute.
func parseOtherMembers(attrs map[string]any) (out []otherMember, rejected int) {
	var raw []GroupMember
	switch v := attrs[attrOtherMembers].(type) {
	case nil:
	case []GroupMember:
		raw = v
	case []map[string]any:
		for _, e := range v {
			raw = append(raw, groupMemberFromMap(e))
		}
	case []any:
		for _, e := range v {
			switch t := e.(type) {
			case map[string]any:
				raw = append(raw, groupMemberFromMap(t))
			case GroupMember:
				raw = append(raw, t)
			default:
				rejected++
			}
		}
	default:
		rejected++
	}
	seen := map[string]struct{}{}
	for _, g := range raw {
		t := normalizeMemberType(g.Type)
		if !validObjectID(g.ID) || t == MemberTypeUser || t == MemberTypeGroup {
			rejected++
			continue
		}
		if _, dup := seen[g.ID]; dup {
			continue
		}
		seen[g.ID] = struct{}{}
		out = append(out, otherMember{ID: g.ID, Type: t, Name: cleanName(g.DisplayName)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, rejected
}

func groupMemberFromMap(e map[string]any) GroupMember {
	s := func(k string) string { v, _ := e[k].(string); return v }
	return GroupMember{ID: s("id"), Type: s("type"), DisplayName: s("display_name")}
}

func (m *Membership) readPeer(ctx context.Context, peer string) (peerValue, bool, error) {
	var pv peerValue
	ok, err := getValue(ctx, m.store, peerKey(peer), &pv)
	return pv, ok, err
}

// ApplyBatch implements MembershipSink.
func (m *Membership) ApplyBatch(ctx context.Context, peer, authority string, upserts []Fragment, removed []RemovedFragment) (ApplyResult, error) {
	var res ApplyResult
	if peer == "" || (len(upserts) > 0 && authority == "") {
		return res, ErrInvalidArgument
	}
	if err := m.checkCluster(); err != nil {
		return res, err
	}
	recorded := m.now()
	pv, _, err := m.readPeer(ctx, peer)
	if err != nil {
		return res, err
	}

	// Removals are keyed by the peer's stored last-known authority, and owned by
	// that authority's registry owner, so a steward that moved tenant cannot write
	// removals into another tenant's keys.
	var tenants []string
	if len(removed) > 0 {
		remAuth := pv.Authority
		if remAuth == "" {
			remAuth = authority
		}
		tenant, err := m.ownerOf(ctx, remAuth)
		switch {
		case err == nil:
			r, err := m.applyRemovals(ctx, scope{tenant: tenant, authority: remAuth, reportedBy: peer}, recorded, removed)
			res.add(r)
			res.SkippedRemovals += r.SkippedRemovals
			if err != nil {
				return res, err
			}
			tenants = append(tenants, tenant)
		case errors.Is(err, ErrUnknownDomainOwner) || errors.Is(err, ErrInvalidArgument):
			res.SkippedRemovals += len(removed)
		default:
			return res, err
		}
	}

	var upsertTenant string
	if len(upserts) > 0 {
		upsertTenant, err = m.ownerOf(ctx, authority)
		if err != nil {
			return res, err
		}
		r, err := m.applyUpserts(ctx, scope{tenant: upsertTenant, authority: authority, reportedBy: peer}, recorded, upserts)
		res.add(r)
		res.RejectedEntries += r.RejectedEntries
		res.RejectedObjects += r.RejectedObjects
		res.TruncatedObjects += r.TruncatedObjects
		if err != nil {
			return res, err
		}
		tenants = append(tenants, upsertTenant)
		if pv.Authority != authority {
			if err := m.writePeer(ctx, peer, authority); err != nil {
				return res, err
			}
		}
	}

	tenant := upsertTenant
	if tenant == "" && len(tenants) > 0 {
		tenant = tenants[0]
	}
	m.emitBatchWarnings(ctx, tenant, peer, res)
	return res, nil
}

func (m *Membership) writePeer(ctx context.Context, peer, authority string) error {
	key := peerKey(peer)
	err := cfgconfig.AtomicUpdate(ctx, m.store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		return newEntry(key, peerValue{PeerID: peer, Authority: authority}, nil, m.now())
	})
	if err != nil {
		return fmt.Errorf("record peer last-known authority: %w", err)
	}
	return nil
}

func (m *Membership) applyUpserts(ctx context.Context, sc scope, recorded time.Time, upserts []Fragment) (ApplyResult, error) {
	var res ApplyResult
	var ds []delta
	patches := patchSet{}
	var groupFragments []string

	for _, f := range upserts {
		var mt MemberType
		switch f.Kind {
		case egtypes.KindDirectoryUser:
			mt = MemberTypeUser
		case egtypes.KindDirectoryGroup:
			mt = MemberTypeGroup
		default:
			res.RejectedObjects++
			continue
		}
		if !validRawID(f.ObjectID) {
			res.RejectedObjects++
			continue
		}
		observed := m.clampObserved(f.ObservedAt, recorded)
		name := cleanName(attrString(f.Attributes, attrDisplayName))

		groups, rejected, truncated := parseMemberOf(f.Attributes)
		res.RejectedEntries += rejected
		if truncated {
			res.TruncatedObjects++
		}
		var cur byMemberValue
		if _, err := getValue(ctx, m.store, byMemberKey(sc.tenant, sc.authority, f.ObjectID), &cur); err != nil {
			return res, err
		}
		newSet := make(map[string]struct{}, len(groups))
		for _, g := range groups {
			newSet[g] = struct{}{}
		}
		curSet := make(map[string]struct{}, len(cur.Groups))
		for _, g := range cur.Groups {
			curSet[g] = struct{}{}
		}
		patch := patches.get(f.ObjectID)
		patch.mtype, patch.name = mt, name
		patch.truncated = &truncated
		for _, g := range groups {
			// Re-asserted adds are idempotent in the shard; they also repair an
			// index entry a crash left behind.
			ds = append(ds, delta{group: g, member: f.ObjectID, mtype: mt, name: name, add: true, observed: observed})
			patches.addGroup(f.ObjectID, mt, name, g)
		}
		if !truncated {
			// A truncated list cannot prove a group was left; nothing is removed.
			for _, g := range cur.Groups {
				if _, still := newSet[g]; !still {
					ds = append(ds, delta{group: g, member: f.ObjectID, mtype: mt, observed: observed})
					patches.delGroup(f.ObjectID, g)
				}
			}
		}

		if mt == MemberTypeGroup {
			groupFragments = append(groupFragments, f.ObjectID)
			others, rej := parseOtherMembers(f.Attributes)
			res.RejectedEntries += rej
			newOthers := make(map[string]struct{}, len(others))
			for _, o := range others {
				newOthers[o.ID] = struct{}{}
				ds = append(ds, delta{group: f.ObjectID, member: o.ID, mtype: o.Type, name: o.Name, add: true, observed: observed})
				patches.addGroup(o.ID, o.Type, o.Name, f.ObjectID)
			}
			for _, o := range cur.OtherMembers {
				if _, still := newOthers[o.ID]; !still {
					ds = append(ds, delta{group: f.ObjectID, member: o.ID, mtype: o.Type, name: o.Name, observed: observed})
					patches.delGroup(o.ID, f.ObjectID)
				}
			}
			patches.get(f.ObjectID).others = &others
		}
	}

	r, err := m.applyDeltas(ctx, sc, recorded, ds)
	res.add(r)
	if err != nil {
		return res, err
	}
	for _, g := range groupFragments {
		if _, err := m.ensureCounter(ctx, sc.tenant, groupHash(sc.authority, g)); err != nil {
			return res, err
		}
	}
	return res, m.applyPatches(ctx, sc, patches)
}

func attrString(attrs map[string]any, key string) string {
	s, _ := attrs[key].(string)
	return s
}

func (m *Membership) applyRemovals(ctx context.Context, sc scope, recorded time.Time, removed []RemovedFragment) (ApplyResult, error) {
	var res ApplyResult
	var ds []delta
	patches := patchSet{}
	for _, rf := range removed {
		if !validRawID(rf.ObjectID) || (rf.Kind != egtypes.KindDirectoryUser && rf.Kind != egtypes.KindDirectoryGroup) {
			res.SkippedRemovals++
			continue
		}
		if rf.Kind == egtypes.KindDirectoryGroup {
			r, err := m.removeGroup(ctx, sc, recorded, rf.ObjectID)
			res.add(r)
			if err != nil {
				return res, err
			}
		}
		// Either kind is also a member of its parent groups.
		var cur byMemberValue
		if _, err := getValue(ctx, m.store, byMemberKey(sc.tenant, sc.authority, rf.ObjectID), &cur); err != nil {
			return res, err
		}
		mt := MemberTypeUser
		if rf.Kind == egtypes.KindDirectoryGroup {
			mt = MemberTypeGroup
		}
		for _, g := range cur.Groups {
			ds = append(ds, delta{group: g, member: rf.ObjectID, mtype: mt, observed: recorded})
			patches.delGroup(rf.ObjectID, g)
		}
		bp := patches.get(rf.ObjectID)
		f := false
		bp.truncated = &f
		bp.others = &[]otherMember{}
	}
	r, err := m.applyDeltas(ctx, sc, recorded, ds)
	res.add(r)
	if err != nil {
		return res, err
	}
	return res, m.applyPatches(ctx, sc, patches)
}

// removeGroup logs a removal for every member of a removed group fragment and
// deletes its membership shards.
func (m *Membership) removeGroup(ctx context.Context, sc scope, recorded time.Time, group string) (ApplyResult, error) {
	var res ApplyResult
	patches := patchSet{}
	var changes []appliedChange
	removeAll := func(members map[string]shardEntry) []appliedChange {
		var out []appliedChange
		for id, e := range members {
			out = append(out, appliedChange{member: id, mtype: e.Type, name: e.Name, observed: recorded})
			delete(members, id)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].member < out[j].member })
		return out
	}
	for idx := 0; idx < membershipShards; idx++ {
		c, err := m.shardUpdate(ctx, sc, group, idx, true, removeAll)
		if err != nil {
			return res, err
		}
		changes = append(changes, c...)
		for _, ch := range c {
			patches.delGroup(ch.member, group)
		}
		if err := m.deleteShardIfEmpty(ctx, shardKey(sc.tenant, sc.authority, group, idx)); err != nil {
			return res, err
		}
	}
	r, err := m.logChanges(ctx, sc, group, recorded, changes)
	res.add(r)
	if err != nil {
		return res, err
	}
	return res, m.applyPatches(ctx, sc, patches)
}

func (m *Membership) deleteShardIfEmpty(ctx context.Context, key *cfgconfig.ConfigKey) error {
	var sv shardValue
	ok, err := getValue(ctx, m.store, key, &sv)
	if err != nil || !ok || len(sv.Members) > 0 {
		return err
	}
	if err := m.store.DeleteConfig(ctx, key); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return fmt.Errorf("delete directory membership shard: %w", err)
	}
	return nil
}

// ApplyGroup implements MembershipSink.
func (m *Membership) ApplyGroup(ctx context.Context, tenant, authority, group string, members []GroupMember, observedAt time.Time) (ApplyResult, error) {
	var res ApplyResult
	if err := validScope(tenant, authority, group); err != nil {
		return res, err
	}
	if err := m.checkCluster(); err != nil {
		return res, err
	}
	recorded := m.now()
	observed := observedAt
	if observed.IsZero() || observed.After(recorded) {
		observed = recorded
	}
	sc := scope{tenant: tenant, authority: authority}

	incoming := make([]map[string]shardEntry, membershipShards)
	for i := range incoming {
		incoming[i] = map[string]shardEntry{}
	}
	for _, gm := range members {
		if !validObjectID(gm.ID) {
			res.RejectedEntries++
			continue
		}
		incoming[shardIndex(gm.ID)][gm.ID] = shardEntry{Type: normalizeMemberType(gm.Type), Name: cleanName(gm.DisplayName)}
	}

	observedGroup, err := m.groupObserved(ctx, tenant, authority, group)
	if err != nil {
		return res, err
	}
	patches := patchSet{}
	var changes []appliedChange
	for idx := 0; idx < membershipShards; idx++ {
		want := incoming[idx]
		c, err := m.shardUpdate(ctx, sc, group, idx, observedGroup, func(cur map[string]shardEntry) []appliedChange {
			var out []appliedChange
			for id, e := range cur {
				if _, keep := want[id]; !keep {
					out = append(out, appliedChange{member: id, mtype: e.Type, name: e.Name, observed: observed})
					delete(cur, id)
				}
			}
			for id, w := range want {
				if e, ok := cur[id]; !ok {
					cur[id] = w
					out = append(out, appliedChange{member: id, mtype: w.Type, name: w.Name, add: true, observed: observed})
				} else if e != w {
					cur[id] = w
					out = append(out, appliedChange{member: id, mtype: w.Type, name: w.Name, add: true, silent: true})
				}
			}
			sort.Slice(out, func(i, j int) bool { return out[i].member < out[j].member })
			return out
		})
		if err != nil {
			return res, err
		}
		changes = append(changes, c...)
		for _, ch := range c {
			if ch.add {
				patches.addGroup(ch.member, ch.mtype, ch.name, group)
			} else {
				patches.delGroup(ch.member, group)
			}
		}
	}
	r, err := m.logChanges(ctx, sc, group, recorded, changes)
	res.add(r)
	if err != nil {
		return res, err
	}
	if _, err := m.ensureCounter(ctx, tenant, groupHash(authority, group)); err != nil {
		return res, err
	}
	if err := m.applyPatches(ctx, sc, patches); err != nil {
		return res, err
	}
	m.emitBatchWarnings(ctx, tenant, "", res)
	return res, nil
}

func (m *Membership) emitBatchWarnings(ctx context.Context, tenant, peer string, res ApplyResult) {
	if n := res.Added + res.Removed; n > m.largeBatch {
		m.emit(ctx, Warning{Kind: WarningLargeBatch, Tenant: tenant, Peer: peer,
			Counts: map[string]int{"changes": n, "added": res.Added, "removed": res.Removed, "baseline": res.Baseline}})
	}
	if res.TruncatedObjects > 0 {
		m.emit(ctx, Warning{Kind: WarningTruncatedObject, Tenant: tenant, Peer: peer,
			Counts: map[string]int{"objects": res.TruncatedObjects}})
	}
	if res.RejectedEntries > 0 || res.RejectedObjects > 0 {
		m.emit(ctx, Warning{Kind: WarningRejectedEntries, Tenant: tenant, Peer: peer,
			Counts: map[string]int{"entries": res.RejectedEntries, "objects": res.RejectedObjects}})
	}
}

func (m *Membership) emit(ctx context.Context, w Warning) {
	m.logger.Warn("directory membership warning",
		"kind", w.Kind,
		"tenant", logging.SanitizeLogValue(w.Tenant),
		"peer", logging.SanitizeLogValue(w.Peer),
		"counts", fmt.Sprint(w.Counts))
	if m.warn != nil {
		m.warn(ctx, w)
	}
}
