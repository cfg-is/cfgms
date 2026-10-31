// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package directory

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	dirif "github.com/cfgis/cfgms/pkg/directory/interfaces"
	egif "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	// DefaultM365InventoryInterval is how often a tenant's inventory is collected.
	DefaultM365InventoryInterval = 60 * time.Minute

	// MaxMemberOf bounds the direct groups recorded on one object. Beyond it the
	// object is flagged member_of_truncated; the group's own member set, passed to
	// the membership sink, is never truncated.
	MaxMemberOf = 10000

	m365Source             = "m365"
	m365PageSize           = 999
	m365WriteBatch         = 500
	m365MaxErrorLen        = 256
	m365ManifestTenant     = "system"
	m365ManifestNamespace  = "m365-inventory-manifest"
	m365StatusNamespace    = "m365-inventory-status"
	m365ManifestCreatedBy  = "m365-inventory"
	m365ConnectionsRefresh = 10 * time.Minute

	// SecurityEventSameEntraTenant is the event kind raised when two CFGMS tenants
	// name the same Entra tenant.
	SecurityEventSameEntraTenant = "m365_inventory_shared_entra_tenant"

	kindUser  = egtypes.KindDirectoryUser
	kindGroup = egtypes.KindDirectoryGroup
)

// DeclaredSet answers whether an object is named by a declared configuration.
// #5562 supplies the real implementation; until then the collector uses an empty
// set, so every recorded object carries managed:false.
type DeclaredSet interface {
	IsDeclared(kind, id string) bool
}

type emptyDeclaredSet struct{}

func (emptyDeclaredSet) IsDeclared(string, string) bool { return false }

// M365Connection names a CFGMS tenant that holds an M365 connection and the Entra
// tenant (directory) id the connection points at.
type M365Connection struct {
	Tenant        string
	EntraTenantID string
}

// M365ConnectionSource lists the CFGMS tenants that have an M365 connection.
type M365ConnectionSource interface {
	M365Connections(ctx context.Context) ([]M365Connection, error)
}

// ObservationWriter is the entity graph write path (EntityGraphProvider.ReportObservations).
type ObservationWriter interface {
	ReportObservations(ctx context.Context, batch egif.ObservationBatch) error
}

// ProviderOpRunner runs an operation against a registered directory provider
// (DirectoryProviderManager.ExecuteProviderOp).
type ProviderOpRunner interface {
	ExecuteProviderOp(ctx context.Context, name string, fn func(dirif.DirectoryProvider) error) error
}

// SecurityEvent is raised for conditions the root admin audit stream must see. It
// names CFGMS tenants, so it must never reach a tenant-visible surface.
type SecurityEvent struct {
	Kind          string
	EntraTenantID string
	Tenants       []string
}

// TenantInventoryStatus is the bounded, persisted outcome of a tenant's latest run.
type TenantInventoryStatus struct {
	Tenant        string    `json:"tenant"`
	EntraTenantID string    `json:"entra_tenant_id"`
	LastAttempt   time.Time `json:"last_attempt"`
	LastSuccess   time.Time `json:"last_success"`
	// Stale is true when the latest run failed: the recorded inventory is the
	// previous one and nothing was retracted.
	Stale bool `json:"stale"`
	// Error is the sanitized, length-bounded failure text of the latest run.
	Error  string `json:"error,omitempty"`
	Users  int    `json:"users"`
	Groups int    `json:"groups"`
}

// M365InventoryConfig configures an M365Inventory. Providers, Connections, Writer,
// Membership, Store and Job are required.
type M365InventoryConfig struct {
	Providers    ProviderOpRunner
	ProviderName string
	Connections  M365ConnectionSource
	Writer       ObservationWriter
	Membership   MembershipSink
	Store        cfgconfig.ConfigStore
	Job          lease.SingletonJob
	Declared     DeclaredSet
	Logger       logging.Logger
	OnSecurity   func(ctx context.Context, ev SecurityEvent)

	// Interval is the per-tenant collection period (default 60 minutes).
	Interval time.Duration
	// Jitter is the window over which a tenant's first run is spread (default
	// Interval/4, capped at 15 minutes). The offset is a stable function of the
	// tenant, so it neither bunches tenants nor changes between restarts.
	Jitter time.Duration
	// Tick is how often Run looks for due tenants (default 1 minute, at most Interval).
	Tick time.Duration
	// PageSize is the Graph page size (default and maximum 999).
	PageSize int
	Now      func() time.Time
}

// M365Inventory is the controller-run collector that records each M365-connected
// tenant's users and groups in the entity graph as DNA-shaped fragments.
type M365Inventory struct {
	cfg M365InventoryConfig

	mu          sync.Mutex
	nextDue     map[string]time.Time
	conns       []M365Connection
	connsAt     time.Time
	started     time.Time
	reported    map[string]string
	cancel      context.CancelFunc
	done        chan struct{}
	runningLoop bool
}

// NewM365Inventory validates cfg and returns a collector.
func NewM365Inventory(cfg M365InventoryConfig) (*M365Inventory, error) {
	switch {
	case cfg.Providers == nil:
		return nil, errors.New("m365 inventory: provider runner is required")
	case cfg.Connections == nil:
		return nil, errors.New("m365 inventory: connection source is required")
	case cfg.Writer == nil:
		return nil, errors.New("m365 inventory: entity graph writer is required")
	case cfg.Membership == nil:
		return nil, errors.New("m365 inventory: membership sink is required")
	case cfg.Store == nil:
		return nil, errors.New("m365 inventory: config store is required")
	}
	if cfg.Declared == nil {
		cfg.Declared = emptyDeclaredSet{}
	}
	if cfg.Logger == nil {
		cfg.Logger = logging.NewNoopLogger()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultM365InventoryInterval
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	} else if cfg.Jitter == 0 {
		cfg.Jitter = cfg.Interval / 4
		if cfg.Jitter > 15*time.Minute {
			cfg.Jitter = 15 * time.Minute
		}
	}
	if cfg.Tick <= 0 || cfg.Tick > cfg.Interval {
		cfg.Tick = time.Minute
		if cfg.Tick > cfg.Interval {
			cfg.Tick = cfg.Interval
		}
	}
	if cfg.PageSize <= 0 || cfg.PageSize > m365PageSize {
		cfg.PageSize = m365PageSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &M365Inventory{cfg: cfg, nextDue: map[string]time.Time{}, reported: map[string]string{}}, nil
}

// Start runs the collection loop until Stop or ctx ends. It returns immediately.
func (c *M365Inventory) Start(ctx context.Context) {
	c.mu.Lock()
	if c.runningLoop {
		c.mu.Unlock()
		return
	}
	c.runningLoop = true
	c.started = c.cfg.Now()
	loopCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(c.cfg.Tick)
		defer t.Stop()
		for {
			c.cfg.Job.RunIfLeader(loopCtx, func(ctx context.Context) { c.collect(ctx, false) })
			select {
			case <-loopCtx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Stop ends the loop and waits for the run in flight.
func (c *M365Inventory) Stop() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel, c.done, c.runningLoop = nil, nil, false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// RunOnce collects every eligible tenant now, if this node holds the lease. It
// reports whether this node ran.
func (c *M365Inventory) RunOnce(ctx context.Context) bool {
	return c.cfg.Job.RunIfLeader(ctx, func(ctx context.Context) { c.collect(ctx, true) })
}

// Status returns the persisted status of a tenant's latest run.
func (c *M365Inventory) Status(ctx context.Context, tenant string) (TenantInventoryStatus, bool, error) {
	var st TenantInventoryStatus
	entry, err := c.cfg.Store.GetConfig(ctx, statusKey(tenant))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return st, false, nil
		}
		return st, false, err
	}
	if err := json.Unmarshal(entry.Data, &st); err != nil {
		return st, false, err
	}
	return st, true, nil
}

func (c *M365Inventory) jitterFor(tenant string) time.Duration {
	if c.cfg.Jitter <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(tenant))
	// Clear the top bit so the hash value is non-negative as an int64; the
	// modulo then stays in signed arithmetic and no width-narrowing
	// conversion is needed.
	h := int64(binary.BigEndian.Uint64(sum[:8]) >> 1)
	return time.Duration(h % int64(c.cfg.Jitter))
}

func (c *M365Inventory) connections(ctx context.Context, force bool) ([]M365Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	if !force && c.conns != nil && now.Sub(c.connsAt) < m365ConnectionsRefresh {
		return c.conns, nil
	}
	conns, err := c.cfg.Connections.M365Connections(ctx)
	if err != nil {
		return nil, err
	}
	c.conns, c.connsAt = conns, now
	return conns, nil
}

// collect runs one pass: it resolves which tenants are eligible and collects each
// (every one when force, otherwise those whose schedule is due). One tenant's
// failure never stops the others.
func (c *M365Inventory) collect(ctx context.Context, force bool) {
	conns, err := c.connections(ctx, force)
	if err != nil {
		c.cfg.Logger.Warn("m365 inventory: listing tenant connections failed", "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	eligible := c.eligible(ctx, conns)
	for _, ce := range eligible {
		if ctx.Err() != nil {
			return
		}
		now := c.cfg.Now()
		c.mu.Lock()
		due, known := c.nextDue[ce.conn.Tenant]
		if !known {
			due = c.started.Add(c.jitterFor(ce.conn.Tenant))
			if c.started.IsZero() {
				due = now.Add(c.jitterFor(ce.conn.Tenant))
			}
			c.nextDue[ce.conn.Tenant] = due
		}
		c.mu.Unlock()
		if !force && now.Before(due) {
			continue
		}
		c.runTenant(ctx, ce.conn, ce.guid)
		c.mu.Lock()
		c.nextDue[ce.conn.Tenant] = c.cfg.Now().Add(c.cfg.Interval)
		c.mu.Unlock()
	}
}

type eligibleConn struct {
	conn M365Connection
	guid string
}

// eligible drops tenants whose Entra tenant id is malformed and every tenant
// whose Entra tenant is named by more than one CFGMS tenant: with two owners the
// right one cannot be told, so that Entra tenant is collected for neither and a
// security event names both.
func (c *M365Inventory) eligible(ctx context.Context, conns []M365Connection) []eligibleConn {
	byGUID := map[string][]string{}
	var out []eligibleConn
	for _, conn := range conns {
		guid, ok := normalizeEntraGUID(conn.EntraTenantID)
		if !ok {
			c.recordFailure(ctx, conn, errors.New("the connection's Entra tenant id is not a GUID"))
			continue
		}
		byGUID[guid] = append(byGUID[guid], conn.Tenant)
		out = append(out, eligibleConn{conn: conn, guid: guid})
	}
	kept := out[:0]
	for _, e := range out {
		if len(byGUID[e.guid]) > 1 {
			continue
		}
		kept = append(kept, e)
	}
	for guid, tenants := range byGUID {
		if len(tenants) < 2 {
			continue
		}
		sort.Strings(tenants)
		key := strings.Join(tenants, "\x00")
		c.mu.Lock()
		already := c.reported[guid] == key
		c.reported[guid] = key
		c.mu.Unlock()
		if already {
			continue
		}
		c.cfg.Logger.Warn("m365 inventory: one Entra tenant is named by several CFGMS tenants; it is collected for none",
			"entra_tenant", logging.SanitizeLogValue(guid), "tenant_count", len(tenants))
		if c.cfg.OnSecurity != nil {
			c.cfg.OnSecurity(ctx, SecurityEvent{Kind: SecurityEventSameEntraTenant, EntraTenantID: guid, Tenants: tenants})
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].conn.Tenant < kept[j].conn.Tenant })
	return kept
}

func normalizeEntraGUID(s string) (string, bool) {
	g := strings.ToLower(strings.TrimSpace(s))
	if len(g) != 36 {
		return "", false
	}
	for i := 0; i < len(g); i++ {
		ch := g[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if ch != '-' {
				return "", false
			}
		case (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'):
		default:
			return "", false
		}
	}
	return g, true
}

func (c *M365Inventory) runTenant(ctx context.Context, conn M365Connection, guid string) {
	tctx := context.WithValue(ctx, ctxkeys.TenantID, conn.Tenant)
	res, err := c.collectTenant(tctx, conn, guid)
	if err != nil {
		c.recordFailure(ctx, conn, err)
		return
	}
	st := TenantInventoryStatus{
		Tenant: conn.Tenant, EntraTenantID: guid,
		LastAttempt: c.cfg.Now(), LastSuccess: c.cfg.Now(),
		Users: res.users, Groups: res.groups,
	}
	if werr := c.writeStatus(ctx, st); werr != nil {
		c.cfg.Logger.Warn("m365 inventory: recording status failed", "tenant", logging.SanitizeLogValue(conn.Tenant), "error", logging.SanitizeLogValue(werr.Error()))
	}
}

// recordFailure keeps the previous inventory, flags it stale and stores a bounded
// error. It never retracts anything.
func (c *M365Inventory) recordFailure(ctx context.Context, conn M365Connection, cause error) {
	msg := logging.SanitizeLogValue(cause.Error())
	if len(msg) > m365MaxErrorLen {
		msg = msg[:m365MaxErrorLen]
	}
	c.cfg.Logger.Warn("m365 inventory: collection failed; previous inventory kept and flagged stale",
		"tenant", logging.SanitizeLogValue(conn.Tenant), "error", msg)
	prev, _, _ := c.Status(ctx, conn.Tenant)
	prev.Tenant, prev.EntraTenantID = conn.Tenant, strings.ToLower(strings.TrimSpace(conn.EntraTenantID))
	prev.LastAttempt, prev.Stale, prev.Error = c.cfg.Now(), true, msg
	if err := c.writeStatus(ctx, prev); err != nil {
		c.cfg.Logger.Warn("m365 inventory: recording status failed", "tenant", logging.SanitizeLogValue(conn.Tenant), "error", logging.SanitizeLogValue(err.Error()))
	}
}

func (c *M365Inventory) writeStatus(ctx context.Context, st TenantInventoryStatus) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return c.cfg.Store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: statusKey(st.Tenant), Data: data, Format: cfgconfig.ConfigFormatJSON,
		CreatedBy: m365ManifestCreatedBy, UpdatedBy: m365ManifestCreatedBy,
	})
}

func hex32(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

func statusKey(tenant string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: m365ManifestTenant, Namespace: m365StatusNamespace, Name: hex32(tenant)}
}

func manifestKey(tenant, guid string, bucket int) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: m365ManifestTenant, Namespace: m365ManifestNamespace,
		Name: hex32(tenant, guid) + "-" + strconv.Itoa(bucket)}
}

type manifestShard struct {
	Tenant        string            `json:"tenant"`
	EntraTenantID string            `json:"entra_tenant_id"`
	Bucket        int               `json:"bucket"`
	Entries       map[string]string `json:"entries"`
}

// loadManifest reads every shard of the tenant's manifest: fragment id -> hash.
func (c *M365Inventory) loadManifest(ctx context.Context, tenant, guid string) (map[string]string, error) {
	out := map[string]string{}
	for b := 0; b < stewarddna.BucketCount; b++ {
		entry, err := c.cfg.Store.GetConfig(ctx, manifestKey(tenant, guid, b))
		if err != nil {
			if errors.Is(err, cfgconfig.ErrConfigNotFound) {
				continue
			}
			return nil, fmt.Errorf("read inventory manifest: %w", err)
		}
		var sh manifestShard
		if err := json.Unmarshal(entry.Data, &sh); err != nil {
			return nil, fmt.Errorf("decode inventory manifest: %w", err)
		}
		if sh.Tenant != tenant || sh.EntraTenantID != guid || sh.Bucket != b {
			return nil, errors.New("inventory manifest shard does not belong to this tenant")
		}
		for id, h := range sh.Entries {
			out[id] = h
		}
	}
	return out, nil
}

// saveManifest rewrites only the buckets in dirty, from the full manifest m.
func (c *M365Inventory) saveManifest(ctx context.Context, tenant, guid string, m map[string]string, dirty map[int]struct{}) error {
	if len(dirty) == 0 {
		return nil
	}
	shards := make(map[int]map[string]string, len(dirty))
	for b := range dirty {
		shards[b] = map[string]string{}
	}
	for id, h := range m {
		if s, ok := shards[stewarddna.BucketOf(id)]; ok {
			s[id] = h
		}
	}
	for b, entries := range shards {
		key := manifestKey(tenant, guid, b)
		if len(entries) == 0 {
			if err := c.cfg.Store.DeleteConfig(ctx, key); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
				return fmt.Errorf("delete inventory manifest shard: %w", err)
			}
			continue
		}
		data, err := json.Marshal(manifestShard{Tenant: tenant, EntraTenantID: guid, Bucket: b, Entries: entries})
		if err != nil {
			return err
		}
		if err := c.cfg.Store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
			Key: key, Data: data, Format: cfgconfig.ConfigFormatJSON,
			CreatedBy: m365ManifestCreatedBy, UpdatedBy: m365ManifestCreatedBy,
		}); err != nil {
			return fmt.Errorf("write inventory manifest shard: %w", err)
		}
	}
	return nil
}

type fragState map[string]interface{}

func (f fragState) AsMap() map[string]interface{} { return f }
func (f fragState) ToYAML() ([]byte, error)       { return nil, errors.New("not serializable") }
func (f fragState) FromYAML([]byte) error         { return errors.New("not deserializable") }
func (f fragState) Validate() error               { return nil }
func (f fragState) GetManagedFields() []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ modules.ConfigState = fragState(nil)

type tenantResult struct{ users, groups int }

// run holds the working state of one tenant collection.
type inventoryRun struct {
	c         *M365Inventory
	conn      M365Connection
	guid      string
	authority string
	now       time.Time

	old     map[string]string
	seen    map[string]struct{}
	written map[string]string
	dirty   map[int]struct{}
	pending []egtypes.Observation
	pendKey []string
	pendH   []string
}

func (c *M365Inventory) collectTenant(ctx context.Context, conn M365Connection, guid string) (res tenantResult, err error) {
	r := &inventoryRun{
		c: c, conn: conn, guid: guid, authority: m365Source + ":" + guid, now: c.cfg.Now(),
		seen: map[string]struct{}{}, written: map[string]string{}, dirty: map[int]struct{}{},
	}
	if r.old, err = c.loadManifest(ctx, conn.Tenant, guid); err != nil {
		return res, err
	}
	// Whatever was written before a failure is recorded in the manifest so the next
	// run does not rewrite it; removals are applied only on a complete enumeration.
	complete := false
	defer func() {
		merged := make(map[string]string, len(r.old)+len(r.written))
		for id, h := range r.old {
			merged[id] = h
		}
		for id, h := range r.written {
			merged[id] = h
		}
		if complete {
			for id := range r.old {
				if _, ok := r.seen[id]; !ok {
					delete(merged, id)
					r.dirty[stewarddna.BucketOf(id)] = struct{}{}
				}
			}
		}
		if serr := c.saveManifest(context.WithoutCancel(ctx), conn.Tenant, guid, merged, r.dirty); serr != nil && err == nil {
			err = serr
		}
	}()

	groups, err := r.listGroups(ctx)
	if err != nil {
		return res, err
	}
	memberOf, err := r.applyMemberships(ctx, groups)
	if err != nil {
		return res, err
	}
	for i := range groups {
		if err := r.emit(ctx, kindGroup, groups[i].ID, groupState(&groups[i], memberOf[groups[i].ID], c.cfg.Declared)); err != nil {
			return res, err
		}
	}
	res.groups = len(groups)
	if res.users, err = r.streamUsers(ctx, memberOf); err != nil {
		return res, err
	}
	if err := r.flush(ctx); err != nil {
		return res, err
	}
	if err := r.retract(ctx); err != nil {
		return res, err
	}
	complete = true
	return res, nil
}

func (r *inventoryRun) provider(ctx context.Context, fn func(dirif.InventoryReader) error) error {
	return r.c.cfg.Providers.ExecuteProviderOp(ctx, r.c.cfg.ProviderName, func(p dirif.DirectoryProvider) error {
		ir, ok := p.(dirif.InventoryReader)
		if !ok {
			return errors.New("the directory provider cannot enumerate an inventory")
		}
		return fn(ir)
	})
}

func (r *inventoryRun) listGroups(ctx context.Context) ([]dirif.DirectoryGroup, error) {
	var groups []dirif.DirectoryGroup
	seen := map[string]struct{}{}
	cursor := ""
	for {
		var page []dirif.DirectoryGroup
		var next string
		if err := r.provider(ctx, func(ir dirif.InventoryReader) (e error) {
			page, next, e = ir.ListGroupsPage(ctx, cursor, r.c.cfg.PageSize)
			return e
		}); err != nil {
			return nil, err
		}
		for _, g := range page {
			if !validObjectID(g.ID) {
				continue
			}
			if _, dup := seen[g.ID]; dup {
				continue
			}
			seen[g.ID] = struct{}{}
			groups = append(groups, g)
		}
		if next == "" {
			return groups, nil
		}
		cursor = next
	}
}

// applyMemberships enumerates each group's members once, hands the complete set
// to the membership sink, and inverts user and group members into the memberOf
// index (object id -> direct group ids) used for the fragments. Graph's per-user
// memberOf is never called.
func (r *inventoryRun) applyMemberships(ctx context.Context, groups []dirif.DirectoryGroup) (map[string][]string, error) {
	memberOf := map[string][]string{}
	current := map[string]struct{}{}
	for _, g := range groups {
		current[g.ID] = struct{}{}
		var members []GroupMember
		cursor := ""
		for {
			var page []dirif.GroupMemberRef
			var next string
			if err := r.provider(ctx, func(ir dirif.InventoryReader) (e error) {
				page, next, e = ir.ListGroupMembersPage(ctx, g.ID, cursor, r.c.cfg.PageSize)
				return e
			}); err != nil {
				return nil, err
			}
			for _, m := range page {
				if m.ID == "" {
					continue
				}
				members = append(members, GroupMember{ID: m.ID, Type: m.Type, DisplayName: m.DisplayName})
				if t := normalizeMemberType(m.Type); t == MemberTypeUser || t == MemberTypeGroup {
					memberOf[m.ID] = append(memberOf[m.ID], g.ID)
				}
			}
			if next == "" {
				break
			}
			cursor = next
		}
		if _, err := r.c.cfg.Membership.ApplyGroup(ctx, r.conn.Tenant, r.authority, g.ID, members, r.now); err != nil {
			return nil, fmt.Errorf("apply membership of a group: %w", err)
		}
	}
	// A group that disappeared leaves no members behind.
	for id := range r.old {
		gid, ok := strings.CutPrefix(id, kindGroup+":")
		if !ok {
			continue
		}
		if _, still := current[gid]; still {
			continue
		}
		if _, err := r.c.cfg.Membership.ApplyGroup(ctx, r.conn.Tenant, r.authority, gid, nil, r.now); err != nil {
			return nil, fmt.Errorf("apply membership of a removed group: %w", err)
		}
	}
	return memberOf, nil
}

func (r *inventoryRun) streamUsers(ctx context.Context, memberOf map[string][]string) (int, error) {
	n := 0
	seen := map[string]struct{}{}
	cursor := ""
	for {
		var page []dirif.DirectoryUser
		var next string
		if err := r.provider(ctx, func(ir dirif.InventoryReader) (e error) {
			page, next, e = ir.ListUsersPage(ctx, cursor, r.c.cfg.PageSize)
			return e
		}); err != nil {
			return 0, err
		}
		for i := range page {
			u := &page[i]
			if !validObjectID(u.ID) {
				continue
			}
			if _, dup := seen[u.ID]; dup {
				continue
			}
			seen[u.ID] = struct{}{}
			n++
			if err := r.emit(ctx, kindUser, u.ID, userState(u, memberOf[u.ID], r.c.cfg.Declared)); err != nil {
				return 0, err
			}
		}
		if next == "" {
			return n, nil
		}
		cursor = next
	}
}

func memberOfAttrs(st fragState, groups []string) {
	gs := append(make([]string, 0, len(groups)), groups...)
	sort.Strings(gs)
	out := gs[:0]
	for i, g := range gs {
		if i == 0 || g != gs[i-1] {
			out = append(out, g)
		}
	}
	gs = out
	if len(gs) > MaxMemberOf {
		gs = gs[:MaxMemberOf]
		st[attrMemberOfTruncated] = true
	}
	st[attrMemberOf] = gs
}

func userState(u *dirif.DirectoryUser, groups []string, d DeclaredSet) fragState {
	st := fragState{
		"source":              m365Source,
		attrDisplayName:       u.DisplayName,
		"user_principal_name": u.UserPrincipalName,
		"mail":                u.Mail,
		"account_enabled":     u.AccountEnabled,
		"department":          u.Department,
		"job_title":           u.JobTitle,
		"office_location":     u.OfficeLocation,
		"company_name":        u.CompanyName,
		"managed":             d.IsDeclared(kindUser, u.ID),
	}
	memberOfAttrs(st, groups)
	return st
}

func groupState(g *dirif.DirectoryGroup, groups []string, d DeclaredSet) fragState {
	st := fragState{
		"source":           m365Source,
		attrDisplayName:    g.DisplayName,
		"description":      g.Description,
		"mail":             g.Mail,
		"mail_enabled":     g.MailEnabled,
		"security_enabled": g.SecurityEnabled,
		"managed":          d.IsDeclared(kindGroup, g.ID),
	}
	memberOfAttrs(st, groups)
	return st
}

func (r *inventoryRun) subject(kind, id string) (string, error) {
	word := "user"
	if kind == kindGroup {
		word = "group"
	}
	eid, err := egtypes.NewEID(m365Source, r.guid, word+":"+id)
	if err != nil {
		return "", err
	}
	return eid.String(), nil
}

// emit hashes one object like a steward fragment and queues an observation when
// the hash differs from the manifest.
func (r *inventoryRun) emit(ctx context.Context, kind, id string, st fragState) error {
	fragID := kind + ":" + id
	r.seen[fragID] = struct{}{}
	canon, err := stewarddna.CanonicalizeFragment(fragID, r.authority, st)
	if err != nil {
		return fmt.Errorf("canonicalize fragment: %w", err)
	}
	hash := stewarddna.FragmentHash(canon)
	if r.old[fragID] == hash {
		return nil
	}
	subject, err := r.subject(kind, id)
	if err != nil {
		return err
	}
	payload := make(map[string]interface{}, len(st)+5)
	for k, v := range st {
		payload[k] = v
	}
	payload["fragment_id"] = fragID
	payload["fragment_hash"] = hash
	payload["module_authority"] = m365Source
	payload["confidence"] = string(egtypes.ConfidenceHigh)
	payload["owning_tenant"] = r.conn.Tenant
	r.pending = append(r.pending, egtypes.Observation{
		Source: r.authority, ObservedAt: r.now, RecordedAt: r.now, Subject: subject,
		Kind: egtypes.ObservationKindState, Confidence: egtypes.ConfidenceHigh, Payload: payload,
	})
	r.pendKey = append(r.pendKey, fragID)
	r.pendH = append(r.pendH, hash)
	if len(r.pending) >= m365WriteBatch {
		return r.flush(ctx)
	}
	return nil
}

func (r *inventoryRun) flush(ctx context.Context) error {
	if len(r.pending) == 0 {
		return nil
	}
	err := r.c.cfg.Writer.ReportObservations(ctx, egif.ObservationBatch{Source: r.authority, Observations: r.pending})
	if err != nil {
		return fmt.Errorf("record inventory in entity graph: %w", err)
	}
	for i, k := range r.pendKey {
		r.written[k] = r.pendH[i]
		r.dirty[stewarddna.BucketOf(k)] = struct{}{}
	}
	r.pending, r.pendKey, r.pendH = nil, nil, nil
	return nil
}

// retract withdraws objects the manifest holds that the complete enumeration did
// not return.
func (r *inventoryRun) retract(ctx context.Context) error {
	var obs []egtypes.Observation
	for fragID := range r.old {
		if _, ok := r.seen[fragID]; ok {
			continue
		}
		kind, id, _ := strings.Cut(fragID, ":")
		subject, err := r.subject(kind, id)
		if err != nil {
			continue
		}
		obs = append(obs, egtypes.Observation{
			Source: r.authority, ObservedAt: r.now, RecordedAt: r.now, Subject: subject,
			Kind: egtypes.ObservationKindAbsence, Confidence: egtypes.ConfidenceHigh,
			Payload: map[string]interface{}{"fragment_id": fragID, "owning_tenant": r.conn.Tenant},
		})
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Subject < obs[j].Subject })
	for len(obs) > 0 {
		n := len(obs)
		if n > m365WriteBatch {
			n = m365WriteBatch
		}
		if err := r.c.cfg.Writer.ReportObservations(ctx, egif.ObservationBatch{Source: r.authority, Observations: obs[:n]}); err != nil {
			return fmt.Errorf("retract removed objects from entity graph: %w", err)
		}
		obs = obs[n:]
	}
	return nil
}
