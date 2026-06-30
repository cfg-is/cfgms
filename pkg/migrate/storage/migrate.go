// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage implements the "storage" migrator for CFGMS controller data.
//
// The migrator covers all eleven storage stores through pkg/storage/interfaces
// using upsert semantics so that re-running the migration is idempotent:
//
//	cfg migrate --provider storage --from oss --to database
//
// Supported backend names: "oss" (flatfile+sqlite composite), "database" (Postgres).
// When invoked via the registry factory the backend configuration is read from
// the environment:
//
//	CFGMS_STORAGE_FLATFILE_ROOT   – flatfile root directory (oss backend)
//	CFGMS_STORAGE_SQLITE_PATH     – SQLite file path (oss backend)
//	CFGMS_STORAGE_CLUSTER_POSTGRES_DSN – Postgres DSN (database backend)
//
// For tests, callers should bypass the factory and use NewStorageMigrator directly
// with pre-built StorageManager instances.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/migrate"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database" // register database provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite provider
)

func init() {
	migrate.Register("storage", func(from, to string) (migrate.Migrator, error) {
		srcMgr, err := openBackend(from)
		if err != nil {
			return nil, fmt.Errorf("storage migrator: source backend %q: %w", from, err)
		}
		dstMgr, err := openBackend(to)
		if err != nil {
			return nil, fmt.Errorf("storage migrator: target backend %q: %w", to, err)
		}
		return NewStorageMigrator(srcMgr, dstMgr), nil
	})
}

// openBackend builds a StorageManager for the named backend using environment
// variables for configuration. Supported names: "oss", "database".
func openBackend(name string) (*interfaces.StorageManager, error) {
	switch name {
	case "oss":
		root := os.Getenv("CFGMS_STORAGE_FLATFILE_ROOT")
		if root == "" {
			return nil, fmt.Errorf("CFGMS_STORAGE_FLATFILE_ROOT must be set for oss backend")
		}
		sqlitePath := os.Getenv("CFGMS_STORAGE_SQLITE_PATH")
		if sqlitePath == "" {
			return nil, fmt.Errorf("CFGMS_STORAGE_SQLITE_PATH must be set for oss backend")
		}
		return interfaces.CreateOSSStorageManager(root, sqlitePath)
	case "database":
		dsn := os.Getenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN")
		if dsn == "" {
			return nil, fmt.Errorf("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN must be set for database backend")
		}
		return interfaces.CreateClusterStorageManager(dsn, nil)
	default:
		return nil, fmt.Errorf("unknown backend %q; supported: oss, database", name)
	}
}

// StorageMigrator moves all controller storage data between two StorageManager
// backends using the pkg/storage/interfaces contracts. Both Plan and Run are
// idempotent; Run adds a post-import integrity check.
type StorageMigrator struct {
	src *interfaces.StorageManager
	dst *interfaces.StorageManager
}

// NewStorageMigrator returns a StorageMigrator that copies data from src to dst.
// Both managers must be non-nil; the caller is responsible for closing them.
func NewStorageMigrator(src, dst *interfaces.StorageManager) *StorageMigrator {
	if src == nil {
		panic("storage.NewStorageMigrator: src must not be nil")
	}
	if dst == nil {
		panic("storage.NewStorageMigrator: dst must not be nil")
	}
	return &StorageMigrator{src: src, dst: dst}
}

// Plan exports all records from the source and returns per-kind counts.
// No writes to the target are performed.
func (m *StorageMigrator) Plan(ctx context.Context) (migrate.Report, error) {
	records, err := exportAll(ctx, m.src)
	if err != nil {
		return migrate.Report{}, fmt.Errorf("storage plan: export failed: %w", err)
	}
	counts := countByKind(records)
	return migrate.Report{Counts: counts, Errors: make(map[string]error)}, nil
}

// Run exports all records from the source, imports them into the target with
// upsert semantics, and then verifies that per-kind counts match. A count
// mismatch returns a non-nil error that lists all mismatched kinds.
func (m *StorageMigrator) Run(ctx context.Context) (migrate.Report, error) {
	records, err := exportAll(ctx, m.src)
	if err != nil {
		return migrate.Report{}, fmt.Errorf("storage run: export failed: %w", err)
	}

	if err := importAll(ctx, m.dst, records); err != nil {
		return migrate.Report{}, fmt.Errorf("storage run: import failed: %w", err)
	}

	srcCounts := countByKind(records)

	// Integrity check: re-export from target and compare counts.
	dstRecords, err := exportAll(ctx, m.dst)
	if err != nil {
		return migrate.Report{}, fmt.Errorf("storage run: integrity check export failed: %w", err)
	}
	dstCounts := countByKind(dstRecords)

	var mismatch []string
	for kind, srcN := range srcCounts {
		if dstN := dstCounts[kind]; dstN != srcN {
			mismatch = append(mismatch, fmt.Sprintf("%s: want %d got %d", kind, srcN, dstN))
		}
	}
	if len(mismatch) > 0 {
		return migrate.Report{Counts: srcCounts, Errors: make(map[string]error)},
			fmt.Errorf("storage migration integrity check failed: %v", mismatch)
	}

	return migrate.Report{Counts: srcCounts, Errors: make(map[string]error)}, nil
}

// ─── kind constants ─────────────────────────────────────────────────────────

const (
	kindConfig            = "config"
	kindAudit             = "audit"
	kindRBACPermission    = "rbac_permission"
	kindRBACRole          = "rbac_role"
	kindRBACSubject       = "rbac_subject"
	kindRBACAssignment    = "rbac_role_assignment"
	kindTenant            = "tenant"
	kindClientTenant      = "client_tenant"
	kindRegistrationToken = "registration_token"
	kindSession           = "session"
	kindSteward           = "steward"
	kindCommand           = "command"
	kindTrigger           = "trigger"
	kindPush              = "push"
	kindIPTrust           = "ip_trust"
)

// ─── export ──────────────────────────────────────────────────────────────────

// exportAll reads every record from every supported store in mgr.
// Tenant records are exported first so that their IDs are available for
// IP-trust scoping.
func exportAll(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	var out []migrate.Record

	// Tenants first — IDs needed for ip_trust scoping.
	tenantRecs, tenantIDs, err := exportTenants(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, tenantRecs...)

	cfgRecs, err := exportConfigs(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, cfgRecs...)

	auditRecs, err := exportAudit(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, auditRecs...)

	rbacRecs, err := exportRBAC(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, rbacRecs...)

	ctRecs, err := exportClientTenants(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, ctRecs...)

	tokenRecs, err := exportRegistrationTokens(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, tokenRecs...)

	sessionRecs, err := exportSessions(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, sessionRecs...)

	stewardRecs, err := exportStewards(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, stewardRecs...)

	cmdRecs, err := exportCommands(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, cmdRecs...)

	trigRecs, err := exportTriggers(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, trigRecs...)

	pushRecs, err := exportPushes(ctx, mgr)
	if err != nil {
		return nil, err
	}
	out = append(out, pushRecs...)

	ipRecs, err := exportIPTrust(ctx, mgr, tenantIDs)
	if err != nil {
		return nil, err
	}
	out = append(out, ipRecs...)

	return out, nil
}

func marshal(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return data, nil
}

func exportTenants(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, []string, error) {
	store := mgr.GetTenantStore()
	if store == nil {
		return nil, nil, nil
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return nil, nil, fmt.Errorf("initialize tenant store: %w", err)
		}
	}
	tenants, err := store.ListTenants(ctx, &business.TenantFilter{})
	if err != nil {
		return nil, nil, fmt.Errorf("list tenants: %w", err)
	}
	recs := make([]migrate.Record, 0, len(tenants))
	ids := make([]string, 0, len(tenants))
	for _, t := range tenants {
		data, err := marshal(t)
		if err != nil {
			return nil, nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindTenant, ID: t.ID, Data: data})
		ids = append(ids, t.ID)
	}
	return recs, ids, nil
}

func exportConfigs(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetConfigStore()
	if store == nil {
		return nil, nil
	}
	entries, err := store.ListConfigs(ctx, &cfgconfig.ConfigFilter{})
	if err != nil {
		return nil, fmt.Errorf("list configs: %w", err)
	}
	recs := make([]migrate.Record, 0, len(entries))
	for _, e := range entries {
		data, err := marshal(e)
		if err != nil {
			return nil, err
		}
		id := configID(e)
		recs = append(recs, migrate.Record{Kind: kindConfig, ID: id, Data: data})
	}
	return recs, nil
}

func configID(e *cfgconfig.ConfigEntry) string {
	if e.Key == nil {
		return ""
	}
	return e.Key.String()
}

func exportAudit(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetAuditStore()
	if store == nil {
		return nil, nil
	}
	entries, err := store.ListAuditEntries(ctx, &business.AuditFilter{})
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	recs := make([]migrate.Record, 0, len(entries))
	for _, e := range entries {
		data, err := marshal(e)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindAudit, ID: e.ID, Data: data})
	}
	return recs, nil
}

func exportRBAC(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetRBACStore()
	if store == nil {
		return nil, nil
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("initialize RBAC store: %w", err)
		}
	}
	var recs []migrate.Record

	perms, err := store.ListPermissions(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list RBAC permissions: %w", err)
	}
	for _, p := range perms {
		data, err := marshal(p)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindRBACPermission, ID: p.Id, Data: data})
	}

	roles, err := store.ListRoles(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list RBAC roles: %w", err)
	}
	for _, r := range roles {
		data, err := marshal(r)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindRBACRole, ID: r.Id, Data: data})
	}

	subjects, err := store.ListSubjects(ctx, "", common.SubjectType_SUBJECT_TYPE_UNSPECIFIED)
	if err != nil {
		return nil, fmt.Errorf("list RBAC subjects: %w", err)
	}
	for _, s := range subjects {
		data, err := marshal(s)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindRBACSubject, ID: s.Id, Data: data})
	}

	assignments, err := store.ListRoleAssignments(ctx, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("list RBAC role assignments: %w", err)
	}
	for _, a := range assignments {
		data, err := marshal(a)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindRBACAssignment, ID: a.Id, Data: data})
	}

	return recs, nil
}

func exportClientTenants(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetClientTenantStore()
	if store == nil {
		return nil, nil
	}
	tenants, err := store.ListClientTenants("")
	if err != nil {
		return nil, fmt.Errorf("list client tenants: %w", err)
	}
	recs := make([]migrate.Record, 0, len(tenants))
	for _, ct := range tenants {
		data, err := marshal(ct)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindClientTenant, ID: ct.TenantID, Data: data})
	}
	return recs, nil
}

func exportRegistrationTokens(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetRegistrationTokenStore()
	if store == nil {
		return nil, nil
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("initialize registration token store: %w", err)
		}
	}
	tokens, err := store.ListTokens(ctx, &business.RegistrationTokenFilter{})
	if err != nil {
		return nil, fmt.Errorf("list registration tokens: %w", err)
	}
	recs := make([]migrate.Record, 0, len(tokens))
	for _, tok := range tokens {
		data, err := marshal(tok)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindRegistrationToken, ID: tok.Token, Data: data})
	}
	return recs, nil
}

func exportSessions(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetSessionStore()
	if store == nil {
		return nil, nil
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("initialize session store: %w", err)
		}
	}
	sessions, err := store.ListSessions(ctx, &business.SessionFilter{})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	recs := make([]migrate.Record, 0, len(sessions))
	for _, s := range sessions {
		data, err := marshal(s)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindSession, ID: s.SessionID, Data: data})
	}
	return recs, nil
}

func exportStewards(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetStewardStore()
	if store == nil {
		return nil, nil
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return nil, fmt.Errorf("initialize steward store: %w", err)
		}
	}
	stewards, err := store.ListStewards(ctx)
	if err != nil {
		return nil, fmt.Errorf("list stewards: %w", err)
	}
	recs := make([]migrate.Record, 0, len(stewards))
	for _, s := range stewards {
		data, err := marshal(s)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindSteward, ID: s.ID, Data: data})
	}
	return recs, nil
}

func exportCommands(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetCommandStore()
	if store == nil {
		return nil, nil
	}
	cmds, err := store.ListCommandRecords(ctx, &business.CommandFilter{})
	if err != nil {
		return nil, fmt.Errorf("list commands: %w", err)
	}
	recs := make([]migrate.Record, 0, len(cmds))
	for _, c := range cmds {
		data, err := marshal(c)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindCommand, ID: c.ID, Data: data})
	}
	return recs, nil
}

func exportTriggers(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetTriggerStore()
	if store == nil {
		return nil, nil
	}
	triggers, err := store.ListTriggers(ctx, business.TriggerStoreFilter{})
	if err != nil {
		return nil, fmt.Errorf("list triggers: %w", err)
	}
	recs := make([]migrate.Record, 0, len(triggers))
	for _, tr := range triggers {
		data, err := marshal(tr)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindTrigger, ID: tr.ID, Data: data})
	}
	return recs, nil
}

// exportPushes exports pending and in-progress push records.
// The PushStore interface does not expose a list-all method; only
// GetPendingPushes (pending + in_progress) is available for enumeration.
func exportPushes(ctx context.Context, mgr *interfaces.StorageManager) ([]migrate.Record, error) {
	store := mgr.GetPushStore()
	if store == nil {
		return nil, nil
	}
	pushes, err := store.GetPendingPushes(ctx)
	if err != nil {
		return nil, fmt.Errorf("get pending pushes: %w", err)
	}
	recs := make([]migrate.Record, 0, len(pushes))
	for _, p := range pushes {
		data, err := marshal(p)
		if err != nil {
			return nil, err
		}
		recs = append(recs, migrate.Record{Kind: kindPush, ID: p.ID, Data: data})
	}
	return recs, nil
}

// exportIPTrust exports IP-trust entries for each of the given tenant IDs.
func exportIPTrust(ctx context.Context, mgr *interfaces.StorageManager, tenantIDs []string) ([]migrate.Record, error) {
	store := mgr.GetIPTrustStore()
	if store == nil {
		return nil, nil
	}
	var recs []migrate.Record
	for _, tid := range tenantIDs {
		entries, err := store.ListTrustedRanges(ctx, tid)
		if err != nil {
			return nil, fmt.Errorf("list ip trust ranges for tenant %s: %w", tid, err)
		}
		for _, e := range entries {
			data, err := marshal(e)
			if err != nil {
				return nil, err
			}
			id := tid + "/" + e.CIDR
			recs = append(recs, migrate.Record{Kind: kindIPTrust, ID: id, Data: data})
		}
	}
	return recs, nil
}

// ─── import ──────────────────────────────────────────────────────────────────

// importAll writes all records to mgr using upsert semantics so that calling
// importAll twice with the same records yields the same final state.
func importAll(ctx context.Context, mgr *interfaces.StorageManager, records []migrate.Record) error {
	for i := range records {
		if err := importRecord(ctx, mgr, records[i]); err != nil {
			return fmt.Errorf("import %s/%s: %w", records[i].Kind, records[i].ID, err)
		}
	}
	return nil
}

func importRecord(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	switch rec.Kind {
	case kindConfig:
		return importConfig(ctx, mgr, rec)
	case kindAudit:
		return importAudit(ctx, mgr, rec)
	case kindRBACPermission:
		return importRBACPermission(ctx, mgr, rec)
	case kindRBACRole:
		return importRBACRole(ctx, mgr, rec)
	case kindRBACSubject:
		return importRBACSubject(ctx, mgr, rec)
	case kindRBACAssignment:
		return importRBACAssignment(ctx, mgr, rec)
	case kindTenant:
		return importTenant(ctx, mgr, rec)
	case kindClientTenant:
		return importClientTenant(ctx, mgr, rec)
	case kindRegistrationToken:
		return importRegistrationToken(ctx, mgr, rec)
	case kindSession:
		return importSession(ctx, mgr, rec)
	case kindSteward:
		return importSteward(ctx, mgr, rec)
	case kindCommand:
		return importCommand(ctx, mgr, rec)
	case kindTrigger:
		return importTrigger(ctx, mgr, rec)
	case kindPush:
		return importPush(ctx, mgr, rec)
	case kindIPTrust:
		return importIPTrust(ctx, mgr, rec)
	default:
		return fmt.Errorf("unknown record kind %q", rec.Kind)
	}
}

func importConfig(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetConfigStore()
	if store == nil {
		return fmt.Errorf("config store not available")
	}
	var entry cfgconfig.ConfigEntry
	if err := json.Unmarshal(rec.Data, &entry); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	return store.StoreConfig(ctx, &entry)
}

func importAudit(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetAuditStore()
	if store == nil {
		return fmt.Errorf("audit store not available")
	}
	var entry business.AuditEntry
	if err := json.Unmarshal(rec.Data, &entry); err != nil {
		return fmt.Errorf("unmarshal audit entry: %w", err)
	}
	// Audit entries are immutable. Check existence first to avoid
	// appending duplicate records in backends that do not deduplicate by ID
	// (e.g. the flatfile provider appends to a JSONL file).
	if existing, err := store.GetAuditEntry(ctx, entry.ID); err == nil && existing != nil {
		return nil
	}
	return store.StoreAuditEntry(ctx, &entry)
}

func importRBACPermission(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetRBACStore()
	if store == nil {
		return fmt.Errorf("RBAC store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize RBAC store: %w", err)
		}
	}
	var perm common.Permission
	if err := json.Unmarshal(rec.Data, &perm); err != nil {
		return fmt.Errorf("unmarshal permission: %w", err)
	}
	if err := store.StorePermission(ctx, &perm); err != nil {
		return store.UpdatePermission(ctx, &perm)
	}
	return nil
}

func importRBACRole(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetRBACStore()
	if store == nil {
		return fmt.Errorf("RBAC store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize RBAC store: %w", err)
		}
	}
	var role common.Role
	if err := json.Unmarshal(rec.Data, &role); err != nil {
		return fmt.Errorf("unmarshal role: %w", err)
	}
	if err := store.StoreRole(ctx, &role); err != nil {
		return store.UpdateRole(ctx, &role)
	}
	return nil
}

func importRBACSubject(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetRBACStore()
	if store == nil {
		return fmt.Errorf("RBAC store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize RBAC store: %w", err)
		}
	}
	var subj common.Subject
	if err := json.Unmarshal(rec.Data, &subj); err != nil {
		return fmt.Errorf("unmarshal subject: %w", err)
	}
	if err := store.StoreSubject(ctx, &subj); err != nil {
		return store.UpdateSubject(ctx, &subj)
	}
	return nil
}

func importRBACAssignment(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetRBACStore()
	if store == nil {
		return fmt.Errorf("RBAC store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize RBAC store: %w", err)
		}
	}
	var a common.RoleAssignment
	if err := json.Unmarshal(rec.Data, &a); err != nil {
		return fmt.Errorf("unmarshal role assignment: %w", err)
	}
	// Check for existence to avoid duplicate-constraint violations.
	existing, _ := store.ListRoleAssignments(ctx, a.SubjectId, a.RoleId, a.TenantId)
	for _, ex := range existing {
		if ex.Id == a.Id {
			return nil // already present
		}
	}
	return store.StoreRoleAssignment(ctx, &a)
}

func importTenant(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetTenantStore()
	if store == nil {
		return fmt.Errorf("tenant store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize tenant store: %w", err)
		}
	}
	var t business.TenantData
	if err := json.Unmarshal(rec.Data, &t); err != nil {
		return fmt.Errorf("unmarshal tenant: %w", err)
	}
	if err := store.CreateTenant(ctx, &t); err != nil {
		if errors.Is(err, business.ErrTenantAlreadyExists) {
			return store.UpdateTenant(ctx, &t)
		}
		return err
	}
	return nil
}

func importClientTenant(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetClientTenantStore()
	if store == nil {
		return fmt.Errorf("client tenant store not available")
	}
	var ct business.ClientTenant
	if err := json.Unmarshal(rec.Data, &ct); err != nil {
		return fmt.Errorf("unmarshal client tenant: %w", err)
	}
	return store.StoreClientTenant(&ct)
}

func importRegistrationToken(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetRegistrationTokenStore()
	if store == nil {
		return fmt.Errorf("registration token store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize registration token store: %w", err)
		}
	}
	var tok business.RegistrationTokenData
	if err := json.Unmarshal(rec.Data, &tok); err != nil {
		return fmt.Errorf("unmarshal registration token: %w", err)
	}
	if err := store.SaveToken(ctx, &tok); err != nil {
		return store.UpdateToken(ctx, &tok)
	}
	return nil
}

func importSession(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetSessionStore()
	if store == nil {
		return fmt.Errorf("session store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize session store: %w", err)
		}
	}
	var s business.Session
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}
	if err := store.CreateSession(ctx, &s); err != nil {
		return store.UpdateSession(ctx, s.SessionID, &s)
	}
	return nil
}

func importSteward(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetStewardStore()
	if store == nil {
		return fmt.Errorf("steward store not available")
	}
	if init, ok := store.(interface{ Initialize(context.Context) error }); ok {
		if err := init.Initialize(ctx); err != nil {
			return fmt.Errorf("initialize steward store: %w", err)
		}
	}
	var s business.StewardRecord
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		return fmt.Errorf("unmarshal steward: %w", err)
	}
	if err := store.RegisterSteward(ctx, &s); err != nil {
		if errors.Is(err, business.ErrStewardAlreadyExists) {
			// Re-sync the status field on idempotent re-run.
			return store.UpdateStewardStatus(ctx, s.ID, s.Status)
		}
		return err
	}
	return nil
}

func importCommand(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetCommandStore()
	if store == nil {
		return fmt.Errorf("command store not available")
	}
	var cmd business.CommandRecord
	if err := json.Unmarshal(rec.Data, &cmd); err != nil {
		return fmt.Errorf("unmarshal command: %w", err)
	}
	// Check existence before creating to avoid duplicate-constraint violations.
	if existing, err := store.GetCommandRecord(ctx, cmd.ID); err == nil && existing != nil {
		return nil // already present
	}
	return store.CreateCommandRecord(ctx, &cmd)
}

func importTrigger(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetTriggerStore()
	if store == nil {
		return fmt.Errorf("trigger store not available")
	}
	var tr business.TriggerRecord
	if err := json.Unmarshal(rec.Data, &tr); err != nil {
		return fmt.Errorf("unmarshal trigger: %w", err)
	}
	return store.StoreTrigger(ctx, &tr)
}

func importPush(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetPushStore()
	if store == nil {
		return fmt.Errorf("push store not available")
	}
	var p business.PushRecord
	if err := json.Unmarshal(rec.Data, &p); err != nil {
		return fmt.Errorf("unmarshal push: %w", err)
	}
	// Check existence to avoid duplicate-constraint violations.
	if existing, err := store.GetPush(ctx, p.ID); err == nil && existing != nil {
		return nil // already present
	}
	if err := store.CreatePush(ctx, &p); err != nil {
		return err
	}
	// Restore the original status if it was in_progress.
	if p.Status == business.PushStatusInProgress {
		return store.UpdatePushStatus(ctx, p.ID, p.Status)
	}
	return nil
}

// importIPTrust adds each IP-trust entry to the target. AddTrustedRange is
// idempotent per its contract ("if the CIDR was previously revoked it is
// re-activated").
func importIPTrust(ctx context.Context, mgr *interfaces.StorageManager, rec migrate.Record) error {
	store := mgr.GetIPTrustStore()
	if store == nil {
		return fmt.Errorf("ip trust store not available")
	}
	var e business.IPTrustEntry
	if err := json.Unmarshal(rec.Data, &e); err != nil {
		return fmt.Errorf("unmarshal ip trust entry: %w", err)
	}
	if err := store.AddTrustedRange(ctx, e.TenantID, e.CIDR, e.PreSeeded); err != nil {
		return err
	}
	if e.Revoked {
		return store.RevokeTrustedRange(ctx, e.TenantID, e.CIDR)
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func countByKind(records []migrate.Record) map[string]int {
	counts := make(map[string]int, 16)
	for _, r := range records {
		counts[r.Kind]++
	}
	return counts
}
