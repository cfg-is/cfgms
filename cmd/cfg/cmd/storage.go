// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile provider for migration target
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite provider for migration target
)

var (
	migrateFrom         string
	migrateTo           string
	migrateGitRoot      string
	migrateFlatfileRoot string
	migrateSQLitePath   string
)

// storageCmd represents the storage command group
var storageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Storage management commands",
	Long: `Manage CFGMS storage backends.

Provides tools for migrating data between storage providers.

Examples:
  # Migrate from git to flatfile+sqlite (OSS composite)
  cfg storage migrate --from git --to flatfile \
    --git-root /data/cfgms-storage \
    --flatfile-root /var/lib/cfgms/config \
    --sqlite-path /var/lib/cfgms/cfgms.db`,
}

// storageMigrateCmd represents the storage migrate subcommand
var storageMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate storage data between providers",
	Long: `Migrate all CFGMS data from a source storage provider to a target provider.

The git storage provider has been removed in this release. Use this command
to export all data from an existing git-backed deployment to the OSS composite
storage backend (flatfile + SQLite).

The command is idempotent: running it twice produces the same record count with
no duplicates because the target providers use upsert semantics.

Examples:
  # Migrate from git to flatfile+sqlite
  cfg storage migrate --from git --to flatfile \
    --git-root /data/cfgms-storage \
    --flatfile-root /var/lib/cfgms/config \
    --sqlite-path /var/lib/cfgms/cfgms.db

  # Dry run: migrate to a temp directory to verify
  cfg storage migrate --from git --to flatfile \
    --git-root /data/cfgms-storage \
    --flatfile-root /tmp/cfgms-migrate-test \
    --sqlite-path /tmp/cfgms-migrate-test/cfgms.db`,
	RunE: runStorageMigrate,
}

func init() {
	storageMigrateCmd.Flags().StringVar(&migrateFrom, "from", "", "Source storage provider (currently only 'git' is supported)")
	storageMigrateCmd.Flags().StringVar(&migrateTo, "to", "", "Target storage provider: flatfile|postgres")
	storageMigrateCmd.Flags().StringVar(&migrateGitRoot, "git-root", "", "Path to the git storage repository root (required when --from=git)")
	storageMigrateCmd.Flags().StringVar(&migrateFlatfileRoot, "flatfile-root", "", "Path to the flatfile storage root directory (required when --to=flatfile)")
	storageMigrateCmd.Flags().StringVar(&migrateSQLitePath, "sqlite-path", "", "Path to the SQLite database file for business-data stores (required when --to=flatfile)")

	_ = storageMigrateCmd.MarkFlagRequired("from")
	_ = storageMigrateCmd.MarkFlagRequired("to")

	storageCmd.AddCommand(storageMigrateCmd)
}

// runStorageMigrate performs the data migration
func runStorageMigrate(cmd *cobra.Command, args []string) error {
	if migrateFrom != "git" {
		return fmt.Errorf("unsupported source provider %q: only 'git' is supported", migrateFrom)
	}

	if migrateTo != "flatfile" && migrateTo != "postgres" {
		return fmt.Errorf("unsupported target provider %q: use 'flatfile' or 'postgres'", migrateTo)
	}

	if migrateGitRoot == "" {
		return fmt.Errorf("--git-root is required when --from=git")
	}

	if migrateTo == "flatfile" {
		if migrateFlatfileRoot == "" {
			return fmt.Errorf("--flatfile-root is required when --to=flatfile")
		}
		if migrateSQLitePath == "" {
			return fmt.Errorf("--sqlite-path is required when --to=flatfile (SQLite stores business-data)")
		}
	}

	// Verify source directory exists
	if _, err := os.Stat(migrateGitRoot); os.IsNotExist(err) {
		return fmt.Errorf("git-root directory does not exist: %s", migrateGitRoot)
	}

	fmt.Printf("Migrating storage: %s → %s\n", migrateFrom, migrateTo)
	fmt.Printf("  Source (git):    %s\n", migrateGitRoot)
	if migrateTo == "flatfile" {
		fmt.Printf("  Target flatfile: %s\n", migrateFlatfileRoot)
		fmt.Printf("  Target sqlite:   %s\n", migrateSQLitePath)
	}
	fmt.Println()

	return migrateFromGitToFlatfile(migrateGitRoot, migrateFlatfileRoot, migrateSQLitePath)
}

// migrateFromGitToFlatfile reads data from a git-backed storage directory and
// writes it to an OSS composite (flatfile + SQLite) storage manager.
//
// The git provider stored data as flat files within a git repository's working
// tree. This function reads those files directly from the filesystem without
// needing the git storage provider, then writes them through the target provider
// interfaces using upsert semantics.
func migrateFromGitToFlatfile(gitRoot, flatfileRoot, sqlitePath string) error {
	ctx := context.Background()

	// Ensure target directories exist
	if err := os.MkdirAll(flatfileRoot, 0750); err != nil {
		return fmt.Errorf("failed to create flatfile root %s: %w", flatfileRoot, err)
	}
	if err := os.MkdirAll(filepath.Dir(sqlitePath), 0750); err != nil {
		return fmt.Errorf("failed to create sqlite directory: %w", err)
	}

	// Create target storage manager
	targetManager, err := interfaces.CreateOSSStorageManager(flatfileRoot, sqlitePath)
	if err != nil {
		return fmt.Errorf("failed to create target storage manager: %w", err)
	}

	counts := make(map[string]int)

	// Migrate ConfigStore: git stored configs at <repo>/configs/<tenantID>/<namespace>/<name>.<format>
	// Flatfile stores at <root>/<tenantID>/configs/<namespace>/<name>.<format>
	configsDir := filepath.Join(gitRoot, "configs")
	if _, err := os.Stat(configsDir); err == nil {
		n, err := migrateConfigStore(ctx, configsDir, targetManager.GetConfigStore())
		if err != nil {
			return fmt.Errorf("config store migration failed: %w", err)
		}
		counts["configs"] = n
	}

	// Migrate AuditStore: git stored audit entries at <repo>/audit/<tenantID>/<YYYY-MM-DD>.jsonl
	// Flatfile stores at <root>/<tenantID>/audit/<YYYY-MM-DD>.jsonl
	auditDir := filepath.Join(gitRoot, "audit")
	if _, err := os.Stat(auditDir); err == nil {
		n, err := migrateAuditStore(ctx, auditDir, targetManager.GetAuditStore())
		if err != nil {
			return fmt.Errorf("audit store migration failed: %w", err)
		}
		counts["audit_entries"] = n
	}

	// Migrate TenantStore: git stored tenants at <repo>/tenants/<tenantID>.json
	tenantsDir := filepath.Join(gitRoot, "tenants")
	if _, err := os.Stat(tenantsDir); err == nil {
		n, err := migrateTenantStore(ctx, tenantsDir, targetManager.GetTenantStore())
		if err != nil {
			return fmt.Errorf("tenant store migration failed: %w", err)
		}
		counts["tenants"] = n
	} else {
		fmt.Println("  NOTE: No tenants directory found (normal if this deployment had no tenants)")
	}

	// Migrate RBACStore: git stored RBAC data at <repo>/rbac/{roles,permissions,assignments,subjects}/*.json
	rbacDir := filepath.Join(gitRoot, "rbac")
	if _, err := os.Stat(rbacDir); err == nil {
		n, err := migrateRBACStore(ctx, rbacDir, targetManager.GetRBACStore())
		if err != nil {
			return fmt.Errorf("RBAC store migration failed: %w", err)
		}
		counts["rbac_entries"] = n
	} else {
		fmt.Println("  NOTE: No rbac directory found (normal if this deployment had no RBAC data)")
	}

	// Migrate RegistrationTokenStore: git stored tokens at <repo>/registration_tokens/<tokenID>.json
	regTokensDir := filepath.Join(gitRoot, "registration_tokens")
	if _, err := os.Stat(regTokensDir); err == nil {
		n, err := migrateRegistrationTokenStore(ctx, regTokensDir, targetManager.GetRegistrationTokenStore())
		if err != nil {
			return fmt.Errorf("registration token store migration failed: %w", err)
		}
		counts["registration_tokens"] = n
	} else {
		fmt.Println("  NOTE: No registration_tokens directory found (normal if this deployment had no tokens)")
	}

	// Migrate ClientTenantStore: git stored client tenants at <repo>/client_tenants/<clientID>.json
	clientTenantsDir := filepath.Join(gitRoot, "client_tenants")
	if _, err := os.Stat(clientTenantsDir); err == nil {
		n, err := migrateClientTenantStore(clientTenantsDir, targetManager.GetClientTenantStore())
		if err != nil {
			return fmt.Errorf("client tenant store migration failed: %w", err)
		}
		counts["client_tenants"] = n
	} else {
		fmt.Println("  NOTE: No client_tenants directory found (normal if this deployment had no client tenants)")
	}

	// Print summary
	fmt.Println("Migration complete:")
	fmt.Printf("  configs migrated:              %d\n", counts["configs"])
	fmt.Printf("  audit entries migrated:        %d\n", counts["audit_entries"])
	fmt.Printf("  tenants migrated:              %d\n", counts["tenants"])
	fmt.Printf("  RBAC entries migrated:         %d\n", counts["rbac_entries"])
	fmt.Printf("  registration tokens migrated:  %d\n", counts["registration_tokens"])
	fmt.Printf("  client tenants migrated:       %d\n", counts["client_tenants"])
	fmt.Println()
	fmt.Println("NOTE: Run 'cfg storage migrate' again after verifying data integrity to confirm migration is complete.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Update controller.cfg: set storage.flatfile_root and storage.sqlite_path")
	fmt.Println("  2. Remove or comment out storage.provider: git")
	fmt.Println("  3. Restart the controller: cfgms-controller --config /etc/cfgms/controller.cfg")

	return nil
}

// migrateConfigStore walks the git config directory and imports each config entry
// into the target ConfigStore. Returns the number of entries migrated.
func migrateConfigStore(ctx context.Context, configsDir string, store interfaces.ConfigStore) (int, error) {
	if store == nil {
		return 0, nil
	}

	count := 0

	err := filepath.WalkDir(configsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip symlinks and non-regular files (defense-in-depth: TOCTOU protection)
		if !d.Type().IsRegular() {
			return nil
		}

		// Determine relative path from the configs root
		// Expected structure: <configsDir>/<tenantID>/<namespace>/<name>.<format>
		rel, err := filepath.Rel(configsDir, path)
		if err != nil {
			return err
		}

		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 3 {
			// Not a valid config path; skip
			return nil
		}

		tenantID := parts[0]
		name := parts[len(parts)-1]
		namespace := strings.Join(parts[1:len(parts)-1], "/")

		// Validate tenantID and namespace to prevent path traversal injection
		if !isValidPathComponent(tenantID) || !isValidNamespace(namespace) {
			fmt.Printf("  WARNING: skipping file with unsafe path components: %s\n", rel)
			return nil
		}

		// Determine format from extension
		ext := strings.TrimPrefix(filepath.Ext(name), ".")
		nameWithoutExt := strings.TrimSuffix(name, filepath.Ext(name))

		// Read file content
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("  WARNING: failed to read %s: %v\n", path, err)
			return nil
		}

		// Build config entry
		now := time.Now()
		entry := &interfaces.ConfigEntry{
			Key: &interfaces.ConfigKey{
				TenantID:  tenantID,
				Namespace: namespace,
				Name:      nameWithoutExt,
			},
			Data:      data,
			Format:    interfaces.ConfigFormat(ext),
			CreatedAt: now,
			UpdatedAt: now,
		}

		if err := store.StoreConfig(ctx, entry); err != nil {
			fmt.Printf("  WARNING: failed to store config %s/%s/%s: %v\n", tenantID, namespace, nameWithoutExt, err)
			return nil
		}

		count++
		return nil
	})

	return count, err
}

// migrateAuditStore walks the git audit directory and imports each audit entry
// into the target AuditStore. Returns the number of entries migrated.
func migrateAuditStore(ctx context.Context, auditDir string, store interfaces.AuditStore) (int, error) {
	if store == nil {
		return 0, nil
	}

	count := 0

	err := filepath.WalkDir(auditDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip symlinks and non-regular files (defense-in-depth: TOCTOU protection)
		if !d.Type().IsRegular() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("  WARNING: failed to read audit file %s: %v\n", path, err)
			return nil
		}

		// Parse JSONL lines
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}

			var entry interfaces.AuditEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				fmt.Printf("  WARNING: failed to parse audit entry in %s: %v\n", path, err)
				continue
			}

			if err := store.StoreAuditEntry(ctx, &entry); err != nil {
				fmt.Printf("  WARNING: failed to store audit entry %s: %v\n", entry.ID, err)
				continue
			}
			count++
		}

		return nil
	})

	return count, err
}

// migrateTenantStore walks the git tenant directory and imports each tenant
// into the target TenantStore. Returns the number of entries migrated.
func migrateTenantStore(ctx context.Context, tenantsDir string, store interfaces.TenantStore) (int, error) {
	if store == nil {
		return 0, nil
	}

	if err := store.Initialize(ctx); err != nil {
		return 0, fmt.Errorf("failed to initialize tenant store: %w", err)
	}

	count := 0

	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read tenants directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// Skip symlinks and non-regular files
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(tenantsDir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read tenant file %s: %v\n", entry.Name(), err)
			continue
		}

		var tenant interfaces.TenantData
		if err := json.Unmarshal(data, &tenant); err != nil {
			fmt.Printf("  WARNING: failed to parse tenant file %s: %v\n", entry.Name(), err)
			continue
		}

		if err := store.CreateTenant(ctx, &tenant); err != nil {
			fmt.Printf("  WARNING: failed to store tenant %s: %v\n", tenant.ID, err)
			continue
		}
		count++
	}

	return count, nil
}

// migrateRBACStore walks the git RBAC directory and imports roles, permissions,
// subjects, and assignments into the target RBACStore. Returns the total number
// of entries migrated.
func migrateRBACStore(ctx context.Context, rbacDir string, store interfaces.RBACStore) (int, error) {
	if store == nil {
		return 0, nil
	}

	if err := store.Initialize(ctx); err != nil {
		return 0, fmt.Errorf("failed to initialize RBAC store: %w", err)
	}

	count := 0

	// Migrate permissions
	permDir := filepath.Join(rbacDir, "permissions")
	if _, err := os.Stat(permDir); err == nil {
		n, err := migrateRBACPermissions(ctx, permDir, store)
		if err != nil {
			fmt.Printf("  WARNING: permission migration error: %v\n", err)
		}
		count += n
	}

	// Migrate roles
	rolesDir := filepath.Join(rbacDir, "roles")
	if _, err := os.Stat(rolesDir); err == nil {
		n, err := migrateRBACRoles(ctx, rolesDir, store)
		if err != nil {
			fmt.Printf("  WARNING: role migration error: %v\n", err)
		}
		count += n
	}

	// Migrate subjects
	subjectsDir := filepath.Join(rbacDir, "subjects")
	if _, err := os.Stat(subjectsDir); err == nil {
		n, err := migrateRBACSubjects(ctx, subjectsDir, store)
		if err != nil {
			fmt.Printf("  WARNING: subject migration error: %v\n", err)
		}
		count += n
	}

	// Migrate assignments
	assignmentsDir := filepath.Join(rbacDir, "assignments")
	if _, err := os.Stat(assignmentsDir); err == nil {
		n, err := migrateRBACAssignments(ctx, assignmentsDir, store)
		if err != nil {
			fmt.Printf("  WARNING: assignment migration error: %v\n", err)
		}
		count += n
	}

	return count, nil
}

func migrateRBACPermissions(ctx context.Context, dir string, store interfaces.RBACStore) (int, error) {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read permission file %s: %v\n", entry.Name(), err)
			continue
		}
		var perm common.Permission
		if err := json.Unmarshal(data, &perm); err != nil {
			fmt.Printf("  WARNING: failed to parse permission file %s: %v\n", entry.Name(), err)
			continue
		}
		if err := store.StorePermission(ctx, &perm); err != nil {
			fmt.Printf("  WARNING: failed to store permission %s: %v\n", perm.GetId(), err)
			continue
		}
		count++
	}
	return count, nil
}

func migrateRBACRoles(ctx context.Context, dir string, store interfaces.RBACStore) (int, error) {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read role file %s: %v\n", entry.Name(), err)
			continue
		}
		var role common.Role
		if err := json.Unmarshal(data, &role); err != nil {
			fmt.Printf("  WARNING: failed to parse role file %s: %v\n", entry.Name(), err)
			continue
		}
		if err := store.StoreRole(ctx, &role); err != nil {
			fmt.Printf("  WARNING: failed to store role %s: %v\n", role.GetId(), err)
			continue
		}
		count++
	}
	return count, nil
}

func migrateRBACSubjects(ctx context.Context, dir string, store interfaces.RBACStore) (int, error) {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read subject file %s: %v\n", entry.Name(), err)
			continue
		}
		var subject common.Subject
		if err := json.Unmarshal(data, &subject); err != nil {
			fmt.Printf("  WARNING: failed to parse subject file %s: %v\n", entry.Name(), err)
			continue
		}
		if err := store.StoreSubject(ctx, &subject); err != nil {
			fmt.Printf("  WARNING: failed to store subject %s: %v\n", subject.GetId(), err)
			continue
		}
		count++
	}
	return count, nil
}

func migrateRBACAssignments(ctx context.Context, dir string, store interfaces.RBACStore) (int, error) {
	count := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read assignment file %s: %v\n", entry.Name(), err)
			continue
		}
		var assignment common.RoleAssignment
		if err := json.Unmarshal(data, &assignment); err != nil {
			fmt.Printf("  WARNING: failed to parse assignment file %s: %v\n", entry.Name(), err)
			continue
		}
		if err := store.StoreRoleAssignment(ctx, &assignment); err != nil {
			fmt.Printf("  WARNING: failed to store assignment %s: %v\n", assignment.GetId(), err)
			continue
		}
		count++
	}
	return count, nil
}

// migrateRegistrationTokenStore walks the git registration tokens directory and
// imports each token into the target RegistrationTokenStore. Returns the number
// of entries migrated.
func migrateRegistrationTokenStore(ctx context.Context, tokensDir string, store interfaces.RegistrationTokenStore) (int, error) {
	if store == nil {
		return 0, nil
	}

	if err := store.Initialize(ctx); err != nil {
		return 0, fmt.Errorf("failed to initialize registration token store: %w", err)
	}

	count := 0

	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read registration tokens directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(tokensDir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read registration token file %s: %v\n", entry.Name(), err)
			continue
		}

		var token interfaces.RegistrationTokenData
		if err := json.Unmarshal(data, &token); err != nil {
			fmt.Printf("  WARNING: failed to parse registration token file %s: %v\n", entry.Name(), err)
			continue
		}

		if err := store.SaveToken(ctx, &token); err != nil {
			fmt.Printf("  WARNING: failed to store registration token %s: %v\n", token.Token, err)
			continue
		}
		count++
	}

	return count, nil
}

// migrateClientTenantStore walks the git client tenants directory and imports
// each client tenant into the target ClientTenantStore. Returns the number of
// entries migrated.
func migrateClientTenantStore(clientTenantsDir string, store interfaces.ClientTenantStore) (int, error) {
	if store == nil {
		return 0, nil
	}

	count := 0

	entries, err := os.ReadDir(clientTenantsDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read client tenants directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(clientTenantsDir, entry.Name()))
		if err != nil {
			fmt.Printf("  WARNING: failed to read client tenant file %s: %v\n", entry.Name(), err)
			continue
		}

		var clientTenant interfaces.ClientTenant
		if err := json.Unmarshal(data, &clientTenant); err != nil {
			fmt.Printf("  WARNING: failed to parse client tenant file %s: %v\n", entry.Name(), err)
			continue
		}

		if err := store.StoreClientTenant(&clientTenant); err != nil {
			fmt.Printf("  WARNING: failed to store client tenant %s: %v\n", clientTenant.ID, err)
			continue
		}
		count++
	}

	return count, nil
}

// isValidPathComponent returns true if s is safe to use as a tenant ID or
// single namespace segment: non-empty, no path separators or ".." components.
func isValidPathComponent(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, "/\\")
}

// isValidNamespace returns true if every segment of the slash-separated
// namespace string is a valid path component.
func isValidNamespace(ns string) bool {
	if ns == "" {
		return true // empty namespace is allowed
	}
	for _, part := range strings.Split(ns, "/") {
		if !isValidPathComponent(part) {
			return false
		}
	}
	return true
}
