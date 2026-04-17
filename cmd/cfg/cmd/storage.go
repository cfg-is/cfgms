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

	// Print summary
	fmt.Println("Migration complete:")
	fmt.Printf("  configs migrated:       %d\n", counts["configs"])
	fmt.Printf("  audit entries migrated: %d\n", counts["audit_entries"])
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
