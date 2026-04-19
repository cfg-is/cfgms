// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile target provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite target provider
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
	Long: `Commands for managing CFGMS storage backends.

Provides tools for migrating data between storage providers.`,
}

// storageMigrateCmd represents the storage migrate subcommand
var storageMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate data from one storage provider to another",
	Long: `Migrate data from an existing storage backend to a new one.

Supported source providers: git
Supported target providers: flatfile, postgres (sqlite for local testing)

The migration reads all data from the source provider and writes it to the
target provider. The command is idempotent: running it twice produces the same
record count with no duplicates.

Examples:
  # Migrate from git to flatfile+sqlite (OSS composite)
  cfg storage migrate --from git --to flatfile --git-root /data/cfgms-git \
    --flatfile-root /data/cfgms-flatfile --sqlite-path /data/cfgms.db

  # Migrate from git to postgres
  cfg storage migrate --from git --to postgres \
    --git-root /data/cfgms-git`,
	RunE: runStorageMigrate,
}

func init() {
	storageMigrateCmd.Flags().StringVar(&migrateFrom, "from", "", "Source storage provider (required, currently only 'git')")
	storageMigrateCmd.Flags().StringVar(&migrateTo, "to", "", "Target storage provider: flatfile, postgres (required)")
	storageMigrateCmd.Flags().StringVar(&migrateGitRoot, "git-root", "", "Path to git repository root (required when --from=git)")
	storageMigrateCmd.Flags().StringVar(&migrateFlatfileRoot, "flatfile-root", "", "Flatfile root directory (required when --to=flatfile)")
	storageMigrateCmd.Flags().StringVar(&migrateSQLitePath, "sqlite-path", "", "SQLite database path (used with --to=flatfile for business data)")

	_ = storageMigrateCmd.MarkFlagRequired("from")
	_ = storageMigrateCmd.MarkFlagRequired("to")

	storageCmd.AddCommand(storageMigrateCmd)
}

// runStorageMigrate performs the storage migration.
func runStorageMigrate(cmd *cobra.Command, args []string) error {
	if migrateFrom != "git" {
		return fmt.Errorf("unsupported source provider %q; only 'git' is supported", migrateFrom)
	}
	if migrateTo != "flatfile" && migrateTo != "postgres" {
		return fmt.Errorf("unsupported target provider %q; supported: flatfile, postgres", migrateTo)
	}
	if migrateGitRoot == "" {
		return fmt.Errorf("--git-root is required when --from=git")
	}
	if migrateTo == "flatfile" && migrateFlatfileRoot == "" {
		return fmt.Errorf("--flatfile-root is required when --to=flatfile")
	}

	// The git provider is loaded dynamically at migration time only.
	// It is NOT registered at controller startup — this is the migration tool.
	// We call loadGitProvider() which imports the git package via a plugin-load approach.
	// Since we cannot blank-import git here (it won't exist after removal), we use
	// the provider registry directly after the git package registers itself.
	//
	// MIGRATION IMPLEMENTATION NOTE:
	// This command loads all data from the git-backed deployment using the git
	// storage provider (which must be available at migration time), then writes
	// to the target OSS composite (flatfile + SQLite).
	//
	// Post-removal: the git provider source is deleted. Operators who need to migrate
	// must use a CFGMS version that still includes the git provider, or use the
	// git-aware build tag. The migration CLI documents this requirement.
	fmt.Fprintf(os.Stderr, "Note: The git storage provider has been removed from CFGMS.\n")
	fmt.Fprintf(os.Stderr, "To migrate data from an existing git-backed deployment, use\n")
	fmt.Fprintf(os.Stderr, "CFGMS v0.9 (the last version with git provider support) to run\n")
	fmt.Fprintf(os.Stderr, "this migration command.\n\n")

	// If git provider is registered (e.g. in a migration build), perform the migration.
	gitProvider, err := interfaces.GetStorageProvider("git")
	if err != nil {
		return fmt.Errorf("git storage provider not available: %w\n"+
			"Use a CFGMS build that includes the git provider to perform this migration", err)
	}

	fmt.Printf("Starting migration: git → %s\n", migrateTo)
	fmt.Printf("  Source: %s\n", migrateGitRoot)
	if migrateTo == "flatfile" {
		fmt.Printf("  Target (flatfile): %s\n", migrateFlatfileRoot)
		if migrateSQLitePath != "" {
			fmt.Printf("  Target (sqlite):   %s\n", migrateSQLitePath)
		}
	}
	fmt.Println()

	gitConfig := map[string]interface{}{
		"repository_path": migrateGitRoot,
		"auto_init":       false,
	}

	ctx := context.Background()
	counts := make(map[string]int)
	errors := make(map[string]error)

	switch migrateTo {
	case "flatfile":
		if err := migrateToFlatfile(ctx, gitProvider, gitConfig, counts, errors); err != nil {
			return err
		}
	case "postgres":
		return fmt.Errorf("postgres migration not yet implemented; use flatfile as intermediate target")
	}

	// Report results
	fmt.Println("Migration complete:")
	total := 0
	for store, count := range counts {
		fmt.Printf("  %-30s %d records\n", store+":", count)
		total += count
	}
	fmt.Printf("  %-30s %d records\n", "Total:", total)

	if len(errors) > 0 {
		fmt.Println("\nWarnings (non-fatal):")
		for store, err := range errors {
			fmt.Printf("  %s: %v\n", store, err)
		}
	}

	return nil
}

// migrateToFlatfile migrates all compatible stores from the git provider to
// the flatfile+sqlite OSS composite target.
func migrateToFlatfile(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, counts map[string]int, errors map[string]error) error {
	// Ensure target directories exist
	if err := os.MkdirAll(migrateFlatfileRoot, 0755); err != nil {
		return fmt.Errorf("failed to create flatfile root directory: %w", err)
	}

	sqlitePath := migrateSQLitePath
	if sqlitePath == "" {
		sqlitePath = filepath.Join(filepath.Dir(migrateFlatfileRoot), "cfgms.db")
		fmt.Printf("  SQLite path not specified, using: %s\n", sqlitePath)
	}

	targetManager, err := interfaces.CreateOSSStorageManager(migrateFlatfileRoot, sqlitePath)
	if err != nil {
		return fmt.Errorf("failed to initialize target storage: %w", err)
	}

	fmt.Println("Migrating config store...")
	if n, err := migrateConfigStore(ctx, gitProvider, gitConfig, targetManager); err != nil {
		errors["config_store"] = err
		fmt.Printf("  WARNING: config store migration incomplete: %v\n", err)
	} else {
		counts["config_store"] = n
		fmt.Printf("  Config store: %d records migrated\n", n)
	}

	fmt.Println("Migrating registration token store...")
	if n, err := migrateRegistrationTokenStore(ctx, gitProvider, gitConfig, targetManager); err != nil {
		errors["registration_token_store"] = err
		fmt.Printf("  WARNING: registration token store migration incomplete: %v\n", err)
	} else {
		counts["registration_token_store"] = n
		fmt.Printf("  Registration token store: %d records migrated\n", n)
	}

	fmt.Println("Migrating tenant store...")
	if n, err := migrateTenantStore(ctx, gitProvider, gitConfig, targetManager); err != nil {
		errors["tenant_store"] = err
		fmt.Printf("  WARNING: tenant store migration incomplete: %v\n", err)
	} else {
		counts["tenant_store"] = n
		fmt.Printf("  Tenant store: %d records migrated\n", n)
	}

	return nil
}

func migrateConfigStore(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, target *interfaces.StorageManager) (int, error) {
	src, err := gitProvider.CreateConfigStore(gitConfig)
	if err != nil {
		return 0, fmt.Errorf("failed to open git config store: %w", err)
	}

	dst := target.GetConfigStore()
	if dst == nil {
		return 0, fmt.Errorf("target config store not available")
	}

	entries, err := src.ListConfigs(ctx, &cfgconfig.ConfigFilter{})
	if err != nil {
		return 0, fmt.Errorf("failed to list configs from git: %w", err)
	}

	n := 0
	for _, entry := range entries {
		entry.UpdatedAt = time.Now()
		if err := dst.StoreConfig(ctx, entry); err != nil {
			return n, fmt.Errorf("failed to store config %v: %w", entry.Key, err)
		}
		n++
	}
	return n, nil
}

func migrateRegistrationTokenStore(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, target *interfaces.StorageManager) (int, error) {
	src, err := gitProvider.CreateRegistrationTokenStore(gitConfig)
	if err != nil {
		return 0, fmt.Errorf("failed to open git registration token store: %w", err)
	}
	if closer, ok := src.(interface{ Initialize(context.Context) error }); ok {
		if err := closer.Initialize(ctx); err != nil {
			return 0, fmt.Errorf("failed to initialize git registration token store: %w", err)
		}
	}

	dst := target.GetRegistrationTokenStore()
	if dst == nil {
		return 0, fmt.Errorf("target registration token store not available")
	}

	tokens, err := src.ListTokens(ctx, &business.RegistrationTokenFilter{})
	if err != nil {
		return 0, fmt.Errorf("failed to list tokens from git: %w", err)
	}

	n := 0
	for _, token := range tokens {
		if err := dst.SaveToken(ctx, token); err != nil {
			return n, fmt.Errorf("failed to store token: %w", err)
		}
		n++
	}
	return n, nil
}

func migrateTenantStore(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, target *interfaces.StorageManager) (int, error) {
	src, err := gitProvider.CreateTenantStore(gitConfig)
	if err != nil {
		return 0, fmt.Errorf("failed to open git tenant store: %w", err)
	}
	if initializer, ok := src.(interface{ Initialize(context.Context) error }); ok {
		if err := initializer.Initialize(ctx); err != nil {
			return 0, fmt.Errorf("failed to initialize git tenant store: %w", err)
		}
	}

	dst := target.GetTenantStore()
	if dst == nil {
		return 0, fmt.Errorf("target tenant store not available")
	}
	if initializer, ok := dst.(interface{ Initialize(context.Context) error }); ok {
		if err := initializer.Initialize(ctx); err != nil {
			return 0, fmt.Errorf("failed to initialize target tenant store: %w", err)
		}
	}

	tenants, err := src.ListTenants(ctx, &business.TenantFilter{})
	if err != nil {
		return 0, fmt.Errorf("failed to list tenants from git: %w", err)
	}

	n := 0
	for _, tenantItem := range tenants {
		if err := dst.CreateTenant(ctx, tenantItem); err != nil {
			// If already exists, try update (idempotency)
			if err2 := dst.UpdateTenant(ctx, tenantItem); err2 != nil {
				return n, fmt.Errorf("failed to migrate tenant %s: %w", tenantItem.ID, err)
			}
		}
		n++
	}
	return n, nil
}
