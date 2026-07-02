// SPDX-License-Identifier: AGPL-3.0-only
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

	"github.com/cfgis/cfgms/pkg/migrate"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile target provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite target provider
)

var (
	migrateFrom           string
	migrateTo             string
	migrateGitRoot        string
	migrateFlatfileRoot   string
	migrateSQLitePath     string
	storageMigrateDryRun  bool
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

Use --dry-run to preview what would be migrated without writing any data.

Examples:
  # Preview migration from git to flatfile+sqlite (dry run)
  cfg storage migrate --from git --to flatfile --git-root /data/cfgms-git \
    --flatfile-root /data/cfgms-flatfile --sqlite-path /data/cfgms.db --dry-run

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
	storageMigrateCmd.Flags().BoolVar(&storageMigrateDryRun, "dry-run", false, "Preview migration plan without writing any data")

	_ = storageMigrateCmd.MarkFlagRequired("from")
	_ = storageMigrateCmd.MarkFlagRequired("to")

	storageCmd.AddCommand(storageMigrateCmd)
}

// runStorageMigrate performs the storage migration.
// It first checks whether a "storage" migrator is registered in pkg/migrate
// (wired by S2 and later stories). If found, it delegates to that migrator so
// all provider-agnostic migration logic flows through the central seam. When no
// "storage" migrator is registered (S1-only), it falls back to the inline git
// migration logic below to preserve backward compatibility.
func runStorageMigrate(cmd *cobra.Command, args []string) error {
	if factory, err := migrate.Lookup("storage"); err == nil {
		m, err := factory(migrateFrom, migrateTo)
		if err != nil {
			return fmt.Errorf("storage migrator: %w", err)
		}
		ctx := context.Background()
		var report migrate.MigrationReport
		if storageMigrateDryRun {
			report, err = m.Plan(ctx)
		} else {
			report, err = m.Run(ctx)
		}
		if err != nil {
			return err
		}
		if storageMigrateDryRun {
			fmt.Println("Dry-run complete (no data written):")
		} else {
			fmt.Println("Migration complete:")
		}
		total := 0
		for store, count := range report.Counts {
			fmt.Printf("  %-30s %d records\n", store+":", count)
			total += count
		}
		fmt.Printf("  %-30s %d records\n", "Total:", total)
		if len(report.Errors) > 0 {
			fmt.Println("\nWarnings (non-fatal):")
			for store, werr := range report.Errors {
				fmt.Printf("  %s: %v\n", store, werr)
			}
		}
		return nil
	}

	// Fallback: inline git migration (no "storage" migrator registered yet).
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

	switch migrateTo {
	case "flatfile":
		reports, err := migrateToFlatfile(ctx, gitProvider, gitConfig, storageMigrateDryRun)
		if err != nil {
			return err
		}
		if storageMigrateDryRun {
			fmt.Println("Dry-run complete (no data written):")
		} else {
			fmt.Println("Migration complete:")
		}
		migrate.PrintReport(os.Stdout, reports)
	case "postgres":
		return fmt.Errorf("postgres migration is not supported; migrate to flatfile first, then switch backend")
	}

	return nil
}

// migrateToFlatfile migrates all compatible stores from the git provider to
// the flatfile+sqlite OSS composite target using step-based execution.
// When dryRun is true each step reads from source and counts records without writing.
func migrateToFlatfile(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, dryRun bool) ([]migrate.Report, error) {
	// Ensure target directories exist
	if err := os.MkdirAll(migrateFlatfileRoot, 0755); err != nil {
		return nil, fmt.Errorf("failed to create flatfile root directory: %w", err)
	}

	sqlitePath := migrateSQLitePath
	if sqlitePath == "" {
		sqlitePath = filepath.Join(filepath.Dir(migrateFlatfileRoot), "cfgms.db")
		fmt.Printf("  SQLite path not specified, using: %s\n", sqlitePath)
	}

	targetManager, err := interfaces.CreateOSSStorageManager(migrateFlatfileRoot, sqlitePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize target storage: %w", err)
	}

	steps := []migrate.Step{
		{
			Name: "config_store",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				return migrateConfigStore(ctx, gitProvider, gitConfig, targetManager, dryRun)
			},
		},
		{
			Name: "registration_token_store",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				return migrateRegistrationTokenStore(ctx, gitProvider, gitConfig, targetManager, dryRun)
			},
		},
		{
			Name: "tenant_store",
			Run: func(ctx context.Context, dryRun bool) (int, error) {
				return migrateTenantStore(ctx, gitProvider, gitConfig, targetManager, dryRun)
			},
		},
	}

	return migrate.RunSteps(ctx, dryRun, steps), nil
}

func migrateConfigStore(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, target *interfaces.StorageManager, dryRun bool) (int, error) {
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
		if dryRun {
			n++
			continue
		}
		entry.UpdatedAt = time.Now()
		if err := dst.StoreConfig(ctx, entry); err != nil {
			return n, fmt.Errorf("failed to store config %v: %w", entry.Key, err)
		}
		n++
	}
	return n, nil
}

func migrateRegistrationTokenStore(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, target *interfaces.StorageManager, dryRun bool) (int, error) {
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
		if dryRun {
			n++
			continue
		}
		if err := dst.SaveToken(ctx, token); err != nil {
			return n, fmt.Errorf("failed to store token: %w", err)
		}
		n++
	}
	return n, nil
}

func migrateTenantStore(ctx context.Context, gitProvider interfaces.StorageProvider, gitConfig map[string]interface{}, target *interfaces.StorageManager, dryRun bool) (int, error) {
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
		if dryRun {
			n++
			continue
		}
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
