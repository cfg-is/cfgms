// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/migrate"
)

var (
	migrateFrom          string
	migrateTo            string
	storageMigrateDryRun bool
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

Supported backends: oss (flatfile + sqlite composite), database (Postgres)

Backend locations come from environment variables:
  CFGMS_STORAGE_FLATFILE_ROOT         flatfile root directory (oss backend)
  CFGMS_STORAGE_SQLITE_PATH           SQLite database path (oss backend)
  CFGMS_STORAGE_CLUSTER_POSTGRES_DSN  Postgres DSN (database backend)

The migration reads all data from the source backend and writes it to the
target backend. The command is idempotent: running it twice produces the same
record count with no duplicates.

Use --dry-run to preview what would be migrated without writing any data.

Examples:
  # Preview migration from the OSS composite to the database (dry run)
  cfg storage migrate --from oss --to database --dry-run

  # Migrate from the OSS composite to the database
  cfg storage migrate --from oss --to database`,
	RunE: runStorageMigrate,
}

func init() {
	storageMigrateCmd.Flags().StringVar(&migrateFrom, "from", "", "Source storage backend: oss, database (required)")
	storageMigrateCmd.Flags().StringVar(&migrateTo, "to", "", "Target storage backend: oss, database (required)")
	storageMigrateCmd.Flags().BoolVar(&storageMigrateDryRun, "dry-run", false, "Preview migration plan without writing any data")

	_ = storageMigrateCmd.MarkFlagRequired("from")
	_ = storageMigrateCmd.MarkFlagRequired("to")

	storageCmd.AddCommand(storageMigrateCmd)
}

// rejectRemovedGitSource returns an error when from names the removed git
// storage provider. The input is deliberately not echoed in the message.
func rejectRemovedGitSource(from string) error {
	if strings.EqualFold(strings.TrimSpace(from), "git") {
		return errors.New("the git storage provider was removed; no migration path from git is supported")
	}
	return nil
}

// runStorageMigrate performs the storage migration by delegating to the
// "storage" migrator registered in pkg/migrate, so all provider-agnostic
// migration logic flows through the central seam.
func runStorageMigrate(cmd *cobra.Command, args []string) error {
	if err := rejectRemovedGitSource(migrateFrom); err != nil {
		return err
	}

	factory, err := migrate.Lookup("storage")
	if err != nil {
		return err
	}
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
