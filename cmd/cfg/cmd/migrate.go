// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package cmd implements the CLI commands for cfg
package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/migrate"
	_ "github.com/cfgis/cfgms/pkg/migrate/secrets" // register "secrets" migrator
	_ "github.com/cfgis/cfgms/pkg/migrate/storage" // register "storage" migrator
)

var (
	migrateProvider string
	migrateFrom2    string
	migrateTo2      string
	migrateDryRun   bool
)

// migrateCmd is the top-level `cfg migrate` command.
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate data between provider backends",
	Long: `Migrate data from one backend to another using a registered provider migrator.

The --provider flag selects which provider's migrator to use (e.g. storage, secrets, blob).
The --from and --to flags select the source and target backends within that provider.
Use --dry-run to preview the migration plan (record counts only, no writes).

If no migrator is registered for the requested --provider, the command lists all
currently registered providers so the operator can correct the invocation.

Examples:
  # Preview what would be migrated (no writes)
  cfg migrate --provider storage --from git --to flatfile --dry-run

  # Execute migration
  cfg migrate --provider storage --from git --to flatfile`,
	RunE: runMigrate,
}

func init() {
	migrateCmd.Flags().StringVar(&migrateProvider, "provider", "", "Provider to migrate (required: storage, secrets, blob)")
	migrateCmd.Flags().StringVar(&migrateFrom2, "from", "", "Source backend name (required)")
	migrateCmd.Flags().StringVar(&migrateTo2, "to", "", "Target backend name (required)")
	migrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Preview migration plan without writing any data")

	_ = migrateCmd.MarkFlagRequired("provider")
	_ = migrateCmd.MarkFlagRequired("from")
	_ = migrateCmd.MarkFlagRequired("to")

	rootCmd.AddCommand(migrateCmd)
}

func runMigrate(cmd *cobra.Command, _ []string) error {
	factory, err := migrate.Lookup(migrateProvider)
	if err != nil {
		return err
	}

	m, err := factory(migrateFrom2, migrateTo2)
	if err != nil {
		return fmt.Errorf("failed to create migrator for provider %q: %w",
			logging.SanitizeLogValue(migrateProvider), err)
	}

	ctx := context.Background()
	out := cmd.OutOrStdout()

	if migrateDryRun {
		if _, err := fmt.Fprintf(out, "Dry-run: planning migration %s → %s (provider: %s)\n",
			logging.SanitizeLogValue(migrateFrom2),
			logging.SanitizeLogValue(migrateTo2),
			logging.SanitizeLogValue(migrateProvider)); err != nil {
			return err
		}

		report, err := m.Plan(ctx)
		if err != nil {
			return fmt.Errorf("migration plan failed: %w", err)
		}

		if _, err := fmt.Fprintln(out, "Migration plan (no writes performed):"); err != nil {
			return err
		}
		return printMigrateReport(out, report)
	}

	if _, err := fmt.Fprintf(out, "Migrating %s → %s (provider: %s)\n",
		logging.SanitizeLogValue(migrateFrom2),
		logging.SanitizeLogValue(migrateTo2),
		logging.SanitizeLogValue(migrateProvider)); err != nil {
		return err
	}

	report, err := m.Run(ctx)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	if _, err := fmt.Fprintln(out, "Migration complete:"); err != nil {
		return err
	}
	if err := printMigrateReport(out, report); err != nil {
		return err
	}

	if len(report.Errors) > 0 {
		if _, err := fmt.Fprintln(out, "\nWarnings (non-fatal):"); err != nil {
			return err
		}
		for store, werr := range report.Errors {
			if _, err := fmt.Fprintf(out, "  %s: %v\n", store, werr); err != nil {
				return err
			}
		}
	}

	return nil
}

func printMigrateReport(out io.Writer, report migrate.Report) error {
	total := 0
	for store, count := range report.Counts {
		if _, err := fmt.Fprintf(out, "  %-30s %d records\n", store+":", count); err != nil {
			return err
		}
		total += count
	}
	if _, err := fmt.Fprintf(out, "  %-30s %d records\n", "Total:", total); err != nil {
		return err
	}
	return nil
}
