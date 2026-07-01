// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
)

// cmdMemExporter exports a fixed, predetermined record set.
type cmdMemExporter struct {
	records []migrate.Record
}

func (e *cmdMemExporter) Export(_ context.Context) ([]migrate.Record, error) {
	cp := make([]migrate.Record, len(e.records))
	copy(cp, e.records)
	return cp, nil
}

// cmdMemImporter accepts records via Import using upsert semantics (Kind+ID as key).
type cmdMemImporter struct {
	mu   sync.Mutex
	data map[string]migrate.Record
}

func newCmdMemImporter() *cmdMemImporter {
	return &cmdMemImporter{data: make(map[string]migrate.Record)}
}

func (i *cmdMemImporter) Import(_ context.Context, records []migrate.Record) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, r := range records {
		i.data[r.Kind+":"+r.ID] = r
	}
	return nil
}

func (i *cmdMemImporter) count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.data)
}

// TestMigrateCmd_UnknownProviderErrors verifies that an unknown --provider value
// returns a non-zero error that names all currently registered providers.
func TestMigrateCmd_UnknownProviderErrors(t *testing.T) {
	// Register a sentinel provider so the error always names at least one entry.
	migrate.Register("sentinel-provider", func(_, _ string) (migrate.Migrator, error) {
		return migrate.NewBaseMigrator(
			&cmdMemExporter{},
			newCmdMemImporter(),
		), nil
	})

	migrateProvider = "definitely-not-a-real-provider"
	migrateFrom2 = "src"
	migrateTo2 = "dst"
	migrateDryRun = false

	err := runMigrate(migrateCmd, nil)
	require.Error(t, err, "unknown provider must return an error")
	assert.Contains(t, err.Error(), "definitely-not-a-real-provider",
		"error must name the unknown provider")
	assert.Contains(t, err.Error(), "sentinel-provider",
		"error must list the registered providers")
}

// TestMigrateCmd_DryRunDoesNotWrite verifies that --dry-run invokes Plan and
// leaves the target importer empty (no writes performed).
func TestMigrateCmd_DryRunDoesNotWrite(t *testing.T) {
	importer := newCmdMemImporter()
	migrate.Register("dry-run-test2", func(_, _ string) (migrate.Migrator, error) {
		return migrate.NewBaseMigrator(
			&cmdMemExporter{records: []migrate.Record{
				{Kind: "config_store", ID: "cfg-1", Data: []byte(`{}`)},
				{Kind: "tenant_store", ID: "t-1", Data: []byte(`{}`)},
			}},
			importer,
		), nil
	})

	migrateProvider = "dry-run-test2"
	migrateFrom2 = "src"
	migrateTo2 = "dst"
	migrateDryRun = true

	var buf bytes.Buffer
	migrateCmd.SetOut(&buf)
	defer migrateCmd.SetOut(nil)

	err := runMigrate(migrateCmd, nil)
	require.NoError(t, err)

	// Plan must report counts without writing.
	assert.Equal(t, 0, importer.count(), "dry-run must not write any records to the target")
	assert.Contains(t, buf.String(), "no writes performed")
}

// TestPrintMigrateReport_WithBytes verifies that printMigrateReport includes
// byte totals per namespace when report.Bytes is populated.
func TestPrintMigrateReport_WithBytes(t *testing.T) {
	report := migrate.Report{
		Counts: map[string]int{
			"installers": 2,
			"reports":    1,
		},
		Bytes: map[string]int64{
			"installers": 1024,
			"reports":    512,
		},
		Errors: make(map[string]error),
	}

	var buf bytes.Buffer
	err := printMigrateReport(&buf, report)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "installers", "output must name the installers namespace")
	assert.Contains(t, out, "reports", "output must name the reports namespace")
	assert.Contains(t, out, "1.0 KB", "output must show installer bytes in human-readable form")
	assert.Contains(t, out, "512 B", "output must show report bytes in human-readable form")
	assert.Contains(t, out, "Total:", "output must include a Total summary line")
	assert.Contains(t, out, "1.5 KB", "Total line must show combined byte total in human-readable form")
}

// TestPrintMigrateReport_WithoutBytes verifies backward compatibility: when Bytes
// is nil, printMigrateReport omits byte information and still prints record counts.
func TestPrintMigrateReport_WithoutBytes(t *testing.T) {
	report := migrate.Report{
		Counts: map[string]int{
			"config_store": 3,
		},
		Errors: make(map[string]error),
	}

	var buf bytes.Buffer
	err := printMigrateReport(&buf, report)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "config_store", "output must name the config_store kind")
	assert.Contains(t, out, "3 records", "output must show record count")
	assert.NotContains(t, out, " B", "output must not include byte suffix when Bytes is nil")
}

// TestMigrateCmd_RunWritesRecords verifies that without --dry-run, Run is
// invoked and the importer receives the exported records.
func TestMigrateCmd_RunWritesRecords(t *testing.T) {
	importer := newCmdMemImporter()
	migrate.Register("run-test2", func(_, _ string) (migrate.Migrator, error) {
		return migrate.NewBaseMigrator(
			&cmdMemExporter{records: []migrate.Record{
				{Kind: "config_store", ID: "cfg-1", Data: []byte(`{}`)},
				{Kind: "config_store", ID: "cfg-2", Data: []byte(`{}`)},
				{Kind: "tenant_store", ID: "t-1", Data: []byte(`{}`)},
			}},
			importer,
		), nil
	})

	migrateProvider = "run-test2"
	migrateFrom2 = "src"
	migrateTo2 = "dst"
	migrateDryRun = false

	var buf bytes.Buffer
	migrateCmd.SetOut(&buf)
	defer migrateCmd.SetOut(nil)

	err := runMigrate(migrateCmd, nil)
	require.NoError(t, err)

	// Run must write all 3 records.
	assert.Equal(t, 3, importer.count(), "Run must write all exported records to the target")
	assert.Contains(t, buf.String(), "Migration complete")
}
