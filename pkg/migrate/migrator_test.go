// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package migrate_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/migrate"
)

// memExporter exports a fixed, predetermined record set.
type memExporter struct {
	records []migrate.Record
}

func (e *memExporter) Export(_ context.Context) ([]migrate.Record, error) {
	cp := make([]migrate.Record, len(e.records))
	copy(cp, e.records)
	return cp, nil
}

// memImporter accepts records via Import using upsert semantics (Kind+ID as key).
// Count returns how many distinct records are stored per Kind.
type memImporter struct {
	mu   sync.Mutex
	data map[string]migrate.Record
}

func newMemImporter() *memImporter {
	return &memImporter{data: make(map[string]migrate.Record)}
}

func (i *memImporter) Import(_ context.Context, records []migrate.Record) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, r := range records {
		i.data[r.Kind+":"+r.ID] = r
	}
	return nil
}

func (i *memImporter) count() map[string]int {
	i.mu.Lock()
	defer i.mu.Unlock()
	counts := make(map[string]int)
	for _, r := range i.data {
		counts[r.Kind]++
	}
	return counts
}

// TestMigrator_DryRunMatchesRunAndIdempotent verifies three invariants of BaseMigrator:
//  1. Plan (dry-run) returns the expected per-kind counts without writing any records.
//  2. Run returns counts equal to the Plan counts.
//  3. A second Run is idempotent: counts are unchanged and the target holds no duplicates.
func TestMigrator_DryRunMatchesRunAndIdempotent(t *testing.T) {
	ctx := context.Background()

	sourceRecords := []migrate.Record{
		{Kind: "config_store", ID: "tenant-1/cfg-a", Data: []byte(`{"k":"v1"}`)},
		{Kind: "config_store", ID: "tenant-1/cfg-b", Data: []byte(`{"k":"v2"}`)},
		{Kind: "tenant_store", ID: "tenant-1", Data: []byte(`{"name":"tenant-1"}`)},
	}

	exporter := &memExporter{records: sourceRecords}
	importer := newMemImporter()
	m := migrate.NewBaseMigrator(exporter, importer)

	// --- Phase 1: dry-run (Plan) ---
	plan, err := m.Plan(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, plan.Counts["config_store"], "plan must count 2 config records")
	assert.Equal(t, 1, plan.Counts["tenant_store"], "plan must count 1 tenant record")

	// Plan must not write anything.
	afterPlan := importer.count()
	assert.Empty(t, afterPlan, "Plan must not write any records to the target")

	// --- Phase 2: first Run ---
	report1, err := m.Run(ctx)
	require.NoError(t, err)
	assert.Equal(t, plan.Counts, report1.Counts, "Run counts must match Plan counts")

	// --- Phase 3: second Run (idempotency) ---
	report2, err := m.Run(ctx)
	require.NoError(t, err)
	assert.Equal(t, report1.Counts, report2.Counts, "second Run counts must equal first Run counts")

	// The target must hold exactly the source records — no duplicates.
	finalCounts := importer.count()
	assert.Equal(t, 2, finalCounts["config_store"], "target must hold exactly 2 config records after two runs")
	assert.Equal(t, 1, finalCounts["tenant_store"], "target must hold exactly 1 tenant record after two runs")
}

// TestRegistry_LookupUnknownListsRegistered verifies that Lookup for an unregistered
// name returns an error that names all currently registered providers.
func TestRegistry_LookupUnknownListsRegistered(t *testing.T) {
	migrate.Register("test-alpha", func(_, _ string) (migrate.Migrator, error) { return nil, nil })
	migrate.Register("test-beta", func(_, _ string) (migrate.Migrator, error) { return nil, nil })

	_, err := migrate.Lookup("not-registered")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-registered")
	assert.Contains(t, err.Error(), "test-alpha")
	assert.Contains(t, err.Error(), "test-beta")
}

// TestRegistry_LookupReturnsFactory verifies that a registered factory is returned by Lookup.
func TestRegistry_LookupReturnsFactory(t *testing.T) {
	called := false
	migrate.Register("test-gamma", func(from, to string) (migrate.Migrator, error) {
		called = true
		assert.Equal(t, "src", from)
		assert.Equal(t, "dst", to)
		return nil, nil
	})

	factory, err := migrate.Lookup("test-gamma")
	require.NoError(t, err)
	require.NotNil(t, factory)

	_, _ = factory("src", "dst")
	assert.True(t, called)
}
