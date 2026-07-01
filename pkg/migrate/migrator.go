// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package migrate defines the provider-agnostic migration engine for CFGMS.
//
// Providers self-register via init() and Register(); the cfg migrate CLI
// dispatches to the registered factory for the chosen provider name.
package migrate

import (
	"context"
	"fmt"
)

// Record is an opaque unit of migrated data. Kind identifies the store type
// (e.g. "config_store", "tenant_store"); ID uniquely identifies the record
// within Kind.
type Record struct {
	Kind string
	ID   string
	Data []byte
}

// Report carries per-kind record counts, optional byte totals, and non-fatal errors.
// Bytes is nil for migrators that do not track byte sizes (e.g. storage, secrets).
type Report struct {
	Counts map[string]int
	Bytes  map[string]int64 // per-namespace byte totals; nil when not tracked
	Errors map[string]error
}

// Exporter reads all records from the source backend.
type Exporter interface {
	Export(ctx context.Context) ([]Record, error)
}

// Importer writes records to the target backend.
// Import must be idempotent: calling it twice with the same record set must
// yield the same state with no duplicates (upsert semantics).
type Importer interface {
	Import(ctx context.Context, records []Record) error
}

// Migrator orchestrates a dry-run plan and an idempotent apply run.
type Migrator interface {
	// Plan performs a dry-run: it counts what would be migrated without writing.
	Plan(ctx context.Context) (Report, error)
	// Run applies the migration. Run is idempotent: a second call yields identical
	// counts and no duplicates in the target backend.
	Run(ctx context.Context) (Report, error)
}

// MigratorFactory creates a Migrator for the given source and target backend names.
type MigratorFactory func(from, to string) (Migrator, error)

// BaseMigrator composes an Exporter and Importer into a Migrator.
// Plan exports without writing; Run exports and imports.
type BaseMigrator struct {
	exporter Exporter
	importer Importer
}

// NewBaseMigrator wraps e and i into a Migrator.
func NewBaseMigrator(e Exporter, i Importer) *BaseMigrator {
	if e == nil {
		panic("migrate.NewBaseMigrator: exporter must not be nil")
	}
	if i == nil {
		panic("migrate.NewBaseMigrator: importer must not be nil")
	}
	return &BaseMigrator{exporter: e, importer: i}
}

// Plan exports all records and returns their counts by kind; no writes are performed.
func (m *BaseMigrator) Plan(ctx context.Context) (Report, error) {
	records, err := m.exporter.Export(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("export failed: %w", err)
	}
	counts := make(map[string]int, 4)
	for _, r := range records {
		counts[r.Kind]++
	}
	return Report{Counts: counts, Errors: make(map[string]error)}, nil
}

// Run exports all records and imports them into the target; returns counts by kind.
// A second call to Run must produce identical counts with no duplicates.
func (m *BaseMigrator) Run(ctx context.Context) (Report, error) {
	records, err := m.exporter.Export(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("export failed: %w", err)
	}
	if err := m.importer.Import(ctx, records); err != nil {
		return Report{}, fmt.Errorf("import failed: %w", err)
	}
	counts := make(map[string]int, 4)
	for _, r := range records {
		counts[r.Kind]++
	}
	return Report{Counts: counts, Errors: make(map[string]error)}, nil
}
