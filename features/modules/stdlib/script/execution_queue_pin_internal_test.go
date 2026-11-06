// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"errors"
	"fmt"
	"testing"
)

func TestMetadataWithReservedRejectsOversizedMetadata(t *testing.T) {
	e := &QueuedExecution{Metadata: map[string]interface{}{}}
	for i := 0; i <= maxQueueMetadataEntries; i++ {
		e.Metadata[fmt.Sprintf("k%d", i)] = i
	}
	e.WithGuard("run-1", "grant-1")
	if _, err := e.metadataWithReserved(); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("expected ErrMetadataTooLarge, got %v", err)
	}
}

func TestMetadataWithReservedAcceptsMetadataAtLimit(t *testing.T) {
	e := &QueuedExecution{Metadata: map[string]interface{}{}}
	for i := 0; i < maxQueueMetadataEntries; i++ {
		e.Metadata[fmt.Sprintf("k%d", i)] = i
	}
	e.WithGuard("run-1", "grant-1")
	m, err := e.metadataWithReserved()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m[MetaGuardRunID] != "run-1" || m[MetaGuardGrantID] != "grant-1" {
		t.Fatalf("guard keys not set: %v / %v", m[MetaGuardRunID], m[MetaGuardGrantID])
	}
	if len(e.Metadata) != maxQueueMetadataEntries {
		t.Fatalf("caller metadata was mutated: %d entries", len(e.Metadata))
	}
}
