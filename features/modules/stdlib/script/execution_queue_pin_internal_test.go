// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"fmt"
	"testing"
)

func TestMetadataWithReservedRejectsOversizedMetadata(t *testing.T) {
	e := &QueuedExecution{Metadata: map[string]interface{}{}}
	for i := 0; i <= maxQueueMetadataEntries; i++ {
		e.Metadata[fmt.Sprintf("k%d", i)] = i
	}
	e.WithGuard("run-1", "grant-1")
	if _, err := e.metadataWithReserved(); err == nil {
		t.Fatal("expected oversized metadata to be rejected")
	}
}
