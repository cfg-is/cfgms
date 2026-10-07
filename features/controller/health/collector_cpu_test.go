// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package health

import (
	"strings"
	"testing"
)

func TestFirstCPUPercent(t *testing.T) {
	t.Run("returns first sample", func(t *testing.T) {
		got, err := firstCPUPercent([]float64{12.5, 25})
		if err != nil {
			t.Fatalf("firstCPUPercent() error = %v", err)
		}
		if got != 12.5 {
			t.Fatalf("firstCPUPercent() = %v, want 12.5", got)
		}
	})

	t.Run("rejects empty sample set", func(t *testing.T) {
		_, err := firstCPUPercent(nil)
		if err == nil {
			t.Fatal("firstCPUPercent() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "no CPU samples returned") {
			t.Fatalf("firstCPUPercent() error = %q, want empty-sample detail", err)
		}
	})
}
