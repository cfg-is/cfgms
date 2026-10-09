// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package health

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
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

type warnCountingLogger struct {
	logging.NoopLogger
	mu    sync.Mutex
	warns []string
}

func (l *warnCountingLogger) Warn(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}

func newEmptyCPUCollector(t *testing.T) (*DefaultSystemCollector, *warnCountingLogger) {
	t.Helper()
	c, err := NewDefaultSystemCollector()
	if err != nil {
		t.Fatalf("NewDefaultSystemCollector() error = %v", err)
	}
	l := &warnCountingLogger{}
	c.logger = l
	c.readCPU = func(context.Context) ([]float64, error) { return nil, nil }
	return c, l
}

func TestCollectMetricsEmptyCPUSample(t *testing.T) {
	c, _ := newEmptyCPUCollector(t)
	if err := c.CollectMetrics(context.Background()); err != nil {
		t.Fatalf("CollectMetrics() error = %v, want nil", err)
	}
	m := c.GetMetrics()
	if m.CPUPercent != 0 {
		t.Fatalf("CPUPercent = %v, want 0", m.CPUPercent)
	}
	if m.MemoryUsedBytes == 0 || m.GoroutineCount == 0 {
		t.Fatalf("memory/goroutine metrics not populated: %+v", m)
	}
}

func TestCollectMetricsEmptyCPUSampleWarnsOnce(t *testing.T) {
	c, l := newEmptyCPUCollector(t)
	for i := 0; i < 2; i++ {
		if err := c.CollectMetrics(context.Background()); err != nil {
			t.Fatalf("CollectMetrics() #%d error = %v", i, err)
		}
	}
	if len(l.warns) != 1 {
		t.Fatalf("warnings = %d (%v), want exactly 1", len(l.warns), l.warns)
	}
	if !strings.Contains(l.warns[0], "CPU metric unavailable") {
		t.Fatalf("warning = %q, want CPU-unavailable detail", l.warns[0])
	}
}

func TestCollectMetricsCPUReadErrorStillFails(t *testing.T) {
	c, _ := newEmptyCPUCollector(t)
	c.readCPU = func(context.Context) ([]float64, error) { return nil, errors.New("boom") }
	if err := c.CollectMetrics(context.Background()); err == nil {
		t.Fatal("CollectMetrics() error = nil, want error")
	}
}
