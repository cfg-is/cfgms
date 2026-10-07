// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume

// consume_live_windows_test.go — runnable entry for the DEX consume PoC (#2571).
//
// This is NOT an ordinary unit test: it is the spike's live runner, gated behind
// the `dexconsume` build tag so it never compiles into normal builds or the
// production steward. Build it into a standalone binary and run it in the steward
// SYSTEM context (which holds the ETW StartTrace privilege):
//
//	CGO_ENABLED=1 go test -c -tags dexconsume -o dex-consume.test.exe ./features/steward/dex/
//	# then, as SYSTEM via `cfg steward exec` (env selects the window/providers):
//	dex-consume.test.exe -test.run TestDexConsumeLive -test.v
//
// Non-privileged it degrades cleanly: StartTrace is denied and the report carries
// SessionStartErr, so the binary still builds and runs anywhere. Config is via
// environment so it survives the detached Start-Process long-run path.
package dex

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return def
}

func envList(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// TestDexConsumeLive runs one consume window and prints the JSON report between
// stable markers so a caller can extract it from mixed test-framework output.
func TestDexConsumeLive(t *testing.T) {
	dur := envDuration("DEX_CONSUME_SEC", 20*time.Second)
	providers := envList("DEX_CONSUME_PROVIDERS")
	session := "cfgms-dex-consume-" + strconv.Itoa(os.Getpid())

	report := RunConsume(context.Background(), ConsumeConfig{
		SessionName: session,
		Duration:    dur,
		Providers:   providers,
	})

	fmt.Println("<<<DEX_CONSUME_JSON>>>")
	fmt.Println(MarshalReport(report))
	fmt.Println("<<<END_DEX_CONSUME_JSON>>>")

	if report.SessionStartErr != "" {
		t.Logf("session did not start (expected when not privileged): %s", report.SessionStartErr)
		return
	}
	t.Logf("consumed: total_seen=%d drained=%d dropped_ring=%d etw_lost=%d throughput/s=%.0f cpu%%=%.3f wsMB=%.1f",
		report.TotalSeen, report.TotalDrained, report.DroppedRing, report.ETWEventsLost,
		report.ThroughputPerSec, report.CPUPercent, report.WorkingSetMB)
}
