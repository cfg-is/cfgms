// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// StewardLogCount copies all steward log files from the container and returns how
// many times any of wants occurs across them. Log files persist across container
// restarts and subtests, so a wait for an event captures this count before the
// action that should produce it and waits for it to grow (Issue #4671).
func (s *FleetTestSuite) StewardLogCount(t *testing.T, container string, wants ...string) int {
	t.Helper()
	tmpDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- docker/tar are fixed binaries; arguments are test-controlled fleet container names and paths, never external input
	if _, err := exec.CommandContext(ctx, "docker", "cp",
		container+":/tmp/cfgms/.", tmpDir).CombinedOutput(); err != nil {
		return 0
	}
	entries, _ := os.ReadDir(tmpDir)
	count := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(tmpDir, entry.Name())) // #nosec G304 -- path is inside the t.TempDir() copy of the container log directory
		if err != nil {
			continue
		}
		for _, want := range wants {
			count += strings.Count(string(content), want)
		}
	}
	return count
}

// WaitForNewStewardLogEntry waits until any of wants occurs more often than the
// before count captured with StewardLogCount — that is, until the event is logged
// anew, not merely present from an earlier run (Issue #4671).
func (s *FleetTestSuite) WaitForNewStewardLogEntry(t *testing.T, container string, before int, timeout time.Duration, wants ...string) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.StewardLogCount(t, container, wants...) > before {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// StewardSessionMarkers are the steward log lines written when a control session
// to the controller is established (cmd/steward/main.go).
var StewardSessionMarkers = []string{
	"Connected to controller via gRPC transport",
	"Reconnected to controller via stored identity",
}

// stewardIDFieldPattern matches one steward_id field of a JSON log line.
var stewardIDFieldPattern = regexp.MustCompile(`"steward_id"\s*:\s*"([^"]*)"`)

// isCompleteStewardID reports whether id is a steward ID as the controller knows
// it. The steward logs some steward_id fields through logging.RedactedID, which
// keeps 8 characters and appends U+2026 ("steward-…", Issue #981); such a value
// names no steward, so it is never a complete ID. The ellipsis is matched both
// as the character and as the JSON escape a different encoder would write.
func isCompleteStewardID(id string) bool {
	return id != "" && !strings.Contains(id, "…") && !strings.Contains(strings.ToLower(id), `\u2026`)
}

// ParseStewardIDFromLogText returns the last complete steward ID in steward log
// text. Redacted and empty steward_id fields are skipped, not returned: which one
// comes last depends on which line the steward wrote most recently, and a log read
// between a redacted line and the next full-ID line must not yield "steward-…"
// (Issue #6346). It reports false when the text carries no complete ID.
func ParseStewardIDFromLogText(logText string) (string, bool) {
	matches := stewardIDFieldPattern.FindAllStringSubmatch(logText, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		if isCompleteStewardID(matches[i][1]) {
			return matches[i][1], true
		}
	}
	return "", false
}

// LastLines returns the last n lines of s.
func LastLines(s string, n int) string {
	lines := splitLines(s)
	if len(lines) <= n {
		return s
	}
	return joinLines(lines[len(lines)-n:])
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func joinLines(lines []string) string {
	result := ""
	for i, l := range lines {
		if i > 0 {
			result += "\n"
		}
		result += l
	}
	return result
}
