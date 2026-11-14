// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"os"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/security"
)

// testTakeOver runs the real rights reset with the calling user as the owner it
// assigns, so the walk (modes, links, quarantine) runs without root.
func testTakeOver(roots []string) (security.TakeoverReport, error) {
	return security.TakeOverForRepairAs(roots, os.Geteuid())
}

// logEntries returns a copy of every log entry received so far.
func (s *roServer) logEntries() []*transportpb.LogEntry {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	return append([]*transportpb.LogEntry(nil), s.logSeen...)
}

// receivedRepairFlush reports whether a repair_flush entry for the named file
// has reached the controller.
func (s *roServer) receivedRepairFlush(file string) bool {
	for _, e := range s.logEntries() {
		if e.GetFields()["source"] == "repair_flush" && e.GetFields()["file"] == file {
			return true
		}
	}
	return false
}
