// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"
	"regexp"
	"time"

	"github.com/cfgis/cfgms/pkg/version"
)

// processStartTime is captured when the server package initialises, which is
// the earliest point the controller binary controls. A restart yields a new
// value, so a change in cfgms_process_start_time_seconds marks a restart.
var processStartTime = time.Now()

// revisionLabelPattern is the shape a revision label may take: a hex commit id,
// optionally marked "-dirty", or the literal "unknown". Anything else (a
// hand-set ldflags value, for example) is exported as "unknown" so the label
// value stays bounded and free of arbitrary text.
var revisionLabelPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{7,64}(?:-dirty)?|unknown)$`)

// revisionLabel returns the revision to export as a label value.
func revisionLabel(revision string) string {
	if revisionLabelPattern.MatchString(revision) {
		return revision
	}
	return "unknown"
}

func init() { registerSignalSource(registerIdentitySignals) }

// registerIdentitySignals exports the running build and process identity:
// cfgms_build_info{revision,version} with value 1, and
// cfgms_process_start_time_seconds as a Unix timestamp. Both are set once at
// registration; neither needs a sampler.
func registerIdentitySignals(s *Server) error {
	signals := s.healthCollector.Signals()

	revision := revisionLabel(version.Revision())
	ver := version.ShortWithoutPrefix()
	buildInfo, err := signals.RegisterGauge("cfgms_build_info",
		"Build information of the running controller; the value is always 1.",
		map[string][]string{"revision": {revision}, "version": {ver}})
	if err != nil {
		return fmt.Errorf("register cfgms_build_info: %w", err)
	}
	if err := buildInfo.Set(1, map[string]string{"revision": revision, "version": ver}); err != nil {
		return fmt.Errorf("set cfgms_build_info: %w", err)
	}

	startTime, err := signals.RegisterGauge("cfgms_process_start_time_seconds",
		"Start time of the controller process in seconds since the Unix epoch.", nil)
	if err != nil {
		return fmt.Errorf("register cfgms_process_start_time_seconds: %w", err)
	}
	if err := startTime.Set(float64(processStartTime.UnixNano())/1e9, nil); err != nil {
		return fmt.Errorf("set cfgms_process_start_time_seconds: %w", err)
	}
	return nil
}
