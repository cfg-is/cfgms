// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"

	"github.com/cfgis/cfgms/pkg/logging"
)

// signalSource registers service-level signals and samplers against a Server's
// health collector (s.healthCollector.Signals(), s.healthCollector.RegisterSampler)
// before the collector starts. A source reads the Server it is given; it must
// not start goroutines of its own, because samplers are the periodic hook.
type signalSource func(s *Server) error

// signalSources is the list of sources run by startHealthServices. It is filled
// at init() time by registerSignalSource and is not modified afterwards.
var signalSources []signalSource

// registerSignalSource adds a source to the list. Call it from an init().
func registerSignalSource(src signalSource) {
	signalSources = append(signalSources, src)
}

// runSignalSources runs every registered source against s. A failing or
// panicking source is logged and skipped: a missing signal must not stop the
// controller from starting. It returns the number of sources that failed.
func (s *Server) runSignalSources() int {
	failed := 0
	for i, src := range signalSources {
		if err := runSignalSource(src, s); err != nil {
			failed++
			s.logger.Warn("Signal source failed to register",
				"source_index", i, "error", logging.SanitizeLogValue(err.Error()))
		}
	}
	return failed
}

func runSignalSource(src signalSource, s *Server) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return src(s)
}
