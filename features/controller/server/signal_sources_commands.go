// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"fmt"

	"github.com/cfgis/cfgms/features/controller/commands"
)

func init() {
	registerSignalSource(commandSignalSource)
}

// commandSignalSource exports command send outcomes and completion latency per
// command type by registering the command signals and handing them to the
// command publisher. A server without a publisher exports nothing.
func commandSignalSource(s *Server) error {
	if s.commandPublisher == nil {
		return nil
	}
	signals, err := commands.NewSignals(s.healthCollector.Signals())
	if err != nil {
		return fmt.Errorf("command signals: %w", err)
	}
	s.commandPublisher.SetSignals(signals)
	return nil
}
