// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package push

import (
	"context"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
)

// FanoutResult captures per-steward delivery outcomes from Fanout.
type FanoutResult struct {
	Succeeded []string
	Failed    map[string]error
}

// terminalStewardStatuses are ControllerService steward statuses that mean the
// steward is not reachable for a config push. registered/healthy/active are all
// reachable; only these definitively-dead states are skipped. (Issue #1572)
var terminalStewardStatuses = map[string]struct{}{
	"lost":         {},
	"deregistered": {},
	"quarantined":  {},
}

// Fanout sends a CommandSyncConfig to every reachable steward via the command
// publisher. Stewards in a terminal status (lost/deregistered/quarantined) are
// skipped. A failure for one steward does not block delivery to others.
func Fanout(
	ctx context.Context,
	cfg *StewardConfiguration,
	stewards []*service.StewardInfo,
	publisher *commands.Publisher,
	logger logging.Logger,
) FanoutResult {
	result := FanoutResult{
		Succeeded: []string{},
		Failed:    make(map[string]error),
	}

	for _, steward := range stewards {
		if _, terminal := terminalStewardStatuses[steward.Status]; terminal {
			continue
		}

		_, err := publisher.TriggerConfigSync(ctx, steward.ID)
		if err != nil {
			logger.Error("Failed to trigger config sync for steward",
				"steward_id", logging.SanitizeLogValue(steward.ID),
				"error", err)
			result.Failed[steward.ID] = err
		} else {
			logger.Info("Triggered config sync for steward",
				"steward_id", logging.SanitizeLogValue(steward.ID))
			result.Succeeded = append(result.Succeeded, steward.ID)
		}
	}

	return result
}
