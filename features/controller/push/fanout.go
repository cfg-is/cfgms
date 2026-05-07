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

// Fanout sends a CommandSyncConfig to every active steward via the command publisher.
// Stewards with Status != "active" are skipped. A failure for one steward does not
// block delivery to others.
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
		if steward.Status != "active" {
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
