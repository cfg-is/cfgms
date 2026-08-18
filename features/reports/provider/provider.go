// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DataProvider implements the interfaces.DataProvider interface.
//
// egProvider is the entity graph central provider: Reports reads device identity,
// observation history, and drift state from the entity graph rather than the flat
// DNARecord store (ADR-022). Tests exercise the real SQLite EntityGraphProvider under
// t.TempDir() rather than substituting its behaviour.
type DataProvider struct {
	egProvider eginterfaces.EntityGraphProvider
	logger     logging.Logger
}

// New creates a new data provider instance backed by the entity graph.
func New(
	egProvider eginterfaces.EntityGraphProvider,
	logger logging.Logger,
) *DataProvider {
	return &DataProvider{
		egProvider: egProvider,
		logger:     logger,
	}
}

// GetDNAData retrieves DNA records based on the query parameters.
// Records are sourced from the entity graph: each observation in the host
// entity's history becomes one DNARecord (DeviceID + StoredAt; DNA is nil because
// the entity graph stores per-fragment observations, not full DNA snapshots).
func (p *DataProvider) GetDNAData(ctx context.Context, query interfaces.DataQuery) ([]storage.DNARecord, error) {
	// Per-device failures are swallowed so a single bad entity never fails a
	// fleet-wide report. A cancelled or expired request is fatal — continuing would
	// hammer the entity graph for every remaining device then report success on a
	// truncated result set.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("DNA data query aborted: %w", err)
	}

	egTimeRange := eginterfaces.TimeRange{
		From: query.TimeRange.Start,
		To:   query.TimeRange.End,
	}

	var allRecords []storage.DNARecord

	if len(query.DeviceIDs) > 0 {
		for _, deviceID := range query.DeviceIDs {
			eid, err := egtypes.NewEID("host", deviceID, "")
			if err != nil {
				// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
				safeDeviceID := logging.SanitizeLogValue(deviceID)
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
				safeErr := logging.SanitizeLogValue(err.Error())
				safeErr = strings.ReplaceAll(safeErr, "\n", "_")
				safeErr = strings.ReplaceAll(safeErr, "\r", "_")
				p.logger.Warn("failed to construct entity ID for device", "device_id", safeDeviceID, "error", safeErr)
				continue
			}

			history, err := p.egProvider.GetHistory(ctx, eid, egTimeRange)
			if err != nil {
				// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
				safeDeviceID := logging.SanitizeLogValue(deviceID)
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
				safeErr := logging.SanitizeLogValue(err.Error())
				safeErr = strings.ReplaceAll(safeErr, "\n", "_")
				safeErr = strings.ReplaceAll(safeErr, "\r", "_")
				p.logger.Warn("failed to get entity history for device", "device_id", safeDeviceID, "error", safeErr)
				continue
			}

			for _, rec := range history {
				allRecords = append(allRecords, storage.DNARecord{
					DeviceID: deviceID,
					StoredAt: rec.Observation.RecordedAt,
				})
			}
		}
	} else {
		// Discover devices by querying the entity graph for all host entities and
		// fetching each one's observation history within the requested time range.
		p.logger.Debug("all-device query: discovering hosts via entity graph",
			"tenant_count", len(query.TenantIDs))
		var nextToken string
		for {
			page, err := p.egProvider.QueryEntities(ctx, eginterfaces.EntityFilter{Kind: "host"}, eginterfaces.PageToken{Token: nextToken, PageSize: 100})
			if err != nil {
				safeErr := logging.SanitizeLogValue(err.Error())
				safeErr = strings.ReplaceAll(safeErr, "\n", "_")
				safeErr = strings.ReplaceAll(safeErr, "\r", "_")
				p.logger.Warn("failed to query host entities for DNA data discovery", "error", safeErr)
				break
			}
			for _, entity := range page.Entities {
				deviceID := entity.Entity.EID.AuthorityName()
				history, err := p.egProvider.GetHistory(ctx, entity.Entity.EID, egTimeRange)
				if err != nil {
					safeDeviceID := logging.SanitizeLogValue(deviceID)
					safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
					safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
					safeErr := logging.SanitizeLogValue(err.Error())
					safeErr = strings.ReplaceAll(safeErr, "\n", "_")
					safeErr = strings.ReplaceAll(safeErr, "\r", "_")
					p.logger.Warn("failed to get entity history for device", "device_id", safeDeviceID, "error", safeErr)
					continue
				}
				for _, rec := range history {
					allRecords = append(allRecords, storage.DNARecord{
						DeviceID: deviceID,
						StoredAt: rec.Observation.RecordedAt,
					})
				}
			}
			if page.NextToken == "" {
				break
			}
			nextToken = page.NextToken
		}
	}

	p.logger.Debug("retrieved DNA records from entity graph",
		"count", len(allRecords),
		"time_range", logging.SanitizeLogValue(fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End)),
		"devices", len(query.DeviceIDs))

	return allRecords, nil
}

// GetDriftEvents retrieves drift events for the queried devices.
// Events are sourced from the entity graph drift projection via ListDrifted:
// each DriftState whose DetectedAt falls within query.TimeRange becomes one
// DriftEvent. When DeviceIDs is non-empty only entities whose EID authority
// name matches a requested device ID are included.
func (p *DataProvider) GetDriftEvents(ctx context.Context, query interfaces.DataQuery) ([]drift.DriftEvent, error) {
	// A cancelled or expired request is fatal — same rationale as GetDNAData.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("drift event query aborted: %w", err)
	}

	deviceFilter := make(map[string]bool, len(query.DeviceIDs))
	for _, id := range query.DeviceIDs {
		deviceFilter[id] = true
	}

	driftStates, err := p.egProvider.ListDrifted(ctx, eginterfaces.DriftFilter{})
	if err != nil {
		return nil, fmt.Errorf("failed to list drifted entities: %w", err)
	}

	result := make([]drift.DriftEvent, 0)
	for _, state := range driftStates {
		if state == nil {
			continue
		}
		deviceID := state.EID.AuthorityName()
		if len(deviceFilter) > 0 && !deviceFilter[deviceID] {
			continue
		}
		if state.DetectedAt.Before(query.TimeRange.Start) || state.DetectedAt.After(query.TimeRange.End) {
			continue
		}
		result = append(result, convertDriftStateToEvent(deviceID, state))
	}

	p.logger.Debug("retrieved drift events from entity graph",
		"device_count", len(deviceFilter),
		"event_count", len(result),
		"time_range", logging.SanitizeLogValue(fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End)))

	return result, nil
}

// convertDriftStateToEvent converts an entity graph DriftState to a drift.DriftEvent.
// Device identity (deviceID = EID authority name) and detection time come from the
// drift state; attribute changes are derived from non-matching drift fields.
func convertDriftStateToEvent(deviceID string, state *eginterfaces.DriftState) drift.DriftEvent {
	var changes []*drift.AttributeChange
	for _, field := range state.Fields {
		if field.Matching {
			continue
		}
		changes = append(changes, &drift.AttributeChange{
			Attribute:     field.Attribute,
			PreviousValue: fmt.Sprintf("%v", field.Desired),
			CurrentValue:  fmt.Sprintf("%v", field.Actual),
			ChangeType:    drift.ChangeTypeModified,
			Severity:      drift.SeverityWarning,
		})
	}
	severity := drift.SeverityInfo
	if len(changes) > 0 {
		severity = drift.SeverityWarning
	}
	return drift.DriftEvent{
		DeviceID:    deviceID,
		Timestamp:   state.DetectedAt,
		Severity:    severity,
		Changes:     changes,
		ChangeCount: len(changes),
	}
}

// GetDeviceStats calculates statistics for specified devices.
func (p *DataProvider) GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	stats := make(map[string]interfaces.DeviceStats)

	// If no specific devices requested, discover devices from the entity graph.
	if len(deviceIDs) == 0 {
		query := interfaces.DataQuery{
			TimeRange: timeRange,
			Limit:     1000,
		}
		records, err := p.GetDNAData(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to discover devices: %w", err)
		}
		deviceSet := make(map[string]bool)
		for _, record := range records {
			deviceSet[record.DeviceID] = true
		}
		for deviceID := range deviceSet {
			deviceIDs = append(deviceIDs, deviceID)
		}
	}

	for _, deviceID := range deviceIDs {
		deviceStats, err := p.calculateDeviceStats(ctx, deviceID, timeRange)
		if err != nil {
			// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
			safeDeviceID := logging.SanitizeLogValue(deviceID)
			safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
			safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
			safeErr := logging.SanitizeLogValue(err.Error())
			safeErr = strings.ReplaceAll(safeErr, "\n", "_")
			safeErr = strings.ReplaceAll(safeErr, "\r", "_")
			p.logger.Warn("failed to calculate stats for device", "device_id", safeDeviceID, "error", safeErr)
			continue
		}
		stats[deviceID] = deviceStats
	}

	return stats, nil
}

// GetTrendData retrieves trend data for a specific metric.
func (p *DataProvider) GetTrendData(ctx context.Context, metric string, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	switch metric {
	case "drift_events":
		return p.getDriftEventTrends(ctx, query)
	case "compliance_score":
		return p.getComplianceTrends(ctx, query)
	case "device_count":
		return p.getDeviceCountTrends(ctx, query)
	default:
		return nil, fmt.Errorf("unsupported metric: %s", metric)
	}
}

// calculateDeviceStats computes comprehensive statistics for a single device.
// History (record count + last-seen) is read from the entity graph host entity;
// drift events are fetched via GetDriftEvents which reads the drift projection.
func (p *DataProvider) calculateDeviceStats(ctx context.Context, deviceID string, timeRange interfaces.TimeRange) (interfaces.DeviceStats, error) {
	stats := interfaces.DeviceStats{
		DeviceID: deviceID,
	}

	eid, err := egtypes.NewEID("host", deviceID, "")
	if err != nil {
		return stats, fmt.Errorf("failed to construct entity ID: %w", err)
	}

	egTimeRange := eginterfaces.TimeRange{
		From: timeRange.Start,
		To:   timeRange.End,
	}

	history, err := p.egProvider.GetHistory(ctx, eid, egTimeRange)
	if err != nil {
		return stats, fmt.Errorf("failed to get entity history: %w", err)
	}

	stats.DNARecordCount = len(history)

	for _, rec := range history {
		if rec.Observation.RecordedAt.After(stats.LastSeen) {
			stats.LastSeen = rec.Observation.RecordedAt
		}
	}

	driftEvents, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
		TimeRange: timeRange,
		DeviceIDs: []string{deviceID},
	})
	if err != nil {
		return stats, fmt.Errorf("failed to get drift events: %w", err)
	}

	stats.DriftEventCount = len(driftEvents)
	stats.ComplianceScore = p.calculateComplianceScore(driftEvents, timeRange)
	stats.RiskLevel = p.calculateRiskLevel(stats.ComplianceScore, driftEvents)

	durationDays := timeRange.End.Sub(timeRange.Start).Hours() / 24
	if durationDays > 0 {
		stats.ChangeFrequency = float64(len(driftEvents)) / durationDays
	}

	return stats, nil
}

// calculateComplianceScore computes a compliance score based on drift events.
func (p *DataProvider) calculateComplianceScore(events []drift.DriftEvent, timeRange interfaces.TimeRange) float64 {
	if len(events) == 0 {
		return 1.0 // Perfect compliance with no drift
	}

	var severityWeight float64
	for _, event := range events {
		switch event.Severity {
		case drift.SeverityCritical:
			severityWeight += 1.0
		case drift.SeverityWarning:
			severityWeight += 0.5
		case drift.SeverityInfo:
			severityWeight += 0.1
		}
	}

	durationDays := timeRange.End.Sub(timeRange.Start).Hours() / 24
	if durationDays == 0 {
		durationDays = 1
	}

	eventsPerDay := severityWeight / durationDays

	score := 1.0 - (eventsPerDay / 5.0)
	if score < 0 {
		score = 0
	}

	return score
}

// calculateRiskLevel determines risk level based on compliance score and events.
func (p *DataProvider) calculateRiskLevel(complianceScore float64, events []drift.DriftEvent) interfaces.RiskLevel {
	criticalCount := 0
	for _, event := range events {
		if event.Severity == drift.SeverityCritical {
			criticalCount++
		}
	}

	if criticalCount > 0 || complianceScore < 0.3 {
		return interfaces.RiskLevelCritical
	} else if complianceScore < 0.6 {
		return interfaces.RiskLevelHigh
	} else if complianceScore < 0.8 {
		return interfaces.RiskLevelMedium
	}

	return interfaces.RiskLevelLow
}

// getDriftEventTrends calculates drift event trends over time.
func (p *DataProvider) getDriftEventTrends(ctx context.Context, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	events, err := p.GetDriftEvents(ctx, query)
	if err != nil {
		return nil, err
	}

	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	eventCounts := make(map[time.Time]int)

	for _, event := range events {
		bucket := p.findTimeBucket(event.Timestamp, buckets)
		eventCounts[bucket]++
	}

	var trends []interfaces.TrendPoint
	for _, bucket := range buckets {
		count := eventCounts[bucket]
		trends = append(trends, interfaces.TrendPoint{
			Timestamp: bucket,
			Value:     float64(count),
			Label:     fmt.Sprintf("%d events", count),
		})
	}

	return trends, nil
}

// getComplianceTrends calculates compliance score trends over time.
func (p *DataProvider) getComplianceTrends(ctx context.Context, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	var trends []interfaces.TrendPoint

	for _, bucket := range buckets {
		dayRange := interfaces.TimeRange{
			Start: bucket,
			End:   bucket.Add(24 * time.Hour),
		}

		dayQuery := query
		dayQuery.TimeRange = dayRange

		events, err := p.GetDriftEvents(ctx, dayQuery)
		if err != nil {
			// One unavailable day must not void the whole trend line: skip the
			// bucket and keep going. The error text can carry a caller-supplied
			// device ID out of the entity graph, so it is sanitized before logging.
			// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
			safeErr := logging.SanitizeLogValue(err.Error())
			safeErr = strings.ReplaceAll(safeErr, "\n", "_")
			safeErr = strings.ReplaceAll(safeErr, "\r", "_")
			p.logger.Warn("failed to get events for compliance trend", "date", bucket, "error", safeErr)
			continue
		}

		score := p.calculateComplianceScore(events, dayRange)

		trends = append(trends, interfaces.TrendPoint{
			Timestamp: bucket,
			Value:     score,
			Label:     fmt.Sprintf("%.2f", score),
		})
	}

	return trends, nil
}

// getDeviceCountTrends calculates device count trends over time.
func (p *DataProvider) getDeviceCountTrends(ctx context.Context, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	var trends []interfaces.TrendPoint

	for _, bucket := range buckets {
		dayRange := interfaces.TimeRange{
			Start: bucket,
			End:   bucket.Add(24 * time.Hour),
		}

		dayQuery := query
		dayQuery.TimeRange = dayRange

		records, err := p.GetDNAData(ctx, dayQuery)
		if err != nil {
			// Skip the unavailable day rather than voiding the whole trend line.
			// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
			safeErr := logging.SanitizeLogValue(err.Error())
			safeErr = strings.ReplaceAll(safeErr, "\n", "_")
			safeErr = strings.ReplaceAll(safeErr, "\r", "_")
			p.logger.Warn("failed to get DNA records for device count trend", "date", bucket, "error", safeErr)
			continue
		}

		deviceSet := make(map[string]bool)
		for _, record := range records {
			deviceSet[record.DeviceID] = true
		}

		trends = append(trends, interfaces.TrendPoint{
			Timestamp: bucket,
			Value:     float64(len(deviceSet)),
			Label:     fmt.Sprintf("%d devices", len(deviceSet)),
		})
	}

	return trends, nil
}

// createTimeBuckets creates time buckets for trend analysis.
func (p *DataProvider) createTimeBuckets(timeRange interfaces.TimeRange, interval time.Duration) []time.Time {
	var buckets []time.Time

	current := timeRange.Start.Truncate(interval)
	for current.Before(timeRange.End) {
		buckets = append(buckets, current)
		current = current.Add(interval)
	}

	return buckets
}

// findTimeBucket finds the appropriate time bucket for a timestamp.
func (p *DataProvider) findTimeBucket(timestamp time.Time, buckets []time.Time) time.Time {
	for i, bucket := range buckets {
		if i == len(buckets)-1 || timestamp.Before(buckets[i+1]) {
			return bucket
		}
	}

	if len(buckets) > 0 {
		return buckets[0]
	}

	return timestamp.Truncate(24 * time.Hour)
}
