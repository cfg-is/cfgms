// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DataProvider implements the interfaces.DataProvider interface.
//
// storageManager is the concrete *storage.Manager: reports read DNA history from
// the same durable store the fleet writes to, and tests exercise that real store
// (SQLite under t.TempDir()) rather than substituting its behaviour.
type DataProvider struct {
	storageManager *storage.Manager
	driftDetector  drift.Detector
	logger         logging.Logger
}

// New creates a new data provider instance
func New(
	storageManager *storage.Manager,
	driftDetector drift.Detector,
	logger logging.Logger,
) *DataProvider {
	return &DataProvider{
		storageManager: storageManager,
		driftDetector:  driftDetector,
		logger:         logger,
	}
}

// GetDNAData retrieves DNA records based on the query parameters
func (p *DataProvider) GetDNAData(ctx context.Context, query interfaces.DataQuery) ([]storage.DNARecord, error) {
	// Per-device storage failures are deliberately swallowed below so a single bad
	// device never fails a fleet-wide report. A cancelled or expired request is not
	// a per-device failure: continuing would hammer storage for every remaining
	// device and then report success with a truncated result set, so it is fatal.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("DNA data query aborted: %w", err)
	}

	var allRecords []storage.DNARecord

	// If specific devices are requested, query each one
	if len(query.DeviceIDs) > 0 {
		for _, deviceID := range query.DeviceIDs {
			options := &storage.QueryOptions{
				TimeRange:   &storage.TimeRange{Start: query.TimeRange.Start, End: query.TimeRange.End},
				IncludeData: true,
			}

			if query.Limit > 0 {
				options.Limit = query.Limit
			}
			if query.Offset > 0 {
				options.Offset = query.Offset
			}

			historyResult, err := p.storageManager.GetHistory(ctx, deviceID, options)
			if err != nil {
				// Sequential-reassignment form required for CodeQL's ReplaceSanitizer;
				// logging.SanitizeLogValue handles full control-char stripping for security.
				safeDeviceID := logging.SanitizeLogValue(deviceID)
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
				safeErr := err.Error()
				safeErr = strings.ReplaceAll(safeErr, "\n", "_")
				safeErr = strings.ReplaceAll(safeErr, "\r", "_")
				p.logger.Warn("failed to get DNA history for device", "device_id", safeDeviceID, "error", safeErr)
				continue
			}

			for _, record := range historyResult.Records {
				allRecords = append(allRecords, *record)
			}
		}
	} else {
		// Design decision: querying all devices requires a fleet listing API not yet
		// exposed by storage.Manager. Pass explicit DeviceIDs in DataQuery for device-scoped
		// reports; tenant-scoped listing is tracked in a separate issue.
		p.logger.Debug("all-device query not supported; pass explicit DeviceIDs",
			"tenant_count", len(query.TenantIDs))
	}

	p.logger.Debug("retrieved DNA records",
		"count", len(allRecords),
		"time_range", logging.SanitizeLogValue(fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End)),
		"devices", len(query.DeviceIDs))

	return allRecords, nil
}

// GetDriftEvents computes drift events on-demand from consecutive DNA history
// snapshots stored in the DNA store. Pairs of adjacent snapshots per device are
// diffed via driftDetector.DetectDrift; the aggregate is filtered to events whose
// Timestamp falls within query.TimeRange.
//
// A device with fewer than 2 stored snapshots in the queried range contributes
// zero events, not an error. This does not add a persistent drift-event store —
// drift is computed at query time from the DNA history CFGMS already stores durably.
func (p *DataProvider) GetDriftEvents(ctx context.Context, query interfaces.DataQuery) ([]drift.DriftEvent, error) {
	// A cancelled or expired request is fatal for the same reason it is in
	// GetDNAData: the per-device error handling below is a resilience measure for
	// individual bad devices, not a licence to report success on an aborted query.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("drift event query aborted: %w", err)
	}

	// Resolve target device IDs.
	// Mirror the GetDeviceStats device-discovery pattern: when empty, discover
	// devices from the DNA history rather than requiring an explicit list.
	deviceIDs := query.DeviceIDs
	if len(deviceIDs) == 0 {
		records, err := p.GetDNAData(ctx, interfaces.DataQuery{
			TimeRange: query.TimeRange,
			Limit:     1000,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to discover devices for drift detection: %w", err)
		}
		seen := make(map[string]bool)
		for _, r := range records {
			if !seen[r.DeviceID] {
				seen[r.DeviceID] = true
				deviceIDs = append(deviceIDs, r.DeviceID)
			}
		}
	}

	var allEvents []drift.DriftEvent
	for _, deviceID := range deviceIDs {
		options := &storage.QueryOptions{
			TimeRange:   &storage.TimeRange{Start: query.TimeRange.Start, End: query.TimeRange.End},
			IncludeData: true,
		}

		historyResult, err := p.storageManager.GetHistory(ctx, deviceID, options)
		if err != nil {
			// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
			safeDeviceID := logging.SanitizeLogValue(deviceID)
			safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
			safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
			safeErr := err.Error()
			safeErr = strings.ReplaceAll(safeErr, "\n", "_")
			safeErr = strings.ReplaceAll(safeErr, "\r", "_")
			p.logger.Warn("failed to get DNA history for drift detection", "device_id", safeDeviceID, "error", safeErr)
			continue
		}

		records := historyResult.Records

		// Sort ascending by StoredAt so consecutive pairs progress forward in time.
		sort.Slice(records, func(i, j int) bool {
			return records[i].StoredAt.Before(records[j].StoredAt)
		})

		// A device with fewer than 2 records has no baseline to compare against.
		if len(records) < 2 {
			continue
		}

		for i := 1; i < len(records); i++ {
			prev := records[i-1]
			curr := records[i]
			if prev.DNA == nil || curr.DNA == nil {
				continue
			}

			events, err := p.driftDetector.DetectDrift(ctx, prev.DNA, curr.DNA)
			if err != nil {
				safeDeviceID := logging.SanitizeLogValue(deviceID)
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
				safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
				safeErr := err.Error()
				safeErr = strings.ReplaceAll(safeErr, "\n", "_")
				safeErr = strings.ReplaceAll(safeErr, "\r", "_")
				p.logger.Warn("drift detection failed for consecutive snapshots", "device_id", safeDeviceID, "error", safeErr)
				continue
			}

			for _, e := range events {
				if e != nil {
					allEvents = append(allEvents, *e)
				}
			}
		}
	}

	// Filter to events whose Timestamp falls within the queried range.
	result := []drift.DriftEvent{}
	for _, event := range allEvents {
		if !event.Timestamp.Before(query.TimeRange.Start) && !event.Timestamp.After(query.TimeRange.End) {
			result = append(result, event)
		}
	}

	p.logger.Debug("computed drift events from DNA history",
		"device_count", len(deviceIDs),
		"event_count", len(result),
		"time_range", logging.SanitizeLogValue(fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End)))

	return result, nil
}

// GetDeviceStats calculates statistics for specified devices
func (p *DataProvider) GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	stats := make(map[string]interfaces.DeviceStats)

	// If no specific devices requested, get all devices from DNA records
	if len(deviceIDs) == 0 {
		query := interfaces.DataQuery{
			TimeRange: timeRange,
			Limit:     1000, // Reasonable limit for device discovery
		}

		records, err := p.GetDNAData(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to discover devices: %w", err)
		}

		// Extract unique device IDs
		deviceSet := make(map[string]bool)
		for _, record := range records {
			deviceSet[record.DeviceID] = true
		}

		for deviceID := range deviceSet {
			deviceIDs = append(deviceIDs, deviceID)
		}
	}

	// Calculate stats for each device
	for _, deviceID := range deviceIDs {
		deviceStats, err := p.calculateDeviceStats(ctx, deviceID, timeRange)
		if err != nil {
			safeDeviceID := logging.SanitizeLogValue(deviceID)
			safeDeviceID = strings.ReplaceAll(safeDeviceID, "\n", "_")
			safeDeviceID = strings.ReplaceAll(safeDeviceID, "\r", "_")
			safeErr := err.Error()
			safeErr = strings.ReplaceAll(safeErr, "\n", "_")
			safeErr = strings.ReplaceAll(safeErr, "\r", "_")
			p.logger.Warn("failed to calculate stats for device", "device_id", safeDeviceID, "error", safeErr)
			continue
		}
		stats[deviceID] = deviceStats
	}

	return stats, nil
}

// GetTrendData retrieves trend data for a specific metric
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

// calculateDeviceStats computes comprehensive statistics for a device
func (p *DataProvider) calculateDeviceStats(ctx context.Context, deviceID string, timeRange interfaces.TimeRange) (interfaces.DeviceStats, error) {
	stats := interfaces.DeviceStats{
		DeviceID: deviceID,
	}

	// Get DNA records for the single, explicitly-requested device.
	//
	// Query storage directly rather than through GetDNAData: GetDNAData is a
	// discovery/aggregation path that intentionally swallows per-device storage
	// errors and continues so one bad device never fails a fleet-wide report.
	// For single-device stats a storage failure is fatal — silently reporting
	// zero records would misrepresent the device — so the error propagates to
	// GetDeviceStats, which skips and logs (sanitized) the offending device.
	options := &storage.QueryOptions{
		TimeRange:   &storage.TimeRange{Start: timeRange.Start, End: timeRange.End},
		IncludeData: true,
	}

	historyResult, err := p.storageManager.GetHistory(ctx, deviceID, options)
	if err != nil {
		return stats, fmt.Errorf("failed to get DNA records: %w", err)
	}

	dnaRecords := make([]storage.DNARecord, 0, len(historyResult.Records))
	for _, record := range historyResult.Records {
		dnaRecords = append(dnaRecords, *record)
	}

	stats.DNARecordCount = len(dnaRecords)

	// Find most recent DNA record for last seen time
	if len(dnaRecords) > 0 {
		mostRecent := dnaRecords[0]
		for _, record := range dnaRecords {
			if record.StoredAt.After(mostRecent.StoredAt) {
				mostRecent = record
			}
		}
		stats.LastSeen = mostRecent.StoredAt
	}

	// Get drift events for the device
	driftEvents, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
		TimeRange: timeRange,
		DeviceIDs: []string{deviceID},
	})
	if err != nil {
		return stats, fmt.Errorf("failed to get drift events: %w", err)
	}

	stats.DriftEventCount = len(driftEvents)

	// Calculate compliance score based on drift events and frequency
	stats.ComplianceScore = p.calculateComplianceScore(driftEvents, timeRange)

	// Determine risk level
	stats.RiskLevel = p.calculateRiskLevel(stats.ComplianceScore, driftEvents)

	// Calculate change frequency (changes per day)
	durationDays := timeRange.End.Sub(timeRange.Start).Hours() / 24
	if durationDays > 0 {
		stats.ChangeFrequency = float64(len(driftEvents)) / durationDays
	}

	return stats, nil
}

// calculateComplianceScore computes a compliance score based on drift events
func (p *DataProvider) calculateComplianceScore(events []drift.DriftEvent, timeRange interfaces.TimeRange) float64 {
	if len(events) == 0 {
		return 1.0 // Perfect compliance with no drift
	}

	// Weight events by severity
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

	// Normalize by time period (events per day)
	durationDays := timeRange.End.Sub(timeRange.Start).Hours() / 24
	if durationDays == 0 {
		durationDays = 1
	}

	eventsPerDay := severityWeight / durationDays

	// Convert to compliance score (0-1, where 1 is perfect compliance)
	// Assuming more than 5 weighted events per day indicates poor compliance
	score := 1.0 - (eventsPerDay / 5.0)
	if score < 0 {
		score = 0
	}

	return score
}

// calculateRiskLevel determines risk level based on compliance score and events
func (p *DataProvider) calculateRiskLevel(complianceScore float64, events []drift.DriftEvent) interfaces.RiskLevel {
	// Count critical events
	criticalCount := 0
	for _, event := range events {
		if event.Severity == drift.SeverityCritical {
			criticalCount++
		}
	}

	// Risk level based on critical events and compliance score
	if criticalCount > 0 || complianceScore < 0.3 {
		return interfaces.RiskLevelCritical
	} else if complianceScore < 0.6 {
		return interfaces.RiskLevelHigh
	} else if complianceScore < 0.8 {
		return interfaces.RiskLevelMedium
	}

	return interfaces.RiskLevelLow
}

// getDriftEventTrends calculates drift event trends over time
func (p *DataProvider) getDriftEventTrends(ctx context.Context, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	events, err := p.GetDriftEvents(ctx, query)
	if err != nil {
		return nil, err
	}

	// Group events by time buckets (daily)
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	eventCounts := make(map[time.Time]int)

	for _, event := range events {
		bucket := p.findTimeBucket(event.Timestamp, buckets)
		eventCounts[bucket]++
	}

	// Convert to trend points
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

// getComplianceTrends calculates compliance score trends over time
func (p *DataProvider) getComplianceTrends(ctx context.Context, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	// Create daily buckets
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	var trends []interfaces.TrendPoint

	for _, bucket := range buckets {
		// Query drift events for this day
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
			// device ID out of storage, so it is sanitized before logging.
			// Sequential-reassignment form required for CodeQL's ReplaceSanitizer.
			safeErr := logging.SanitizeLogValue(err.Error())
			safeErr = strings.ReplaceAll(safeErr, "\n", "_")
			safeErr = strings.ReplaceAll(safeErr, "\r", "_")
			p.logger.Warn("failed to get events for compliance trend", "date", bucket, "error", safeErr)
			continue
		}

		// Calculate compliance score for this day
		score := p.calculateComplianceScore(events, dayRange)

		trends = append(trends, interfaces.TrendPoint{
			Timestamp: bucket,
			Value:     score,
			Label:     fmt.Sprintf("%.2f", score),
		})
	}

	return trends, nil
}

// getDeviceCountTrends calculates device count trends over time
func (p *DataProvider) getDeviceCountTrends(ctx context.Context, query interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	var trends []interfaces.TrendPoint

	for _, bucket := range buckets {
		// Query DNA records for this day
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

		// Count unique devices
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

// createTimeBuckets creates time buckets for trend analysis
func (p *DataProvider) createTimeBuckets(timeRange interfaces.TimeRange, interval time.Duration) []time.Time {
	var buckets []time.Time

	current := timeRange.Start.Truncate(interval)
	for current.Before(timeRange.End) {
		buckets = append(buckets, current)
		current = current.Add(interval)
	}

	return buckets
}

// findTimeBucket finds the appropriate time bucket for a timestamp
func (p *DataProvider) findTimeBucket(timestamp time.Time, buckets []time.Time) time.Time {
	for i, bucket := range buckets {
		// If this is the last bucket or timestamp is before next bucket
		if i == len(buckets)-1 || timestamp.Before(buckets[i+1]) {
			return bucket
		}
	}

	// Fallback to first bucket
	if len(buckets) > 0 {
		return buckets[0]
	}

	return timestamp.Truncate(24 * time.Hour)
}
