// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DataProvider implements the interfaces.DataProvider interface
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
				p.logger.Warn("failed to get DNA history for device", "device_id", deviceID, "error", err)
				continue
			}

			for _, record := range historyResult.Records {
				allRecords = append(allRecords, *record)
			}
		}
	} else {
		// For queries without specific devices, we'd need a different approach
		// This would require additional methods in the storage manager
		p.logger.Debug("querying all devices not implemented, returning empty results")
	}

	p.logger.Debug("retrieved DNA records",
		"count", len(allRecords),
		"time_range", fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End),
		"devices", len(query.DeviceIDs))

	return allRecords, nil
}

// GetDriftEvents retrieves drift events based on the query parameters
func (p *DataProvider) GetDriftEvents(ctx context.Context, query interfaces.DataQuery) ([]drift.DriftEvent, error) {
	// For now, the drift detection system doesn't have a direct historical query interface.
	// In a full implementation, we would need to add event storage and querying to the drift package.
	// This is a limitation that would need to be addressed in the drift detection system.

	p.logger.Debug("drift event querying not fully implemented - returning empty results",
		"time_range", fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End))

	// Return empty slice for now
	return []drift.DriftEvent{}, nil
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
			p.logger.Warn("failed to calculate stats for device", "device_id", deviceID, "error", err)
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

	// Get DNA records for the device
	dnaQuery := interfaces.DataQuery{
		TimeRange: timeRange,
		DeviceIDs: []string{deviceID},
	}

	dnaRecords, err := p.GetDNAData(ctx, dnaQuery)
	if err != nil {
		return stats, fmt.Errorf("failed to get DNA records: %w", err)
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
	driftEvents, err := p.GetDriftEvents(ctx, dnaQuery)
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
			p.logger.Warn("failed to get events for compliance trend", "date", bucket, "error", err)
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
			p.logger.Warn("failed to get DNA records for device count trend", "date", bucket, "error", err)
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

// getDriftEvents is a placeholder for getting drift events
// The drift detection system currently doesn't expose historical event querying
