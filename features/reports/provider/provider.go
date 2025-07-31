package provider

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/features/reports"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DataProvider implements the reports.DataProvider interface
type DataProvider struct {
	storageManager *storage.Manager
	driftDetector  *drift.Detector
	logger         logging.Logger
}

// New creates a new data provider instance
func New(
	storageManager *storage.Manager,
	driftDetector *drift.Detector,
	logger logging.Logger,
) *DataProvider {
	return &DataProvider{
		storageManager: storageManager,
		driftDetector:  driftDetector,
		logger:         logger,
	}
}

// GetDNAData retrieves DNA records based on the query parameters
func (p *DataProvider) GetDNAData(ctx context.Context, query reports.DataQuery) ([]storage.DNARecord, error) {
	// Convert to storage query options
	options := storage.QueryOptions{
		StartTime: query.TimeRange.Start,
		EndTime:   query.TimeRange.End,
		DeviceIDs: query.DeviceIDs,
		Metadata:  query.Filters,
		Limit:     query.Limit,
		Offset:    query.Offset,
	}

	// Add tenant filtering if specified
	if len(query.TenantIDs) > 0 {
		if options.Metadata == nil {
			options.Metadata = make(map[string]string)
		}
		// Assuming tenant info is stored in metadata - adjust as needed
		for _, tenantID := range query.TenantIDs {
			options.Metadata["tenant_id"] = tenantID
		}
	}

	records, err := p.storageManager.QueryRecords(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNA records: %w", err)
	}

	p.logger.Debug("retrieved DNA records",
		"count", len(records),
		"time_range", fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End),
		"devices", len(query.DeviceIDs))

	return records, nil
}

// GetDriftEvents retrieves drift events based on the query parameters
func (p *DataProvider) GetDriftEvents(ctx context.Context, query reports.DataQuery) ([]drift.DriftEvent, error) {
	// Create drift query - assuming drift.Detector has a GetEvents method
	// This interface may need to be added to the drift package
	driftQuery := drift.EventQuery{
		StartTime: query.TimeRange.Start,
		EndTime:   query.TimeRange.End,
		DeviceIDs: query.DeviceIDs,
		Severity:  []drift.Severity{drift.Critical, drift.Warning, drift.Info},
	}

	// Filter by tenant if specified
	if len(query.TenantIDs) > 0 {
		driftQuery.TenantIDs = query.TenantIDs
	}

	events, err := p.getDriftEvents(ctx, driftQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get drift events: %w", err)
	}

	p.logger.Debug("retrieved drift events",
		"count", len(events),
		"time_range", fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End))

	return events, nil
}

// GetDeviceStats calculates statistics for specified devices
func (p *DataProvider) GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange reports.TimeRange) (map[string]reports.DeviceStats, error) {
	stats := make(map[string]reports.DeviceStats)

	// If no specific devices requested, get all devices from DNA records
	if len(deviceIDs) == 0 {
		query := reports.DataQuery{
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
func (p *DataProvider) GetTrendData(ctx context.Context, metric string, query reports.DataQuery) ([]reports.TrendPoint, error) {
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
func (p *DataProvider) calculateDeviceStats(ctx context.Context, deviceID string, timeRange reports.TimeRange) (reports.DeviceStats, error) {
	stats := reports.DeviceStats{
		DeviceID: deviceID,
	}

	// Get DNA records for the device
	dnaQuery := reports.DataQuery{
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
			if record.Timestamp.After(mostRecent.Timestamp) {
				mostRecent = record
			}
		}
		stats.LastSeen = mostRecent.Timestamp
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
func (p *DataProvider) calculateComplianceScore(events []drift.DriftEvent, timeRange reports.TimeRange) float64 {
	if len(events) == 0 {
		return 1.0 // Perfect compliance with no drift
	}

	// Weight events by severity
	var severityWeight float64
	for _, event := range events {
		switch event.Severity {
		case drift.Critical:
			severityWeight += 1.0
		case drift.Warning:
			severityWeight += 0.5
		case drift.Info:
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
func (p *DataProvider) calculateRiskLevel(complianceScore float64, events []drift.DriftEvent) reports.RiskLevel {
	// Count critical events
	criticalCount := 0
	for _, event := range events {
		if event.Severity == drift.Critical {
			criticalCount++
		}
	}

	// Risk level based on critical events and compliance score
	if criticalCount > 0 || complianceScore < 0.3 {
		return reports.RiskLevelCritical
	} else if complianceScore < 0.6 {
		return reports.RiskLevelHigh
	} else if complianceScore < 0.8 {
		return reports.RiskLevelMedium
	}
	
	return reports.RiskLevelLow
}

// getDriftEventTrends calculates drift event trends over time
func (p *DataProvider) getDriftEventTrends(ctx context.Context, query reports.DataQuery) ([]reports.TrendPoint, error) {
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
	var trends []reports.TrendPoint
	for _, bucket := range buckets {
		count := eventCounts[bucket]
		trends = append(trends, reports.TrendPoint{
			Timestamp: bucket,
			Value:     float64(count),
			Label:     fmt.Sprintf("%d events", count),
		})
	}

	return trends, nil
}

// getComplianceTrends calculates compliance score trends over time
func (p *DataProvider) getComplianceTrends(ctx context.Context, query reports.DataQuery) ([]reports.TrendPoint, error) {
	// Create daily buckets
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	var trends []reports.TrendPoint

	for _, bucket := range buckets {
		// Query drift events for this day
		dayRange := reports.TimeRange{
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
		
		trends = append(trends, reports.TrendPoint{
			Timestamp: bucket,
			Value:     score,
			Label:     fmt.Sprintf("%.2f", score),
		})
	}

	return trends, nil
}

// getDeviceCountTrends calculates device count trends over time
func (p *DataProvider) getDeviceCountTrends(ctx context.Context, query reports.DataQuery) ([]reports.TrendPoint, error) {
	buckets := p.createTimeBuckets(query.TimeRange, 24*time.Hour)
	var trends []reports.TrendPoint

	for _, bucket := range buckets {
		// Query DNA records for this day
		dayRange := reports.TimeRange{
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

		trends = append(trends, reports.TrendPoint{
			Timestamp: bucket,
			Value:     float64(len(deviceSet)),
			Label:     fmt.Sprintf("%d devices", len(deviceSet)),
		})
	}

	return trends, nil
}

// createTimeBuckets creates time buckets for trend analysis
func (p *DataProvider) createTimeBuckets(timeRange reports.TimeRange, interval time.Duration) []time.Time {
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
// This method assumes the drift.Detector has a GetEvents method
// In the actual implementation, this might need to be added to the drift package
func (p *DataProvider) getDriftEvents(ctx context.Context, query drift.EventQuery) ([]drift.DriftEvent, error) {
	// This is a placeholder implementation
	// The actual drift package would need to provide a method to query historical events
	
	// For now, return empty slice - this would need to be implemented
	// based on how drift events are actually stored and queried
	p.logger.Warn("getDriftEvents not fully implemented - returning empty results")
	return []drift.DriftEvent{}, nil
}