// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"errors"
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

// errTenantScopeRequired is returned by a read that carries neither a device
// selector nor a tenant scope. Such a read has no authorization cut at all: the
// entity graph treats an empty EntityFilter.TenantFilter / DriftFilter.TenantFilter
// as "every tenant" (pkg/entitygraph/providers/sqlite/entity_reads.go and
// .../drift.go add an owning_tenant predicate only when the filter is set), so
// serving it would return the whole deployment to whoever asked. ADR-022 §7 makes
// the caller-tenant-subtree filter mandatory on every read, so this fails closed.
var errTenantScopeRequired = errors.New("report query requires a tenant scope or an explicit device list")

// hostDiscoveryPageSize bounds one QueryEntities page during fleet-wide host
// discovery. Discovery pages rather than loading a tenant's whole host set at once.
const hostDiscoveryPageSize = 100

// tenantScopes normalizes query.TenantIDs into the distinct tenant-subtree filters
// a read must be split across. EntityFilter and DriftFilter each carry exactly one
// subtree, so N tenants means N filtered queries — never one unfiltered query
// standing in for their union. Blank entries are dropped: an empty TenantFilter
// means "all tenants" to the providers, which is precisely what must not happen.
func tenantScopes(tenantIDs []string) []string {
	scopes := make([]string, 0, len(tenantIDs))
	seen := make(map[string]struct{}, len(tenantIDs))
	for _, id := range tenantIDs {
		scope := strings.TrimSpace(id)
		if scope == "" {
			continue
		}
		if _, dup := seen[scope]; dup {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	return scopes
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
//
// The query names the hosts one of two ways. DeviceIDs reads each named host's
// history directly; those IDs are authorized against the caller's tenant at the API
// boundary. With no DeviceIDs, hosts are discovered per tenant subtree named by
// TenantIDs, and a query naming neither is refused (errTenantScopeRequired).
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
		// Fleet-wide discovery. The caller named no device, so the tenant subtree
		// is the only authorization cut left and it is mandatory (ADR-022 §7):
		// discovery runs once per requested tenant with that tenant's subtree
		// filter, and a query that can name no tenant is refused rather than
		// widened to every host in every tenant.
		scopes := tenantScopes(query.TenantIDs)
		if len(scopes) == 0 {
			return nil, errTenantScopeRequired
		}

		p.logger.Debug("all-device query: discovering hosts via entity graph",
			"tenant_scope_count", len(scopes))

		for _, scope := range scopes {
			scopeRecords, err := p.discoverHostRecords(ctx, scope, egTimeRange)
			if err != nil {
				return nil, err
			}
			allRecords = append(allRecords, scopeRecords...)
		}
	}

	p.logger.Debug("retrieved DNA records from entity graph",
		"count", len(allRecords),
		"time_range", logging.SanitizeLogValue(fmt.Sprintf("%v to %v", query.TimeRange.Start, query.TimeRange.End)),
		"devices", len(query.DeviceIDs))

	return allRecords, nil
}

// discoverHostRecords returns one DNARecord per observation of every host entity
// inside tenantScope's subtree, within egTimeRange.
//
// The tenant cut is applied by the provider (EntityFilter.TenantFilter), never
// after the fact in memory. Pagination follows the provider's page token; a token
// that repeats is a provider fault and ends the walk with an error rather than
// looping forever. A per-host history failure is skipped so one bad entity cannot
// void a tenant-wide report, but a failure of the discovery query itself is fatal:
// it truncates the fleet by an unknown amount, and a report that silently covers
// an unknown subset of hosts understates drift.
func (p *DataProvider) discoverHostRecords(
	ctx context.Context,
	tenantScope string,
	egTimeRange eginterfaces.TimeRange,
) ([]storage.DNARecord, error) {
	filter := eginterfaces.EntityFilter{Kind: "host", TenantFilter: tenantScope}

	var (
		records    []storage.DNARecord
		nextToken  string
		seenTokens = make(map[string]struct{})
	)

	for {
		page, err := p.egProvider.QueryEntities(ctx, filter, eginterfaces.PageToken{
			Token:    nextToken,
			PageSize: hostDiscoveryPageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to query host entities for tenant scope: %w", err)
		}

		for _, view := range page.Entities {
			if view == nil || view.Entity == nil {
				continue
			}
			eid := view.Entity.EID
			deviceID := eid.AuthorityName()

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
				records = append(records, storage.DNARecord{
					DeviceID: deviceID,
					StoredAt: rec.Observation.RecordedAt,
				})
			}
		}

		if page.NextToken == "" {
			return records, nil
		}
		if _, repeated := seenTokens[page.NextToken]; repeated {
			return nil, fmt.Errorf("host discovery aborted: entity graph page token repeated after %d records", len(records))
		}
		seenTokens[page.NextToken] = struct{}{}
		nextToken = page.NextToken
	}
}

// GetDriftEvents retrieves drift events for the queried devices.
// Events are sourced from the entity graph drift projection via ListDrifted:
// each DriftState whose DetectedAt falls within query.TimeRange becomes one
// DriftEvent. When DeviceIDs is non-empty only entities whose EID authority
// name matches a requested device ID are included.
//
// listDriftStates decides the authorization cut applied to the projection read —
// device selector when the query names devices, tenant subtree otherwise, and a
// refusal when the query names neither.
func (p *DataProvider) GetDriftEvents(ctx context.Context, query interfaces.DataQuery) ([]drift.DriftEvent, error) {
	// A cancelled or expired request is fatal — same rationale as GetDNAData.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("drift event query aborted: %w", err)
	}

	deviceFilter := make(map[string]bool, len(query.DeviceIDs))
	for _, id := range query.DeviceIDs {
		deviceFilter[id] = true
	}

	driftStates, err := p.listDriftStates(ctx, query)
	if err != nil {
		return nil, err
	}

	result := make([]drift.DriftEvent, 0)
	for _, state := range driftStates {
		if state == nil {
			continue
		}
		// Drift is reported against a host's fragment entities (subject
		// host:<device>/<fragment>), so the device identity of an event is the
		// EID's host authority. A drift state on any other authority kind —
		// cluster, directory, tenant — names no device and has no place in a
		// device report, so it is dropped rather than attributed to a device.
		if state.EID.AuthorityType() != "host" {
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

// listDriftStates reads the drift projection under the narrowest authorization
// cut the query carries.
//
// A device selector is the narrowest cut and takes precedence: every requested
// device is authorized against the caller's tenant subtree at the API boundary
// (enforceDeviceTenant, features/reports/api/handlers.go) before the query gets
// here, and the returned event set is restricted to exactly those devices. Layering
// a subtree filter on top would also mean resolving the tenant through
// eg_entity_index, which only carries an owning_tenant for entities whose reporter
// supplied one — that would silently drop authorized devices from the answer.
//
// Without a device selector the tenant subtree is the only cut available, and it is
// mandatory: an empty DriftFilter makes the providers skip the entity-index join
// entirely (pkg/entitygraph/providers/sqlite/drift.go) and return every drifted
// entity in the deployment, desired-vs-actual field values included. One filtered
// query is issued per requested tenant, and a query naming no tenant is refused.
func (p *DataProvider) listDriftStates(
	ctx context.Context,
	query interfaces.DataQuery,
) ([]*eginterfaces.DriftState, error) {
	if len(query.DeviceIDs) > 0 {
		states, err := p.egProvider.ListDrifted(ctx, eginterfaces.DriftFilter{})
		if err != nil {
			return nil, fmt.Errorf("failed to list drifted entities: %w", err)
		}
		return states, nil
	}

	scopes := tenantScopes(query.TenantIDs)
	if len(scopes) == 0 {
		return nil, errTenantScopeRequired
	}

	var states []*eginterfaces.DriftState
	for _, scope := range scopes {
		scoped, err := p.egProvider.ListDrifted(ctx, eginterfaces.DriftFilter{TenantFilter: scope})
		if err != nil {
			return nil, fmt.Errorf("failed to list drifted entities: %w", err)
		}
		states = append(states, scoped...)
	}

	return states, nil
}

// convertDriftStateToEvent converts an entity graph DriftState to a drift.DriftEvent.
// Device identity (deviceID = EID authority name) and detection time come from the
// drift state; attribute changes are derived from non-matching drift fields.
//
// The entity graph's drift-diff projection (ADR-022) carries desired/actual/matching
// only — no severity of its own — so each changed field's severity is classified from
// its attribute name via drift.CategorizeAttributeSeverity, the same keyword-category
// rule the pre-migration flat-store path fell back to. The event's overall severity is
// the most severe of its changes.
func convertDriftStateToEvent(deviceID string, state *eginterfaces.DriftState) drift.DriftEvent {
	var changes []*drift.AttributeChange
	severity := drift.SeverityInfo
	for _, field := range state.Fields {
		if field.Matching {
			continue
		}
		fieldSeverity := drift.CategorizeAttributeSeverity(field.Attribute)
		changes = append(changes, &drift.AttributeChange{
			Attribute:     field.Attribute,
			PreviousValue: fmt.Sprintf("%v", field.Desired),
			CurrentValue:  fmt.Sprintf("%v", field.Actual),
			ChangeType:    drift.ChangeTypeModified,
			Severity:      fieldSeverity,
		})
		if severityRank(fieldSeverity) > severityRank(severity) {
			severity = fieldSeverity
		}
	}
	return drift.DriftEvent{
		DeviceID:    deviceID,
		Timestamp:   state.DetectedAt,
		Severity:    severity,
		Changes:     changes,
		ChangeCount: len(changes),
	}
}

// severityRank orders DriftSeverity values so the most severe of a set of changes
// can be picked with a plain comparison.
func severityRank(s drift.DriftSeverity) int {
	switch s {
	case drift.SeverityCritical:
		return 2
	case drift.SeverityWarning:
		return 1
	default:
		return 0
	}
}

// GetDeviceStats calculates statistics for the specified devices.
//
// The device list is the authorization cut for this call: the signature carries
// no tenant, so an empty list names neither a device nor a tenant and there is no
// safe set to enumerate — discovering hosts here would have to query the entity
// graph with no tenant filter and would return every tenant's fleet. An empty list
// therefore yields empty statistics.
//
// Callers that want fleet-wide statistics resolve the device set under a tenant
// scope first: the report engine derives it from the tenant-filtered DNA records
// (features/reports/engine/engine.go gatherReportData) and the compliance summary
// builds it from the tenant-scoped steward registry
// (features/controller/api/handlers_compliance.go).
func (p *DataProvider) GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	stats := make(map[string]interfaces.DeviceStats)

	if len(deviceIDs) == 0 {
		p.logger.Debug("device stats requested with no device list: no tenant scope to discover under, returning empty stats")
		return stats, nil
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
