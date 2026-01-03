// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package database provides utilities for PostgreSQL storage provider
package database

import (
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// serializeMetadata converts a metadata map to JSON bytes
func serializeMetadata(metadata map[string]interface{}) ([]byte, error) {
	if metadata == nil {
		return []byte("{}"), nil
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return data, nil
}

// deserializeMetadata converts JSON bytes to a metadata map
func deserializeMetadata(data []byte) (map[string]interface{}, error) {
	if len(data) == 0 {
		return make(map[string]interface{}), nil
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, nil
}

// serializeAuditChanges converts AuditChanges to JSON for database storage
func serializeAuditChanges(changes *interfaces.AuditChanges) ([]byte, error) {
	if changes == nil {
		return []byte("{}"), nil
	}

	data, err := json.Marshal(changes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit changes: %w", err)
	}

	return data, nil
}

// deserializeAuditChanges converts JSON to AuditChanges
func deserializeAuditChanges(data []byte) (*interfaces.AuditChanges, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var changes interfaces.AuditChanges
	if err := json.Unmarshal(data, &changes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit changes: %w", err)
	}

	return &changes, nil
}

// convertNullString handles SQL NULL strings
func convertNullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// buildAuditFilterQuery constructs a WHERE clause from AuditFilter
func buildAuditFilterQuery(filter *interfaces.AuditFilter, args []interface{}) (string, []interface{}) {
	if filter == nil {
		return "", args
	}

	conditions := []string{}
	argCount := len(args)

	// Tenant ID filter
	if filter.TenantID != "" {
		argCount++
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argCount))
		args = append(args, filter.TenantID)
	}

	// Event types filter
	if len(filter.EventTypes) > 0 {
		argCount++
		eventTypes := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			eventTypes[i] = string(et)
		}
		conditions = append(conditions, fmt.Sprintf("event_type = ANY($%d)", argCount))
		args = append(args, eventTypes)
	}

	// Actions filter
	if len(filter.Actions) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("action = ANY($%d)", argCount))
		args = append(args, filter.Actions)
	}

	// User IDs filter
	if len(filter.UserIDs) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("user_id = ANY($%d)", argCount))
		args = append(args, filter.UserIDs)
	}

	// User types filter
	if len(filter.UserTypes) > 0 {
		argCount++
		userTypes := make([]string, len(filter.UserTypes))
		for i, ut := range filter.UserTypes {
			userTypes[i] = string(ut)
		}
		conditions = append(conditions, fmt.Sprintf("user_type = ANY($%d)", argCount))
		args = append(args, userTypes)
	}

	// Results filter
	if len(filter.Results) > 0 {
		argCount++
		results := make([]string, len(filter.Results))
		for i, r := range filter.Results {
			results[i] = string(r)
		}
		conditions = append(conditions, fmt.Sprintf("result = ANY($%d)", argCount))
		args = append(args, results)
	}

	// Severities filter
	if len(filter.Severities) > 0 {
		argCount++
		severities := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			severities[i] = string(s)
		}
		conditions = append(conditions, fmt.Sprintf("severity = ANY($%d)", argCount))
		args = append(args, severities)
	}

	// Resource types filter
	if len(filter.ResourceTypes) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("resource_type = ANY($%d)", argCount))
		args = append(args, filter.ResourceTypes)
	}

	// Resource IDs filter
	if len(filter.ResourceIDs) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("resource_id = ANY($%d)", argCount))
		args = append(args, filter.ResourceIDs)
	}

	// Time range filter
	if filter.TimeRange != nil {
		if filter.TimeRange.Start != nil {
			argCount++
			conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argCount))
			args = append(args, *filter.TimeRange.Start)
		}
		if filter.TimeRange.End != nil {
			argCount++
			conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argCount))
			args = append(args, *filter.TimeRange.End)
		}
	}

	// Tags filter (PostgreSQL array contains)
	if len(filter.Tags) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("tags @> $%d", argCount))
		args = append(args, filter.Tags)
	}

	// Search query filter (PostgreSQL full-text search on details JSONB)
	if filter.SearchQuery != "" {
		argCount++
		conditions = append(conditions, fmt.Sprintf("(details::text ILIKE $%d OR error_message ILIKE $%d OR resource_name ILIKE $%d)", argCount, argCount, argCount))
		args = append(args, "%"+filter.SearchQuery+"%")
	}

	if len(conditions) == 0 {
		return "", args
	}

	return "WHERE " + joinConditions(conditions, " AND "), args
}

// joinConditions joins string conditions with a separator
func joinConditions(conditions []string, separator string) string {
	if len(conditions) == 0 {
		return ""
	}
	if len(conditions) == 1 {
		return conditions[0]
	}

	result := conditions[0]
	for i := 1; i < len(conditions); i++ {
		result += separator + conditions[i]
	}
	return result
}

// buildOrderByClause constructs ORDER BY clause from filter
func buildOrderByClause(filter *interfaces.AuditFilter) string {
	if filter == nil || filter.SortBy == "" {
		return "ORDER BY timestamp DESC" // Default sort
	}

	var column string
	switch filter.SortBy {
	case "timestamp":
		column = "timestamp"
	case "severity":
		column = "severity"
	case "user_id":
		column = "user_id"
	case "event_type":
		column = "event_type"
	case "action":
		column = "action"
	default:
		column = "timestamp" // Default fallback
	}

	order := "DESC" // Default descending
	if filter.Order == "asc" {
		order = "ASC"
	}

	return fmt.Sprintf("ORDER BY %s %s", column, order)
}

// buildLimitOffsetClause constructs LIMIT and OFFSET clause from filter
func buildLimitOffsetClause(filter *interfaces.AuditFilter) string {
	if filter == nil {
		return ""
	}

	clause := ""
	if filter.Limit > 0 {
		clause += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		clause += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	return clause
}

// buildConfigFilterQuery constructs a WHERE clause from ConfigFilter
func buildConfigFilterQuery(filter *interfaces.ConfigFilter, args []interface{}) (string, []interface{}) {
	if filter == nil {
		return "", args
	}

	conditions := []string{}
	argCount := len(args)

	// Tenant ID filter
	if filter.TenantID != "" {
		argCount++
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argCount))
		args = append(args, filter.TenantID)
	}

	// Namespace filter
	if filter.Namespace != "" {
		argCount++
		conditions = append(conditions, fmt.Sprintf("namespace = $%d", argCount))
		args = append(args, filter.Namespace)
	}

	// Names filter
	if len(filter.Names) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("name = ANY($%d)", argCount))
		args = append(args, pq.Array(filter.Names))
	}

	// Tags filter
	if len(filter.Tags) > 0 {
		argCount++
		conditions = append(conditions, fmt.Sprintf("tags @> $%d", argCount))
		args = append(args, pq.Array(filter.Tags))
	}

	// Created by filter
	if filter.CreatedBy != "" {
		argCount++
		conditions = append(conditions, fmt.Sprintf("created_by = $%d", argCount))
		args = append(args, filter.CreatedBy)
	}

	// Updated by filter
	if filter.UpdatedBy != "" {
		argCount++
		conditions = append(conditions, fmt.Sprintf("updated_by = $%d", argCount))
		args = append(args, filter.UpdatedBy)
	}

	// Time-based filters
	if filter.CreatedAfter != nil {
		argCount++
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argCount))
		args = append(args, *filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		argCount++
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argCount))
		args = append(args, *filter.CreatedBefore)
	}

	if filter.UpdatedAfter != nil {
		argCount++
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argCount))
		args = append(args, *filter.UpdatedAfter)
	}

	if filter.UpdatedBefore != nil {
		argCount++
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argCount))
		args = append(args, *filter.UpdatedBefore)
	}

	if len(conditions) == 0 {
		return "", args
	}

	return "WHERE " + joinConditions(conditions, " AND "), args
}

// buildConfigOrderByClause constructs ORDER BY clause for config filter
func buildConfigOrderByClause(filter *interfaces.ConfigFilter) string {
	if filter == nil || filter.SortBy == "" {
		return "ORDER BY updated_at DESC" // Default sort
	}

	var column string
	switch filter.SortBy {
	case "created_at":
		column = "created_at"
	case "updated_at":
		column = "updated_at"
	case "name":
		column = "name"
	case "version":
		column = "version"
	case "namespace":
		column = "namespace"
	default:
		column = "updated_at" // Default fallback
	}

	order := "DESC" // Default descending
	if filter.Order == "asc" {
		order = "ASC"
	}

	return fmt.Sprintf("ORDER BY %s %s", column, order)
}

// buildConfigLimitOffsetClause constructs LIMIT and OFFSET clause for config filter
func buildConfigLimitOffsetClause(filter *interfaces.ConfigFilter) string {
	if filter == nil {
		return ""
	}

	clause := ""
	if filter.Limit > 0 {
		clause += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		clause += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	return clause
}
