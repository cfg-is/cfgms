// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite provides shared utilities for the SQLite storage provider
package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// nullString returns a sql.NullString that is NULL when the input is empty.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullTime returns a sql.NullString storing a time value as RFC3339, or NULL when zero.
func nullTime(t *time.Time) sql.NullString {
	if t == nil || t.IsZero() {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339Nano), Valid: true}
}

// parseNullTime parses a sql.NullString as an RFC3339 time pointer.
func parseNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, ns.String)
	if err != nil {
		return nil
	}
	return &t
}

// formatTime formats a time.Time to RFC3339Nano for SQLite storage.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// parseTime parses an RFC3339Nano string back to time.Time.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// marshalJSON serialises a value to a JSON string, returning "{}" for nil maps.
func marshalJSON(v interface{}) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(b), nil
}

// marshalJSONSlice serialises a string slice to a JSON array string.
func marshalJSONSlice(v []string) (string, error) {
	if v == nil {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON array: %w", err)
	}
	return string(b), nil
}

// unmarshalJSONSlice parses a JSON array string into a string slice.
func unmarshalJSONSlice(s string) ([]string, error) {
	if s == "" || s == "null" {
		return nil, nil
	}
	var result []string
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON array: %w", err)
	}
	return result, nil
}

// unmarshalJSONMap parses a JSON object string into a map.
func unmarshalJSONMap(s string) (map[string]interface{}, error) {
	if s == "" || s == "null" || s == "{}" {
		return make(map[string]interface{}), nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON map: %w", err)
	}
	return result, nil
}

// unmarshalJSONStringMap parses a JSON object string into a map[string]string.
func unmarshalJSONStringMap(s string) (map[string]string, error) {
	if s == "" || s == "null" || s == "{}" {
		return make(map[string]string), nil
	}
	var result map[string]string
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON string map: %w", err)
	}
	return result, nil
}

// placeholders returns a comma-separated list of n `?` placeholders for use in SQL IN clauses.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n*2-1)
	for i := 0; i < n; i++ {
		b[i*2] = '?'
		if i < n-1 {
			b[i*2+1] = ','
		}
	}
	return string(b)
}

// stringSliceToInterface converts []string to []interface{} for use as variadic SQL args.
func stringSliceToInterface(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
