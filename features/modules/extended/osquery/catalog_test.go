// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery

import (
	"strings"
	"testing"
)

// TestCatalogRegistry_AllEntriesHaveIDs verifies that every catalog entry's
// registered key matches its declared ID field. A mismatch would cause lookups
// to find the wrong entry or BuildQuery to log the wrong ID.
func TestCatalogRegistry_AllEntriesHaveIDs(t *testing.T) {
	for key, entry := range catalogRegistry {
		if entry.ID != key {
			t.Errorf("catalog entry %q has mismatched ID field %q", key, entry.ID)
		}
	}
}

// TestCatalogRegistry_QueriesNonEmpty verifies that no catalog entry has an
// empty query template (which would silently execute a no-op against osquery).
func TestCatalogRegistry_QueriesNonEmpty(t *testing.T) {
	for key, entry := range catalogRegistry {
		if strings.TrimSpace(entry.query) == "" {
			t.Errorf("catalog entry %q has an empty query template", key)
		}
	}
}

// TestLookupCatalogEntry_KnownID returns the entry for a known catalog ID.
func TestLookupCatalogEntry_KnownID(t *testing.T) {
	entry, err := LookupCatalogEntry("host_info")
	if err != nil {
		t.Fatalf("LookupCatalogEntry(\"host_info\") returned error: %v", err)
	}
	if entry == nil {
		t.Fatal("LookupCatalogEntry returned nil entry for known ID")
	}
	if entry.ID != "host_info" {
		t.Errorf("entry.ID = %q, want %q", entry.ID, "host_info")
	}
}

// TestLookupCatalogEntry_UnknownID returns an error for an unrecognised catalog ID.
func TestLookupCatalogEntry_UnknownID(t *testing.T) {
	_, err := LookupCatalogEntry("not-a-real-catalog-id")
	if err == nil {
		t.Fatal("LookupCatalogEntry must return an error for an unrecognised catalog ID")
	}
	if !strings.Contains(err.Error(), "unknown query id") {
		t.Errorf("error %q does not identify the unknown-ID rejection", err.Error())
	}
}

// TestValidateParams_ValidEnum verifies that a declared enum parameter with an
// allowed value passes validation.
func TestValidateParams_ValidEnum(t *testing.T) {
	entry, err := LookupCatalogEntry("process_list")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}
	if err := ValidateParams(entry, map[string]string{"name_prefix": "cfgms"}); err != nil {
		t.Errorf("valid enum value must pass: %v", err)
	}
}

// TestValidateParams_InvalidEnum rejects a value not in the enum's allowed set.
func TestValidateParams_InvalidEnum(t *testing.T) {
	entry, err := LookupCatalogEntry("process_list")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}
	err = ValidateParams(entry, map[string]string{"name_prefix": "bash"})
	if err == nil {
		t.Fatal("invalid enum value must be rejected")
	}
	if !strings.Contains(err.Error(), "not in the allowed set") {
		t.Errorf("error %q does not identify the enum-rejection branch", err.Error())
	}
}

// TestValidateParams_SQLMetacharactersRejectedForCharset rejects each of the
// four SQL metacharacter patterns for a charset-typed parameter.
func TestValidateParams_SQLMetacharactersRejectedForCharset(t *testing.T) {
	entry, err := LookupCatalogEntry("file_info")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}

	tests := []struct {
		name  string
		value string
	}{
		{"single_quote", "' OR 1=1"},
		{"double_dash", "/etc/passwd--"},
		{"semicolon", "/etc/passwd;id"},
		{"UNION", "/etc/passwd UNION SELECT 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(entry, map[string]string{"path": tt.value})
			if err == nil {
				t.Fatalf("SQL metacharacter %q in charset param must be rejected", tt.value)
			}
			if !strings.Contains(err.Error(), "SQL metacharacter") {
				t.Errorf("error %q does not identify the SQL-metacharacter rejection", err.Error())
			}
		})
	}
}

// TestValidateParams_MissingRequired rejects a request that omits a parameter
// declared as required in the catalog entry's schema.
func TestValidateParams_MissingRequired(t *testing.T) {
	entry, err := LookupCatalogEntry("file_info")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}
	err = ValidateParams(entry, map[string]string{}) // "path" is required
	if err == nil {
		t.Fatal("missing required parameter must be rejected")
	}
	if !strings.Contains(err.Error(), "required parameter") {
		t.Errorf("error %q does not identify the missing-parameter rejection", err.Error())
	}
}

// TestValidateParams_UndeclaredParam rejects a parameter name not in the
// catalog entry's schema.
func TestValidateParams_UndeclaredParam(t *testing.T) {
	entry, err := LookupCatalogEntry("host_info")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}
	err = ValidateParams(entry, map[string]string{"injected": "value"})
	if err == nil {
		t.Fatal("undeclared parameter must be rejected")
	}
	if !strings.Contains(err.Error(), "not declared") {
		t.Errorf("error %q does not identify the undeclared-param rejection", err.Error())
	}
}

// TestValidateParams_ValidCharset verifies a safe absolute path passes the
// charset validator.
func TestValidateParams_ValidCharset(t *testing.T) {
	entry, err := LookupCatalogEntry("file_info")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}
	if err := ValidateParams(entry, map[string]string{"path": "/etc/os-release"}); err != nil {
		t.Errorf("safe absolute path must pass charset validation: %v", err)
	}
}

// TestBuildQuery_SubstitutesParams verifies that BuildQuery replaces
// {{param_name}} placeholders with provided values.
func TestBuildQuery_SubstitutesParams(t *testing.T) {
	entry := &CatalogEntry{
		ID:    "test",
		query: "SELECT * FROM t WHERE name = '{{name}}' AND x = '{{x}}'",
	}
	got := entry.BuildQuery(map[string]string{"name": "foo", "x": "bar"})
	want := "SELECT * FROM t WHERE name = 'foo' AND x = 'bar'"
	if got != want {
		t.Errorf("BuildQuery = %q, want %q", got, want)
	}
}

// TestBuildQuery_NoParams verifies that BuildQuery handles entries with no
// parameters by returning the query template unchanged.
func TestBuildQuery_NoParams(t *testing.T) {
	entry, err := LookupCatalogEntry("host_info")
	if err != nil {
		t.Fatalf("LookupCatalogEntry: %v", err)
	}
	q := entry.BuildQuery(nil)
	if q == "" {
		t.Error("BuildQuery must return a non-empty query for host_info (no params)")
	}
	if strings.Contains(q, "{{") {
		t.Error("BuildQuery must not leave unreplaced placeholders for a no-param entry")
	}
}

// TestParamSchema_Enum_ValidValue passes for an allowed literal.
func TestParamSchema_Enum_ValidValue(t *testing.T) {
	s := ParamSchema{
		Type:          ParamTypeEnum,
		AllowedValues: []string{"a", "b", "c"},
	}
	if err := s.Validate("p", "b"); err != nil {
		t.Errorf("Validate allowed enum value: %v", err)
	}
}

// TestParamSchema_Enum_InvalidValue rejects a value not in the allowed set.
func TestParamSchema_Enum_InvalidValue(t *testing.T) {
	s := ParamSchema{
		Type:          ParamTypeEnum,
		AllowedValues: []string{"a", "b"},
	}
	if err := s.Validate("p", "c"); err == nil {
		t.Error("Validate must reject a value not in the allowed enum set")
	}
}

// TestParamSchema_Charset_SQLInjection rejects values containing each of the
// four SQL metacharacter patterns defined in sqlMetacharacters.
func TestParamSchema_Charset_SQLInjection(t *testing.T) {
	s := ParamSchema{Type: ParamTypeCharset}

	for _, bad := range []string{"'", "--", ";", "UNION"} {
		if err := s.Validate("p", bad); err == nil {
			t.Errorf("Validate must reject SQL metacharacter %q in charset param", bad)
		}
	}
}

// TestParamSchema_Charset_CaseInsensitiveSQLMeta verifies that UNION is rejected
// regardless of case (union, Union, UNION).
func TestParamSchema_Charset_CaseInsensitiveSQLMeta(t *testing.T) {
	s := ParamSchema{Type: ParamTypeCharset}
	for _, variant := range []string{"union", "Union", "UNION"} {
		if err := s.Validate("p", variant); err == nil {
			t.Errorf("Validate must reject case-variant SQL keyword %q", variant)
		}
	}
}
