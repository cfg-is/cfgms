// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestActiveDirectoryModule_New(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger)
	assert.NotNil(t, module)

	// Test with nil logger
	moduleWithNilLogger := New(nil)
	assert.NotNil(t, moduleWithNilLogger)
}

func TestActiveDirectoryModule_GetCapabilities(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	capabilities := module.GetCapabilities()
	assert.NotNil(t, capabilities)

	assert.Equal(t, true, capabilities["supports_read"])
	assert.Equal(t, false, capabilities["supports_write"], "no write operation is implemented")
	assert.Equal(t, false, capabilities["supports_monitor"])
	assert.Equal(t, true, capabilities["system_context"])
	assert.Equal(t, true, capabilities["credential_free"])

	objectTypes, ok := capabilities["object_types"].([]string)
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"user", "group"}, objectTypes)

	kinds, ok := capabilities["inventory_kinds"].([]string)
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{kindDirectoryUser, kindDirectoryGroup}, kinds)

	platforms, ok := capabilities["platforms"].([]string)
	assert.True(t, ok)
	assert.Contains(t, platforms, "windows")
}

func TestADModuleConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *ADModuleConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: &ADModuleConfig{
				OperationType:  "read",
				ObjectTypes:    []string{"user", "group"},
				PageSize:       100,
				RequestTimeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "missing operation type",
			config: &ADModuleConfig{
				ObjectTypes: []string{"user"},
			},
			expectError: true,
		},
		{
			name: "missing object types",
			config: &ADModuleConfig{
				OperationType: "read",
				ObjectTypes:   []string{},
			},
			expectError: true,
		},
		{
			name: "negative page size",
			config: &ADModuleConfig{
				OperationType: "read",
				ObjectTypes:   []string{"user"},
				PageSize:      -1,
			},
			expectError: true,
		},
		{
			name: "negative timeout",
			config: &ADModuleConfig{
				OperationType:  "read",
				ObjectTypes:    []string{"user"},
				RequestTimeout: -1 * time.Second,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestADModuleConfig_AsMap(t *testing.T) {
	config := &ADModuleConfig{
		OperationType:       "read",
		ObjectTypes:         []string{"user", "group"},
		SearchBase:          "DC=example,DC=com",
		PageSize:            100,
		RequestTimeout:      30 * time.Second,
		EnableDNACollection: true,
	}

	configMap := config.AsMap()
	assert.Equal(t, "read", configMap["operation_type"])
	assert.Equal(t, []string{"user", "group"}, configMap["object_types"])
	assert.Equal(t, "DC=example,DC=com", configMap["search_base"])
	assert.Equal(t, 100, configMap["page_size"])
	assert.Equal(t, 30*time.Second, configMap["request_timeout"])
	assert.Equal(t, true, configMap["enable_dna_collection"])
}

func TestADModuleConfig_YAML(t *testing.T) {
	config := &ADModuleConfig{
		OperationType:  "read",
		ObjectTypes:    []string{"user"},
		PageSize:       100,
		RequestTimeout: 30 * time.Second,
	}

	// Test ToYAML
	yamlData, err := config.ToYAML()
	assert.NoError(t, err)
	assert.NotEmpty(t, yamlData)

	// Test FromYAML
	newConfig := &ADModuleConfig{}
	err = newConfig.FromYAML(yamlData)
	assert.NoError(t, err)
	assert.Equal(t, config.OperationType, newConfig.OperationType)
	assert.Equal(t, config.ObjectTypes, newConfig.ObjectTypes)
	assert.Equal(t, config.PageSize, newConfig.PageSize)
	assert.Equal(t, config.RequestTimeout, newConfig.RequestTimeout)
}

func TestADSystemStatus_AsMap(t *testing.T) {
	now := time.Now()
	status := &ADSystemStatus{
		SystemContext:      true,
		Hostname:           "TEST-DC01",
		Domain:             "example.com",
		DomainController:   "dc01.example.com",
		ForestRoot:         "example.com",
		HealthStatus:       "healthy",
		RequestCount:       10,
		ErrorCount:         0,
		LastHealthCheck:    now,
		DNACollectionCount: 5,
		LastDNACollection:  now,
	}

	statusMap := status.AsMap()
	assert.Equal(t, true, statusMap["system_context"])
	assert.Equal(t, "TEST-DC01", statusMap["hostname"])
	assert.Equal(t, "example.com", statusMap["domain"])
	assert.Equal(t, "dc01.example.com", statusMap["domain_controller"])
	assert.Equal(t, "example.com", statusMap["forest_root"])
	assert.Equal(t, "healthy", statusMap["health_status"])
	assert.Equal(t, int64(10), statusMap["request_count"])
	assert.Equal(t, int64(0), statusMap["error_count"])
	assert.Equal(t, now, statusMap["last_health_check"])
	assert.Equal(t, int64(5), statusMap["dna_collection_count"])
	assert.Equal(t, now, statusMap["last_dna_collection"])
}

func TestActiveDirectoryModule_Set_InvalidConfig(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	invalidConfig := &ADModuleConfig{
		// Missing required fields
	}

	ctx := context.Background()
	err := module.Set(ctx, "config", invalidConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AD configuration")
}

func TestActiveDirectoryModule_Get_InvalidResourceID(t *testing.T) {
	module := New(logging.NewNoopLogger()).(*activeDirectoryModule)
	ctx := context.Background()

	for _, id := range []string{"", "query:user:Administrator", "list:user", "dna_collection", "invalid_operation"} {
		_, err := module.Get(ctx, id)
		assert.Error(t, err, "Get(%q)", id)
		assert.Contains(t, err.Error(), "unsupported operation")
	}
}

func TestActiveDirectoryModule_Test_NotConfigured(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()
	config := &ADModuleConfig{
		OperationType: "read",
		ObjectTypes:   []string{"user"},
	}

	// Test when module is not configured
	matches, err := module.Test(ctx, "test", config)
	assert.Error(t, err)
	assert.False(t, matches)
	assert.Contains(t, err.Error(), "module not configured")
}

func TestActiveDirectoryModule_UpdateStats(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	// Test request count update
	module.updateStats(true)
	module.stats.RLock()
	assert.Equal(t, int64(1), module.stats.requestCount)
	assert.Equal(t, int64(0), module.stats.errorCount)
	assert.False(t, module.stats.lastRequest.IsZero())
	module.stats.RUnlock()

	// Test error count update
	module.updateStats(false)
	module.stats.RLock()
	assert.Equal(t, int64(1), module.stats.requestCount)
	assert.Equal(t, int64(1), module.stats.errorCount)
	module.stats.RUnlock()
}

func TestActiveDirectoryModule_GetHostname(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	hostname := module.getHostname()
	assert.NotEmpty(t, hostname)
	// On non-Windows systems this might return "unknown" but should not panic
}

// ---------------------------------------------------------------------------
// Test script runner
// ---------------------------------------------------------------------------

// fakeRunner is a test implementation of scriptRunner. It decodes the request
// like the read script does and serves records from serve, encoding each as
// one NDJSON line. Large data sets are generated on the fly.
type fakeRunner struct {
	serve    func(op string, emit func(rec interface{}) error) error
	requests []readRequest
}

func (f *fakeRunner) Run(_ context.Context, request []byte, onLine func(line []byte) error) error {
	var req readRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return err
	}
	f.requests = append(f.requests, req)
	return f.serve(req.Operation, func(rec interface{}) error {
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return onLine(line)
	})
}

// guid returns a deterministic canonical objectGUID for prefix and n.
func guid(prefix byte, n int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%c%011x", n, prefix, n)
}

func userRecord(n int, memberOf []string) map[string]interface{} {
	return map[string]interface{}{
		"type":                "user",
		"id":                  guid('a', n),
		"sam_account_name":    fmt.Sprintf("user%d", n),
		"user_principal_name": fmt.Sprintf("user%d@acme-corp.example", n),
		"display_name":        fmt.Sprintf("User %d", n),
		"mail":                fmt.Sprintf("user%d@acme-corp.example", n),
		"enabled":             true,
		"distinguished_name":  fmt.Sprintf("CN=User %d,CN=Users,DC=acme-corp,DC=example", n),
		"object_sid":          fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+n),
		"when_created":        "2026-01-02T03:04:05Z",
		"directory_domain":    "acme-corp.example",
		"member_of":           memberOf,
		"member_of_truncated": false,
	}
}

func groupRecord(n int, memberOf []string, others []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type":                    "group",
		"id":                      guid('b', n),
		"sam_account_name":        fmt.Sprintf("group%d", n),
		"display_name":            fmt.Sprintf("Group %d", n),
		"distinguished_name":      fmt.Sprintf("CN=Group %d,CN=Users,DC=acme-corp,DC=example", n),
		"group_scope":             "Global",
		"group_category":          "Security",
		"directory_domain":        "acme-corp.example",
		"member_of":               memberOf,
		"member_of_truncated":     false,
		"other_members":           others,
		"other_members_truncated": false,
	}
}

func newFakeModule(serve func(op string, emit func(rec interface{}) error) error) (*activeDirectoryModule, *fakeRunner) {
	r := &fakeRunner{serve: serve}
	return newWithRunner(logging.NewNoopLogger(), r), r
}

// inventoryObjects returns the per-object list from a Get result.
func inventoryObjects(t *testing.T, state modules.ConfigState) []map[string]interface{} {
	t.Helper()
	raw, ok := state.AsMap()[modules.PerObjectKey].([]interface{})
	require.True(t, ok, "Get must return the object list under %s", modules.PerObjectKey)
	out := make([]map[string]interface{}, 0, len(raw))
	for _, e := range raw {
		obj, ok := e.(map[string]interface{})
		require.True(t, ok)
		out = append(out, obj)
	}
	return out
}

func statusServe(op string, emit func(rec interface{}) error) error {
	if op != "status" {
		return fmt.Errorf("unexpected operation %q", op)
	}
	return emit(map[string]interface{}{
		"type": "status", "domain": "acme-corp.example", "domain_controller": "dc01.acme-corp.example",
		"forest_root": "acme-corp.example", "netbios_name": "ACME",
	})
}

// ---------------------------------------------------------------------------
// Per-object inventory (#5556)
// ---------------------------------------------------------------------------

func TestGet_DirectoryUser_EmitsPerObjectState(t *testing.T) {
	g1, g2 := guid('b', 1), guid('b', 2)
	m, r := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		require.Equal(t, "users", op)
		if err := emit(userRecord(2, nil)); err != nil {
			return err
		}
		return emit(userRecord(1, []string{g2, g1, g2}))
	})

	state, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	require.Len(t, r.requests, 1)
	assert.Equal(t, readRequest{Operation: "users", PageSize: defaultPageSize}, r.requests[0])

	objs := inventoryObjects(t, state)
	require.Len(t, objs, 2)
	assert.Equal(t, guid('a', 1), objs[0]["id"], "objects are sorted by id")
	assert.Equal(t, guid('a', 2), objs[1]["id"])

	attrs, ok := objs[0]["attrs"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, map[string]interface{}{
		"sam_account_name":    "user1",
		"user_principal_name": "user1@acme-corp.example",
		"display_name":        "User 1",
		"mail":                "user1@acme-corp.example",
		"enabled":             true,
		"distinguished_name":  "CN=User 1,CN=Users,DC=acme-corp,DC=example",
		"object_sid":          "S-1-5-21-1-2-3-1001",
		"when_created":        "2026-01-02T03:04:05Z",
		"directory_domain":    "acme-corp.example",
		"managed":             false,
		"member_of":           []string{g1, g2},
	}, attrs, "member_of is sorted and deduplicated; no volatile fields")
}

func TestGet_DirectoryGroup_EmitsPerObjectState(t *testing.T) {
	parent := guid('b', 9)
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		require.Equal(t, "groups", op)
		return emit(groupRecord(1, []string{parent}, nil))
	})
	state, err := m.Get(context.Background(), kindDirectoryGroup)
	require.NoError(t, err)
	objs := inventoryObjects(t, state)
	require.Len(t, objs, 1)
	attrs := objs[0]["attrs"].(map[string]interface{})
	assert.Equal(t, "Global", attrs["group_scope"])
	assert.Equal(t, "Security", attrs["group_category"])
	assert.Equal(t, false, attrs["managed"])
	assert.Equal(t, []string{parent}, attrs["member_of"])
	assert.Equal(t, []interface{}{}, attrs["other_members"])
}

func TestGetUsers_StableHashAcrossRuns(t *testing.T) {
	// Each run serves the same directory in a different order; the state must
	// not depend on read order.
	run := 0
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		run++
		order := []int{1, 2, 3}
		if run%2 == 0 {
			order = []int{3, 1, 2}
		}
		for _, n := range order {
			groups := []string{guid('b', 3), guid('b', 1), guid('b', 2)}
			if run%2 == 0 {
				groups = []string{guid('b', 2), guid('b', 3), guid('b', 1)}
			}
			if err := emit(userRecord(n, groups)); err != nil {
				return err
			}
		}
		return nil
	})
	conformance.AssertDeterministicGet(t, m, kindDirectoryUser)
}

func TestGet_ReservedIDsAreInventory_DeclaredReservedNameRejected(t *testing.T) {
	m, r := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		switch op {
		case "users":
			return emit(userRecord(1, nil))
		case "groups":
			return emit(groupRecord(1, nil, nil))
		}
		return statusServe(op, emit)
	})

	for _, id := range []string{kindDirectoryUser, kindDirectoryGroup} {
		state, err := m.Get(context.Background(), id)
		require.NoError(t, err, "Get(%q) is inventory", id)
		assert.Len(t, inventoryObjects(t, state), 1)

		cfg := &ADModuleConfig{OperationType: "read", ObjectTypes: []string{"user"}}
		err = m.Set(context.Background(), id, cfg)
		require.Error(t, err, "a declared resource named %q must be rejected", id)
		assert.Contains(t, err.Error(), "reserved")
		assert.Error(t, validateDeclaredResourceID(id))
	}
	assert.NoError(t, validateDeclaredResourceID("config"))
	assert.Len(t, r.requests, 2, "a rejected Set never reads the directory")
}

func TestGet_UserIn300Groups_ListsAll300(t *testing.T) {
	var groups []string
	for i := 300; i >= 1; i-- {
		groups = append(groups, guid('b', i))
	}
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		return emit(userRecord(1, groups))
	})

	state, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	attrs := inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	memberOf := attrs["member_of"].([]string)
	require.Len(t, memberOf, 300)
	assert.True(t, sort.StringsAreSorted(memberOf))
	assert.NotContains(t, attrs, "member_of_truncated")
	conformance.AssertDeterministicGet(t, m, kindDirectoryUser)
}

func TestGet_GroupWith60000Members_Enumerates60000UserObjectsEachListingTheGroup(t *testing.T) {
	const members = 60000
	big := guid('b', 1)
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		// Served in pages of defaultPageSize, the way the script pages AD.
		for page := 0; page*defaultPageSize < members; page++ {
			for i := page * defaultPageSize; i < (page+1)*defaultPageSize && i < members; i++ {
				if err := emit(userRecord(i, []string{big})); err != nil {
					return err
				}
			}
		}
		return nil
	})

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	state, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	objs := inventoryObjects(t, state)
	require.Len(t, objs, members)
	for _, obj := range objs {
		attrs := obj["attrs"].(map[string]interface{})
		require.Equal(t, []string{big}, attrs["member_of"])
	}

	// The stated bound: one Get holds up to maxInventoryObjects objects of
	// about 1 KB each in memory once.
	const statedBound = maxInventoryObjects * 1024
	var growth uint64
	if after.HeapAlloc > before.HeapAlloc {
		growth = after.HeapAlloc - before.HeapAlloc
	}
	assert.Less(t, growth, uint64(statedBound),
		"retained heap for %d objects must stay within the %d-object bound", members, maxInventoryObjects)
	runtime.KeepAlive(state)
}

func TestGet_MemberOfOverBoundIsFlaggedNotSilent(t *testing.T) {
	var groups []string
	for i := maxListEntries + 25; i >= 1; i-- {
		groups = append(groups, guid('b', i))
	}
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		return emit(userRecord(1, groups))
	})

	state, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	attrs := inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	memberOf := attrs["member_of"].([]string)
	require.Len(t, memberOf, maxListEntries)
	assert.Equal(t, guid('b', 1), memberOf[0], "the first entries in sorted order are kept")
	assert.Equal(t, true, attrs["member_of_truncated"], "truncation is flagged")

	// A truncation the script already made is carried through as well.
	rec := userRecord(2, []string{guid('b', 1)})
	rec["member_of_truncated"] = true
	m2, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error { return emit(rec) })
	state, err = m2.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	attrs = inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	assert.Equal(t, true, attrs["member_of_truncated"])
}

func TestGet_NoEntityGraphEdgesKeyEmitted(t *testing.T) {
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		if op == "users" {
			return emit(userRecord(1, []string{guid('b', 1)}))
		}
		return emit(groupRecord(1, []string{guid('b', 2)}, nil))
	})
	for _, id := range []string{kindDirectoryUser, kindDirectoryGroup} {
		state, err := m.Get(context.Background(), id)
		require.NoError(t, err)
		enc, err := json.Marshal(state.AsMap())
		require.NoError(t, err)
		assert.NotContains(t, string(enc), "__entitygraph_edges")
		assert.Equal(t, []string{modules.PerObjectKey}, mapKeys(state.AsMap()))
	}
}

func TestGet_GroupWithComputerContactAndFSPMembers_ListsThemWithTypeIDName(t *testing.T) {
	others := []map[string]interface{}{
		{"type": "foreign_security_principal", "id": guid('c', 3), "name": "S-1-5-21-9-9-9-500"},
		{"type": "computer", "id": guid('c', 1), "name": "WS01"},
		{"type": "contact", "id": guid('c', 2), "name": "Vendor Contact"},
		{"type": "msDS-Unknown", "id": guid('c', 4), "name": "Odd Object"},
		{"type": "computer", "id": guid('c', 1), "name": "WS01"},
	}
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		return emit(groupRecord(1, nil, others))
	})

	state, err := m.Get(context.Background(), kindDirectoryGroup)
	require.NoError(t, err)
	attrs := inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	assert.Equal(t, []interface{}{
		map[string]interface{}{"type": "computer", "id": guid('c', 1), "name": "WS01"},
		map[string]interface{}{"type": "contact", "id": guid('c', 2), "name": "Vendor Contact"},
		map[string]interface{}{"type": "foreign_security_principal", "id": guid('c', 3), "name": "S-1-5-21-9-9-9-500"},
		map[string]interface{}{"type": "other", "id": guid('c', 4), "name": "Odd Object"},
	}, attrs["other_members"], "sorted by (type, id), deduplicated, unknown types reported as other")
	assert.NotContains(t, attrs, "other_members_truncated")

	// Over the bound: flagged, not silent.
	var many []map[string]interface{}
	for i := 0; i < maxListEntries+3; i++ {
		many = append(many, map[string]interface{}{"type": "computer", "id": guid('c', i), "name": "PC"})
	}
	m2, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		return emit(groupRecord(1, nil, many))
	})
	state, err = m2.Get(context.Background(), kindDirectoryGroup)
	require.NoError(t, err)
	attrs = inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	assert.Len(t, attrs["other_members"], maxListEntries)
	assert.Equal(t, true, attrs["other_members_truncated"])
}

func TestGet_ScriptErrorRecordFailsTheRead(t *testing.T) {
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		return emit(map[string]interface{}{"type": "error", "code": "ad_module_unavailable", "detail": "System.IO.FileNotFoundException"})
	})
	_, err := m.Get(context.Background(), kindDirectoryUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ad_module_unavailable")
}

func TestGet_InvalidAndDuplicateObjectsSkipped(t *testing.T) {
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		bad := userRecord(1, nil)
		bad["id"] = "not-a-guid"
		for _, rec := range []map[string]interface{}{bad, userRecord(2, nil), userRecord(2, nil)} {
			if err := emit(rec); err != nil {
				return err
			}
		}
		return nil
	})
	state, err := m.Get(context.Background(), kindDirectoryUser)
	require.NoError(t, err)
	objs := inventoryObjects(t, state)
	require.Len(t, objs, 1)
	assert.Equal(t, guid('a', 2), objs[0]["id"])
}

func TestGet_SingleValueListsDecode(t *testing.T) {
	// Windows PowerShell can render a one-element array as a scalar.
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error {
		rec := groupRecord(1, nil, nil)
		rec["member_of"] = guid('b', 7)
		rec["other_members"] = map[string]interface{}{"type": "contact", "id": guid('c', 1), "name": "C"}
		return emit(rec)
	})
	state, err := m.Get(context.Background(), kindDirectoryGroup)
	require.NoError(t, err)
	attrs := inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	assert.Equal(t, []string{guid('b', 7)}, attrs["member_of"])
	assert.Len(t, attrs["other_members"], 1)
}

func TestGet_Status_UsesStatusRead(t *testing.T) {
	m, r := newFakeModule(statusServe)
	state, err := m.Get(context.Background(), "status")
	require.NoError(t, err)
	status := state.(*ADSystemStatus)
	assert.Equal(t, "healthy", status.HealthStatus)
	assert.Equal(t, "acme-corp.example", status.Domain)
	assert.Equal(t, "dc01.acme-corp.example", status.DomainController)
	require.Len(t, r.requests, 1)
	assert.Equal(t, "status", r.requests[0].Operation)
}

func TestActiveDirectoryModule_Set_ValidConfig(t *testing.T) {
	m, r := newFakeModule(statusServe)
	config := &ADModuleConfig{
		OperationType:       "read",
		ObjectTypes:         []string{"user", "group"},
		PageSize:            50,
		RequestTimeout:      15 * time.Second,
		EnableDNACollection: true,
	}
	require.NoError(t, m.Set(context.Background(), "config", config))

	m.configMux.RLock()
	stored := m.config
	m.configMux.RUnlock()
	assert.Equal(t, 50, stored.PageSize)
	assert.Equal(t, config.ObjectTypes, stored.ObjectTypes)

	// The configured page size travels to the script as a typed value.
	_, err := m.Get(context.Background(), "status")
	require.NoError(t, err)
	assert.Equal(t, 50, r.requests[len(r.requests)-1].PageSize)

	ok, err := m.Test(context.Background(), "config", config)
	require.NoError(t, err)
	assert.True(t, ok)
}

// ---------------------------------------------------------------------------
// Manifest (#5556)
// ---------------------------------------------------------------------------

func TestManifest_ParsesOwnsPerObjectAndObserveWhen(t *testing.T) {
	meta, err := modules.LoadModuleMetadata("module.yaml")
	require.NoError(t, err)

	assert.ElementsMatch(t, []modules.OwnershipDeclaration{
		{Kind: kindDirectoryUser, PerObject: true},
		{Kind: kindDirectoryGroup, PerObject: true},
	}, meta.Owns)
	assert.Equal(t, []modules.ObservePredicate{{Fact: "ad_pdc_emulator", Equals: "true"}}, meta.ObserveWhen)

	require.NotNil(t, meta.BehavioralEnvelope)
	assert.Equal(t, []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}, meta.BehavioralEnvelope.ShellsOutTo)
	assert.NotEmpty(t, meta.BehavioralEnvelope.WritesPaths)
	assert.NotEmpty(t, meta.BehavioralEnvelope.ReadsPaths)
	assert.NotEmpty(t, meta.BehavioralEnvelope.LolbinUsageJustification)
}

func TestModuleYAML_ListsNoUnimplementedWriteOperations(t *testing.T) {
	data, err := os.ReadFile("module.yaml")
	require.NoError(t, err)
	var manifest struct {
		Permissions struct {
			Windows []string `yaml:"windows"`
		} `yaml:"permissions"`
		SupportedOperations map[string][]string `yaml:"supported_operations"`
		Security            struct {
			AuditOperations []string `yaml:"audit_operations"`
		} `yaml:"security"`
	}
	require.NoError(t, yaml.Unmarshal(data, &manifest))

	assert.Empty(t, manifest.SupportedOperations["write"], "no write operation is implemented")
	assert.Empty(t, manifest.Security.AuditOperations, "no write operation is implemented")
	assert.NotContains(t, manifest.Permissions.Windows, "Act as part of operating system")

	// Every listed read operation is served by Get.
	m, _ := newFakeModule(statusServe)
	for _, op := range manifest.SupportedOperations["read"] {
		_, err := m.Get(context.Background(), op)
		assert.NoError(t, err, "read operation %q is listed but not implemented", op)
	}
	for _, removed := range []string{"query", "list", "dna_collection"} {
		assert.NotContains(t, manifest.SupportedOperations["read"], removed)
		_, err := m.Get(context.Background(), removed)
		assert.Error(t, err, "removed operation %q must not be served", removed)
	}
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestGet_ScriptFlaggedCappedMembershipIsCarried(t *testing.T) {
	// The script flags lists that may have been capped by the directory
	// service's per-object membership limit even when they are short; the
	// module must keep that flag rather than report the list as complete.
	rec := groupRecord(1, []string{guid('b', 2)}, []map[string]interface{}{
		{"type": "computer", "id": guid('c', 1), "name": "WS01"},
	})
	rec["member_of_truncated"] = true
	rec["other_members_truncated"] = true
	m, _ := newFakeModule(func(op string, emit func(rec interface{}) error) error { return emit(rec) })

	state, err := m.Get(context.Background(), kindDirectoryGroup)
	require.NoError(t, err)
	attrs := inventoryObjects(t, state)[0]["attrs"].(map[string]interface{})
	assert.Equal(t, true, attrs["member_of_truncated"])
	assert.Equal(t, true, attrs["other_members_truncated"])
	assert.Len(t, attrs["other_members"], 1)
}
