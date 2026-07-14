// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// inMemoryScriptRepo is a simple in-memory ScriptRepository for tests.
// It stores scripts by "id@version" key and returns ErrNotFound for missing keys.
type inMemoryScriptRepo struct {
	scripts map[string]*VersionedScript
}

func newInMemoryScriptRepo(scripts ...*VersionedScript) *inMemoryScriptRepo {
	r := &inMemoryScriptRepo{scripts: make(map[string]*VersionedScript)}
	for _, s := range scripts {
		key := s.Metadata.ID + "@" + s.Metadata.Version.String()
		r.scripts[key] = s
	}
	return r
}

func (r *inMemoryScriptRepo) Get(id, version string) (*VersionedScript, error) {
	key := id + "@" + version
	if s, ok := r.scripts[key]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("script %s@%s not found", id, version)
}

func (r *inMemoryScriptRepo) Create(s *VersionedScript) error {
	key := s.Metadata.ID + "@" + s.Metadata.Version.String()
	r.scripts[key] = s
	return nil
}

func (r *inMemoryScriptRepo) List(_ *ScriptFilter) ([]*ScriptMetadata, error) {
	result := make([]*ScriptMetadata, 0, len(r.scripts))
	for _, s := range r.scripts {
		result = append(result, s.Metadata)
	}
	return result, nil
}

func (r *inMemoryScriptRepo) Update(s *VersionedScript) error {
	key := s.Metadata.ID + "@" + s.Metadata.Version.String()
	r.scripts[key] = s
	return nil
}

func (r *inMemoryScriptRepo) Delete(id, version string) error {
	key := id + "@" + version
	delete(r.scripts, key)
	return nil
}

func (r *inMemoryScriptRepo) ListVersions(id string) ([]*Version, error) {
	var versions []*Version
	for _, s := range r.scripts {
		if s.Metadata.ID == id {
			v := *s.Metadata.Version
			versions = append(versions, &v)
		}
	}
	return versions, nil
}

func (r *inMemoryScriptRepo) GetLatestVersion(id string) (*Version, error) {
	var latest *Version
	for _, s := range r.scripts {
		if s.Metadata.ID == id {
			if latest == nil || s.Metadata.Version.Compare(latest) > 0 {
				v := *s.Metadata.Version
				latest = &v
			}
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no versions found for script %s", id)
	}
	return latest, nil
}

func (r *inMemoryScriptRepo) Rollback(id, version string) error { return nil }

// makeTestVersionedScript builds a minimal VersionedScript for test use.
func makeTestVersionedScript(id, version string) *VersionedScript {
	v, _ := ParseVersion(version)
	return &VersionedScript{
		Metadata: &ScriptMetadata{
			ID:       id,
			Name:     id,
			Version:  v,
			Shell:    getTestShell(),
			Platform: []string{"linux", "darwin", "windows"},
		},
		Content: getTestScript(),
		Hash:    "abc123",
	}
}

// testConfigState mirrors the executor's unexported genericConfigState so tests
// can exercise CompareStates against the real comparator without importing the
// unexported type.
type testConfigState struct {
	data map[string]interface{}
}

func (t *testConfigState) AsMap() map[string]interface{} { return t.data }
func (t *testConfigState) ToYAML() ([]byte, error)       { return yaml.Marshal(t.data) }
func (t *testConfigState) FromYAML(data []byte) error    { return yaml.Unmarshal(data, &t.data) }
func (t *testConfigState) Validate() error               { return nil }
func (t *testConfigState) GetManagedFields() []string {
	excluded := map[string]bool{"path": true, "name": true, "transport": true, "tenant_id": true}
	fields := make([]string, 0, len(t.data))
	for k := range t.data {
		if !excluded[k] {
			fields = append(fields, k)
		}
	}
	return fields
}

// getFailingScript returns a script that exits non-zero on the current platform.
func getFailingScript() string {
	switch runtime.GOOS {
	case "windows":
		return "exit /B 1"
	default:
		return "exit 1"
	}
}

// getTestShell returns an appropriate shell for the current platform
func getTestShell() ShellType {
	switch runtime.GOOS {
	case "windows":
		return ShellCmd
	default:
		return ShellBash
	}
}

// getTestScript returns a simple test script for the current platform
func getTestScript() string {
	switch runtime.GOOS {
	case "windows":
		return "echo Hello World"
	default:
		return "echo 'Hello World'"
	}
}

func TestScriptModule_New(t *testing.T) {
	module := New()
	if module == nil {
		t.Fatal("New() returned nil")
	}

	// Module is already of type modules.Module, no need to verify
}

func TestScriptConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  ScriptConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   getTestShell(),
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty content",
			config: ScriptConfig{
				Content: "",
				Shell:   getTestShell(),
			},
			wantErr: true,
		},
		{
			name: "empty shell",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   "",
			},
			wantErr: true,
		},
		{
			name: "unsupported shell on platform",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   ShellType("unsupported"),
			},
			wantErr: true,
		},
		{
			name: "negative timeout",
			config: ScriptConfig{
				Content: getTestScript(),
				Shell:   getTestShell(),
				Timeout: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "required signature missing",
			config: ScriptConfig{
				Content:       getTestScript(),
				Shell:         getTestShell(),
				SigningPolicy: SigningPolicyRequired,
				Signature:     nil,
			},
			wantErr: true,
		},
		{
			name: "invalid signing policy",
			config: ScriptConfig{
				Content:       getTestScript(),
				Shell:         getTestShell(),
				SigningPolicy: SigningPolicy("invalid"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ScriptConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScriptConfig_DefaultValues(t *testing.T) {
	config := ScriptConfig{
		Content: getTestScript(),
		Shell:   getTestShell(),
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Check default timeout is set
	if config.Timeout != 5*time.Minute {
		t.Errorf("Expected default timeout of 5 minutes, got %v", config.Timeout)
	}

	// Check default signing policy is set
	if config.SigningPolicy != SigningPolicyNone {
		t.Errorf("Expected default signing policy 'none', got %v", config.SigningPolicy)
	}
}

func TestScriptConfig_AsMap(t *testing.T) {
	config := ScriptConfig{
		Content:     getTestScript(),
		Shell:       getTestShell(),
		Timeout:     30 * time.Second,
		Environment: map[string]string{"TEST": "value"},
		WorkingDir:  "/tmp",
		Description: "Test script",
	}

	asMap := config.AsMap()

	// Check required fields
	if asMap["content"] != config.Content {
		t.Errorf("Expected content %v, got %v", config.Content, asMap["content"])
	}
	if asMap["shell"] != string(config.Shell) {
		t.Errorf("Expected shell %v, got %v", config.Shell, asMap["shell"])
	}
	if asMap["timeout"] != config.Timeout.String() {
		t.Errorf("Expected timeout %v, got %v", config.Timeout.String(), asMap["timeout"])
	}

	// Check optional fields
	if asMap["environment"] == nil {
		t.Error("Expected environment to be present in map")
	}
	if asMap["working_dir"] != config.WorkingDir {
		t.Errorf("Expected working_dir %v, got %v", config.WorkingDir, asMap["working_dir"])
	}
	if asMap["description"] != config.Description {
		t.Errorf("Expected description %v, got %v", config.Description, asMap["description"])
	}
}

func TestScriptConfig_YAMLSerialization(t *testing.T) {
	original := ScriptConfig{
		Content:       getTestScript(),
		Shell:         getTestShell(),
		Timeout:       30 * time.Second,
		Environment:   map[string]string{"TEST": "value"},
		SigningPolicy: SigningPolicyOptional,
		Description:   "Test script",
	}

	// Serialize to YAML
	yamlData, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() failed: %v", err)
	}

	// Deserialize from YAML
	var deserialized ScriptConfig
	err = deserialized.FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML() failed: %v", err)
	}

	// Compare key fields
	if deserialized.Content != original.Content {
		t.Errorf("Content mismatch: got %v, want %v", deserialized.Content, original.Content)
	}
	if deserialized.Shell != original.Shell {
		t.Errorf("Shell mismatch: got %v, want %v", deserialized.Shell, original.Shell)
	}
	if deserialized.Timeout != original.Timeout {
		t.Errorf("Timeout mismatch: got %v, want %v", deserialized.Timeout, original.Timeout)
	}
	if deserialized.SigningPolicy != original.SigningPolicy {
		t.Errorf("SigningPolicy mismatch: got %v, want %v", deserialized.SigningPolicy, original.SigningPolicy)
	}
}

func TestScriptConfig_GetManagedFields(t *testing.T) {
	config := ScriptConfig{
		Content:     getTestScript(),
		Shell:       getTestShell(),
		Environment: map[string]string{"TEST": "value"},
		WorkingDir:  "/tmp",
		Description: "Test script",
	}

	fields := config.GetManagedFields()

	// Check that basic fields are always present
	expectedBasic := []string{"content", "shell", "timeout", "signing_policy"}
	for _, expected := range expectedBasic {
		found := false
		for _, field := range fields {
			if field == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected field %s not found in managed fields", expected)
		}
	}

	// Check that optional fields are present when set
	expectedOptional := []string{"environment", "working_dir", "description"}
	for _, expected := range expectedOptional {
		found := false
		for _, field := range fields {
			if field == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected optional field %s not found in managed fields", expected)
		}
	}
}

func TestScriptModule_GetSet(t *testing.T) {
	module := NewModule()
	ctx := context.Background()
	resourceID := "test-script"

	// Test Get on non-existent resource
	config, err := module.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	// Should return empty config
	scriptConfig, ok := config.(*ScriptConfig)
	if !ok {
		t.Fatalf("Get() returned wrong type: %T", config)
	}
	if scriptConfig.SigningPolicy != SigningPolicyNone {
		t.Errorf("Expected empty config with 'none' signing policy, got %v", scriptConfig.SigningPolicy)
	}

	// Test Set with valid config
	testConfig := &ScriptConfig{
		Content: getTestScript(),
		Shell:   getTestShell(),
		Timeout: 10 * time.Second,
	}

	// Add context timestamp to avoid panic
	ctx = context.WithValue(ctx, timestampKey, time.Now().Unix())

	err = module.Set(ctx, resourceID, testConfig)
	if err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Test Get after Set
	config, err = module.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("Get() after Set() failed: %v", err)
	}

	scriptConfig, ok = config.(*ScriptConfig)
	if !ok {
		t.Fatalf("Get() returned wrong type: %T", config)
	}

	if scriptConfig.Content != testConfig.Content {
		t.Errorf("Content mismatch: got %v, want %v", scriptConfig.Content, testConfig.Content)
	}
	if scriptConfig.Shell != testConfig.Shell {
		t.Errorf("Shell mismatch: got %v, want %v", scriptConfig.Shell, testConfig.Shell)
	}
}

func TestScriptModule_ExecutionState(t *testing.T) {
	module := NewModule()
	resourceID := "test-execution-state"

	// Test non-existent execution state
	state, exists := module.GetExecutionState(resourceID)
	if exists {
		t.Error("Expected non-existent execution state to return false")
	}
	if state != nil {
		t.Error("Expected nil state for non-existent execution")
	}

	// Create a test execution state
	testConfig := &ScriptConfig{
		Content: getTestScript(),
		Shell:   getTestShell(),
	}

	ctx := context.WithValue(context.Background(), timestampKey, time.Now().Unix())

	// This will create an execution state
	err := module.Set(ctx, resourceID, testConfig)
	if err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Test existing execution state
	state, exists = module.GetExecutionState(resourceID)
	if !exists {
		t.Error("Expected existing execution state to return true")
	}
	if state == nil {
		t.Fatal("Expected non-nil state for existing execution")
	}

	if state.Config.Content != testConfig.Content {
		t.Errorf("Execution state content mismatch: got %v, want %v", state.Config.Content, testConfig.Content)
	}

	// Test clear execution
	module.ClearExecution(resourceID)
	_, exists = module.GetExecutionState(resourceID)
	if exists {
		t.Error("Expected cleared execution state to return false")
	}
}

func TestScriptModule_InvalidConfig(t *testing.T) {
	module := NewModule()
	ctx := context.Background()
	resourceID := "test-invalid"

	// Test with invalid script config
	invalidConfig := &ScriptConfig{
		Content: "", // Empty content should fail validation
		Shell:   getTestShell(),
	}

	err := module.Set(ctx, resourceID, invalidConfig)
	if err == nil {
		t.Error("Expected Set() to fail with invalid script config")
	}
}

// TestScriptModule_FailedRunNotMarkedConverged verifies that a script exiting
// non-zero is NOT marked converged: after Set() the module must return a current
// state that the real comparator sees as drifted from desired so that the
// executor re-invokes Set() on the next converge cycle (Issue #2479 symptom 1).
func TestScriptModule_FailedRunNotMarkedConverged(t *testing.T) {
	module := NewModule()
	ctx := context.WithValue(context.Background(), timestampKey, time.Now().Unix())
	resourceID := "test-fail-no-converge"

	// desired is a map-backed ConfigState, the same form the executor delivers.
	desired := &testConfigState{data: map[string]interface{}{
		"content":           getFailingScript(),
		"shell":             string(getTestShell()),
		"timeout":           "30s",
		"signing_policy":    string(SigningPolicyNone),
		"execution_context": string(ExecutionContextSystem),
	}}

	// Set() runs the script which exits non-zero; the module stores StatusFailed.
	if err := module.Set(ctx, resourceID, desired); err != nil {
		t.Fatalf("Set() returned unexpected error: %v", err)
	}

	state, ok := module.GetExecutionState(resourceID)
	if !ok {
		t.Fatal("expected execution state to be stored after Set()")
	}
	if state.Status != StatusFailed {
		t.Fatalf("expected StatusFailed after non-zero exit, got %s", state.Status)
	}

	current, err := module.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("Get() after failed execution returned error: %v", err)
	}

	// The real comparator must detect drift so the executor re-invokes Set().
	comparator := stewardtesting.NewStateComparator()
	driftDetected, diff := comparator.CompareStates(current, desired)
	if !driftDetected {
		t.Errorf("expected drift to be detected after failed script (resource would be wrongly skipped); diff: %s", diff.GetDetailedDiff())
	}
}

// TestModule_StageAction verifies that the stage action:
//  1. Looks up a library script by id+version from the script repository.
//  2. Records staged state (StatusStaged) without executing the inline content.
//  3. Resolves param_bindings via the secret store on that path.
func TestModule_StageAction(t *testing.T) {
	const scriptID = "cirunner-provision"
	const scriptVersion = "1.0.0"

	// Populate the in-memory repository with a known script.
	repo := newInMemoryScriptRepo(makeTestVersionedScript(scriptID, scriptVersion))

	// Set up a real secret store so we can verify secret binding resolution.
	store := newTestSecretStore(t)
	storeSecret(t, store, "github/runner-token", "ghs-staging-secret")

	module := NewModule()
	module.SetScriptRepository(repo)
	module.SetSecretStore(store)

	ctx := context.WithValue(context.Background(), timestampKey, time.Now().Unix())
	resourceID := "ci-runner-script"

	cfg := &ScriptConfig{
		Action: ScriptActionStage,
		Stage: &StageConfig{
			ID:      scriptID,
			Version: scriptVersion,
		},
		ParamBindings: []ParamBinding{
			{Name: "RunnerToken", From: ParamSourceSecretStore, Key: "github/runner-token"},
			{Name: "OrgName", From: ParamSourceLiteral, Value: "my-org"},
		},
	}

	err := module.Set(ctx, resourceID, cfg)
	require.NoError(t, err, "stage action must succeed")

	// Verify the module recorded staged status — no inline execution occurred.
	state, exists := module.GetExecutionState(resourceID)
	require.True(t, exists, "execution state must be recorded after stage")
	assert.Equal(t, StatusStaged, state.Status, "status must be StatusStaged (not Running/Completed)")
	assert.Nil(t, state.Result, "no ExecutionResult should be produced on the stage path")

	// Verify the staged ref points to the correct script.
	require.NotNil(t, state.Staged, "staged ref must be populated")
	assert.Equal(t, scriptID, state.Staged.ID)
	assert.Equal(t, scriptVersion, state.Staged.Version)
	require.NotNil(t, state.Staged.Script, "library script must be fetched and recorded")
	assert.Equal(t, scriptID, state.Staged.Script.Metadata.ID)

	// Verify param_bindings were resolved.
	require.Len(t, state.Staged.ResolvedParams, 2)
	byName := make(map[string]ResolvedParam)
	for _, p := range state.Staged.ResolvedParams {
		byName[p.Name] = p
	}

	token := byName["RunnerToken"]
	assert.Equal(t, "ghs-staging-secret", token.Value, "secret binding must be resolved")
	assert.True(t, token.IsSecret, "RunnerToken must be marked as a secret")

	org := byName["OrgName"]
	assert.Equal(t, "my-org", org.Value, "literal binding must be resolved")
	assert.False(t, org.IsSecret, "OrgName must not be marked as a secret")
}

// TestModule_StageAction_MissingRepo verifies that a stage action without
// a configured script repository returns a clear error.
func TestModule_StageAction_MissingRepo(t *testing.T) {
	module := NewModule() // No script repository configured.

	ctx := context.Background()
	cfg := &ScriptConfig{
		Action: ScriptActionStage,
		Stage:  &StageConfig{ID: "some-script", Version: "1.0.0"},
	}

	err := module.Set(ctx, "resource-1", cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "script repository")
}

// TestModule_StageAction_MissingScript verifies that looking up a non-existent
// library script returns a clear error.
func TestModule_StageAction_MissingScript(t *testing.T) {
	repo := newInMemoryScriptRepo() // Empty repository.
	module := NewModule()
	module.SetScriptRepository(repo)

	ctx := context.Background()
	cfg := &ScriptConfig{
		Action: ScriptActionStage,
		Stage:  &StageConfig{ID: "nonexistent-script", Version: "1.0.0"},
	}

	err := module.Set(ctx, "resource-1", cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "library script lookup failed")
}

// TestModule_StageAction_LiteralOnlyBindings verifies the stage path with
// literal-only param bindings (no secret store required).
func TestModule_StageAction_LiteralOnlyBindings(t *testing.T) {
	const scriptID = "deploy-agent"
	const scriptVersion = "2.0.1"

	repo := newInMemoryScriptRepo(makeTestVersionedScript(scriptID, scriptVersion))
	module := NewModule()
	module.SetScriptRepository(repo)
	// No secret store set — literal bindings must not require one.

	ctx := context.Background()
	cfg := &ScriptConfig{
		Action: ScriptActionStage,
		Stage:  &StageConfig{ID: scriptID, Version: scriptVersion},
		ParamBindings: []ParamBinding{
			{Name: "Endpoint", From: ParamSourceLiteral, Value: "https://api.example.com"},
		},
	}

	err := module.Set(ctx, "resource-2", cfg)
	require.NoError(t, err)

	state, exists := module.GetExecutionState("resource-2")
	require.True(t, exists)
	assert.Equal(t, StatusStaged, state.Status)
	require.Len(t, state.Staged.ResolvedParams, 1)
	assert.Equal(t, "https://api.example.com", state.Staged.ResolvedParams[0].Value)
}

// TestModule_StageConfig_Validate_MissingStage verifies that a stage action
// without a stage config fails validation.
func TestModule_StageConfig_Validate_MissingStage(t *testing.T) {
	cfg := &ScriptConfig{
		Action: ScriptActionStage,
		// Stage is nil — must fail.
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stage configuration is required")
}

// TestModule_StageConfig_Validate_MissingID verifies that a stage config without
// an ID fails validation.
func TestModule_StageConfig_Validate_MissingID(t *testing.T) {
	cfg := &ScriptConfig{
		Action: ScriptActionStage,
		Stage:  &StageConfig{ID: "", Version: "1.0.0"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stage.id")
}

// TestScriptModule_SuccessRunNoDriftWithNonSecondTimeout verifies that a script
// exiting 0 is reported as compliant with no verification failure, including when
// timeout is expressed in non-second units (e.g. "5m") that Go's Duration.String()
// would otherwise normalise to "5m0s" and cause a false mismatch (Issue #2479 symptom 2).
func TestScriptModule_SuccessRunNoDriftWithNonSecondTimeout(t *testing.T) {
	module := NewModule()
	ctx := context.WithValue(context.Background(), timestampKey, time.Now().Unix())
	resourceID := "test-success-no-drift"

	// Use a non-second timeout to exercise the normalisation fix.
	desired := &testConfigState{data: map[string]interface{}{
		"content":           getTestScript(),
		"shell":             string(getTestShell()),
		"timeout":           "5m",
		"signing_policy":    string(SigningPolicyNone),
		"execution_context": string(ExecutionContextSystem),
	}}

	if err := module.Set(ctx, resourceID, desired); err != nil {
		t.Fatalf("Set() returned unexpected error: %v", err)
	}

	state, ok := module.GetExecutionState(resourceID)
	if !ok {
		t.Fatal("expected execution state to be stored after Set()")
	}
	if state.Status != StatusCompleted {
		t.Fatalf("expected StatusCompleted after exit-0 script, got %s", state.Status)
	}

	current, err := module.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("Get() after successful execution returned error: %v", err)
	}

	// The real comparator must find NO drift; any drift here causes the executor
	// to report "verification failed: changes not fully applied".
	comparator := stewardtesting.NewStateComparator()
	driftDetected, diff := comparator.CompareStates(current, desired)
	if driftDetected {
		t.Errorf("unexpected drift detected after successful execution (would cause false verification failure); diff: %s", diff.GetDetailedDiff())
	}
}
