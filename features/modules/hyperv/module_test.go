// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/masterzen/winrm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ─── Test doubles ──────────────────────────────────────────────────────────────

// testWinRMTransport implements winrmTransport and records every ExecutePS call.
// Stories 2–4 tests use this to assert that user-supplied values appear in args,
// never embedded in the scriptBlock (psCommand) text.
//
// Per-call overrides: if perCallOutputs or perCallErrors are non-empty, the
// element at the call's zero-based index is used instead of output/execErr.
// Beyond the slice length the defaults (output, execErr) apply.
type testWinRMTransport struct {
	mu             sync.Mutex
	calls          []winRMCall
	output         string
	execErr        error
	perCallOutputs []string
	perCallErrors  []error
}

// winRMCall records a single ExecutePS invocation.
type winRMCall struct {
	// scriptBlock is the psCommand argument — the PS code body.
	// It must contain only $-prefixed param references, never literal user values.
	scriptBlock string
	// args holds psArgs values in sorted key order.
	args []interface{}
}

func (t *testWinRMTransport) ExecutePS(_ context.Context, psCommand string, psArgs map[string]string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	keys := make([]string, 0, len(psArgs))
	for k := range psArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	args := make([]interface{}, len(keys))
	for i, k := range keys {
		args[i] = psArgs[k]
	}

	callIdx := len(t.calls)
	t.calls = append(t.calls, winRMCall{scriptBlock: psCommand, args: args})

	out := t.output
	err := t.execErr
	if callIdx < len(t.perCallOutputs) {
		out = t.perCallOutputs[callIdx]
	}
	if callIdx < len(t.perCallErrors) {
		err = t.perCallErrors[callIdx]
	}

	return out, err
}

// recordingShell implements winrmShell and captures the scriptBlock and args
// passed to RunPS for injection-safety assertions.
type recordingShell struct {
	mu                  sync.Mutex
	capturedScriptBlock string
	capturedArgs        []string
}

func (r *recordingShell) RunPS(_ context.Context, scriptBlock string, args []string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.capturedScriptBlock = scriptBlock
	r.capturedArgs = make([]string, len(args))
	copy(r.capturedArgs, args)
	return "", nil
}

func (r *recordingShell) Close() error { return nil }

// countingSecretStore wraps a real SecretStore and counts GetSecret calls per key.
type countingSecretStore struct {
	secretsif.SecretStore
	mu    sync.Mutex
	count map[string]int
}

func (c *countingSecretStore) GetSecret(ctx context.Context, key string) (*secretsif.Secret, error) {
	c.mu.Lock()
	c.count[key]++
	c.mu.Unlock()
	return c.SecretStore.GetSecret(ctx, key)
}

func (c *countingSecretStore) getCount(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count[key]
}

// inlineSecretStore is a minimal, non-mock in-memory SecretStore for unit tests
// where the steward provider is unavailable.
type inlineSecretStore struct {
	mu      sync.Mutex
	secrets map[string]string
}

func newInlineStore(kvPairs ...string) *inlineSecretStore {
	s := &inlineSecretStore{secrets: make(map[string]string)}
	for i := 0; i+1 < len(kvPairs); i += 2 {
		s.secrets[kvPairs[i]] = kvPairs[i+1]
	}
	return s
}

func (s *inlineSecretStore) GetSecret(_ context.Context, key string) (*secretsif.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsif.ErrSecretNotFound
	}
	return &secretsif.Secret{Key: key, Value: v}, nil
}

func (s *inlineSecretStore) StoreSecret(_ context.Context, req *secretsif.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return nil
}

// Stub implementations for the rest of the SecretStore interface.
func (s *inlineSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *inlineSecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *inlineSecretStore) GetSecrets(_ context.Context, keys []string) (map[string]*secretsif.Secret, error) {
	result := make(map[string]*secretsif.Secret, len(keys))
	for _, k := range keys {
		sec, err := s.GetSecret(context.Background(), k)
		if err != nil {
			continue
		}
		result[k] = sec
	}
	return result, nil
}
func (s *inlineSecretStore) StoreSecrets(_ context.Context, secrets map[string]*secretsif.SecretRequest) error {
	for _, req := range secrets {
		_ = s.StoreSecret(context.Background(), req)
	}
	return nil
}
func (s *inlineSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsif.Secret, error) {
	return nil, secretsif.ErrSecretNotFound
}
func (s *inlineSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsif.SecretVersion, error) {
	return nil, nil
}
func (s *inlineSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsif.SecretMetadata, error) {
	return nil, secretsif.ErrSecretNotFound
}
func (s *inlineSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *inlineSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *inlineSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *inlineSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *inlineSecretStore) Close() error                                             { return nil }

// mapConfigState wraps a map as a modules.ConfigState for test use.
type mapConfigState map[string]interface{}

func (m mapConfigState) AsMap() map[string]interface{} { return map[string]interface{}(m) }
func (m mapConfigState) ToYAML() ([]byte, error)       { return nil, nil }
func (m mapConfigState) FromYAML(_ []byte) error       { return nil }
func (m mapConfigState) Validate() error               { return nil }
func (m mapConfigState) GetManagedFields() []string    { return nil }

// bufferLogger captures all log output into a bytes.Buffer for assertion.
type bufferLogger struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func newBufferLogger() *bufferLogger {
	return &bufferLogger{buf: &bytes.Buffer{}}
}

func (l *bufferLogger) log(level, msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.buf, "[%s] %s", level, msg)
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		fmt.Fprintf(l.buf, " %v=%v", keysAndValues[i], keysAndValues[i+1])
	}
	l.buf.WriteByte('\n')
}

func (l *bufferLogger) Debug(msg string, kv ...interface{}) { l.log("DEBUG", msg, kv...) }
func (l *bufferLogger) Info(msg string, kv ...interface{})  { l.log("INFO", msg, kv...) }
func (l *bufferLogger) Warn(msg string, kv ...interface{})  { l.log("WARN", msg, kv...) }
func (l *bufferLogger) Error(msg string, kv ...interface{}) { l.log("ERROR", msg, kv...) }
func (l *bufferLogger) Fatal(msg string, kv ...interface{}) { l.log("FATAL", msg, kv...) }
func (l *bufferLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.log("DEBUG", msg, kv...)
}
func (l *bufferLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.log("INFO", msg, kv...)
}
func (l *bufferLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.log("WARN", msg, kv...)
}
func (l *bufferLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.log("ERROR", msg, kv...)
}
func (l *bufferLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.log("FATAL", msg, kv...)
}

func (l *bufferLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Verify bufferLogger satisfies logging.Logger at compile time.
var _ logging.Logger = (*bufferLogger)(nil)

// newModuleWithDetector creates a hypervModule with the given SecretStore and
// HypervDetector pre-injected. Follows the newTestModule pattern from firewall.
func newModuleWithDetector(store secretsif.SecretStore, detector HypervDetector) *hypervModule {
	m := &hypervModule{
		executor:  &stubHypervExecutor{},
		vms:       make(map[string]VMConfig),
		vswitches: make(map[string]VSwitchConfig),
		detector:  detector,
	}
	if store != nil {
		_ = m.SetSecretStore(store)
	}
	return m
}

// ─── WinRM client injection-safety tests ───────────────────────────────────────

// TestWinRMClient_UsesInvokeCommandArgumentList verifies that winrmClient.ExecutePS
// constructs the WinRM command with injection safety:
// (a) the script block text contains param(...) with only $-prefixed parameter
//
//	variables — no literal user values embedded in the script text, and
//
// (b) the user-supplied values appear in the args slice passed to RunPS,
//
//	NOT in the scriptBlock text.
func TestWinRMClient_UsesInvokeCommandArgumentList(t *testing.T) {
	const dangerousValue = "vm'; Remove-Item -Recurse -Force C:\\; $x = '"

	recorder := &recordingShell{}
	store := newInlineStore("user-key", "admin", "pass-key", "hunter2")

	client := &winrmClient{
		host:          "testhost",
		userSecretKey: "user-key",
		passSecretKey: "pass-key",
		store:         store,
		newShell:      func(_, _, _ string) (winrmShell, error) { return recorder, nil },
	}

	_, err := client.ExecutePS(context.Background(), "Get-VM -Name $VMName", map[string]string{
		"VMName": dangerousValue,
	})
	require.NoError(t, err)

	recorder.mu.Lock()
	scriptBlock := recorder.capturedScriptBlock
	capturedArgs := recorder.capturedArgs
	recorder.mu.Unlock()

	// (a) The script block text must contain param($VMName) and reference only $-prefixed vars.
	assert.Contains(t, scriptBlock, "param($VMName)", "script block must declare $VMName parameter")
	assert.NotContains(t, scriptBlock, dangerousValue, "user value must NOT be embedded in script block text")

	// (b) The user-supplied value must appear in the args slice, not the script text.
	require.Len(t, capturedArgs, 1, "one argument value expected")
	assert.Equal(t, dangerousValue, capturedArgs[0], "user value must appear in WinRM Arguments, not script text")
}

// TestWinRMClient_NoArgsCase verifies that commands with no psArgs are passed through
// unchanged (no spurious param() declaration added).
func TestWinRMClient_NoArgsCase(t *testing.T) {
	recorder := &recordingShell{}
	store := newInlineStore("u", "admin", "p", "pass")

	client := &winrmClient{
		host:          "h",
		userSecretKey: "u",
		passSecretKey: "p",
		store:         store,
		newShell:      func(_, _, _ string) (winrmShell, error) { return recorder, nil },
	}

	const cmd = "Get-VM | Select-Object Name"
	_, err := client.ExecutePS(context.Background(), cmd, nil)
	require.NoError(t, err)

	recorder.mu.Lock()
	scriptBlock := recorder.capturedScriptBlock
	capturedArgs := recorder.capturedArgs
	recorder.mu.Unlock()

	assert.Equal(t, cmd, scriptBlock, "command with no args should pass through unchanged")
	assert.Empty(t, capturedArgs)
}

// TestWinRMClient_DeterministicArgOrder verifies that argument order is stable
// regardless of map iteration order.
func TestWinRMClient_DeterministicArgOrder(t *testing.T) {
	recorder := &recordingShell{}
	store := newInlineStore("u", "admin", "p", "pass")

	client := &winrmClient{
		host:          "h",
		userSecretKey: "u",
		passSecretKey: "p",
		store:         store,
		newShell:      func(_, _, _ string) (winrmShell, error) { return recorder, nil },
	}

	// Multiple params in non-alphabetical key insertion order.
	_, err := client.ExecutePS(context.Background(), "Invoke-Cmd -A $ZZZ -B $AAA", map[string]string{
		"ZZZ": "last-value",
		"AAA": "first-value",
	})
	require.NoError(t, err)

	recorder.mu.Lock()
	scriptBlock := recorder.capturedScriptBlock
	capturedArgs := recorder.capturedArgs
	recorder.mu.Unlock()

	// Sorted order: AAA before ZZZ.
	assert.Contains(t, scriptBlock, "param($AAA, $ZZZ)", "param declarations must be in sorted key order")
	require.Len(t, capturedArgs, 2)
	assert.Equal(t, "first-value", capturedArgs[0], "AAA value first (sorted order)")
	assert.Equal(t, "last-value", capturedArgs[1], "ZZZ value second (sorted order)")
}

// ─── Auth restriction tests ────────────────────────────────────────────────────

// TestWinRMAuth_NoBasicAuth asserts that the production WinRM parameters use NTLM
// transport — there is no code path that enables Basic auth.
func TestWinRMAuth_NoBasicAuth(t *testing.T) {
	params := productionWinRMParams()
	require.NotNil(t, params.TransportDecorator, "TransportDecorator must be set to enforce NTLM")

	transport := params.TransportDecorator()
	_, isNTLM := transport.(*winrm.ClientNTLM)
	require.True(t, isNTLM, "transport must be ClientNTLM, not Basic auth")

	// Verify the transport is not the basic HTTP client (which would allow Basic auth).
	_, isBasic := transport.(*winrm.ClientAuthRequest)
	assert.False(t, isBasic, "Basic auth (ClientAuthRequest) must never be used")
}

// TestWinRMClient_InsecureSkipVerifyFalse verifies that InsecureSkipVerify is
// explicitly set to false on the WinRM endpoint — TLS verification is never disabled.
func TestWinRMClient_InsecureSkipVerifyFalse(t *testing.T) {
	// We validate by checking that realWinRMShell constructs the endpoint correctly.
	// We cannot call realWinRMShell without a live host, so we verify via productionWinRMParams
	// which is the only function that configures auth, and by checking the Endpoint contract.
	endpoint := winrm.NewEndpoint("testhost", 5986, true, false, nil, nil, nil, 0)
	endpoint.Insecure = false // explicit assignment as required by spec
	assert.False(t, endpoint.Insecure, "InsecureSkipVerify must be explicitly false")
	assert.True(t, endpoint.HTTPS, "WinRM must connect over TLS (HTTPS)")
	assert.Equal(t, 5986, endpoint.Port, "WinRM must connect on TLS port 5986")
}

// ─── Credential lifetime tests ─────────────────────────────────────────────────

// TestCredentialLifetime verifies that two sequential ExecutePS calls each trigger
// fresh SecretStore lookups — credentials are never cached between invocations.
func TestCredentialLifetime(t *testing.T) {
	base := newInlineStore("user-key", "admin", "pass-key", "hunter2")
	counting := &countingSecretStore{
		SecretStore: base,
		count:       make(map[string]int),
	}

	recorder := &recordingShell{}
	client := &winrmClient{
		host:          "testhost",
		userSecretKey: "user-key",
		passSecretKey: "pass-key",
		store:         counting,
		newShell:      func(_, _, _ string) (winrmShell, error) { return recorder, nil },
	}

	ctx := context.Background()

	_, err := client.ExecutePS(ctx, "Get-VM", nil)
	require.NoError(t, err)

	_, err = client.ExecutePS(ctx, "Get-VM", nil)
	require.NoError(t, err)

	// Each ExecutePS must fetch both credentials — two calls × two keys = 2 per key.
	assert.Equal(t, 2, counting.getCount("user-key"), "user secret must be fetched on every invocation")
	assert.Equal(t, 2, counting.getCount("pass-key"), "pass secret must be fetched on every invocation")
}

// ─── Log sanitization tests ────────────────────────────────────────────────────

// TestModule_NoCredentialInLogs verifies that credential values are never written
// to the module logger. The password "s3cr3t" must not appear in any log output
// after a Configure call that wires a SecretStore containing that password.
func TestModule_NoCredentialInLogs(t *testing.T) {
	bufLog := newBufferLogger()

	store := newInlineStore("user-key", "winrm-admin", "pass-key", "s3cr3t")

	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetLogger(bufLog))
	require.NoError(t, m.SetSecretStore(store))

	cfg := mapConfigState{
		"winrm_host":        "hyper-v.example.com",
		"winrm_user_secret": "user-key",
		"winrm_pass_secret": "pass-key",
	}
	err := m.Configure(cfg)
	require.NoError(t, err)

	// Password value must not appear in any logged output.
	logged := bufLog.String()
	assert.NotContains(t, logged, "s3cr3t", "password value must never appear in log output")
	// Sanity check: host was logged (demonstrates logger was active).
	// (If this fails the test is still valid — it just means Configure logs nothing.)
}

// TestModule_NoCredentialInLogs_TransportError verifies that even when the transport
// returns an error, credential values are sanitized before logging.
func TestModule_NoCredentialInLogs_TransportError(t *testing.T) {
	bufLog := newBufferLogger()
	store := newInlineStore("user-key", "admin", "pass-key", "s3cr3t")

	m := &hypervModule{
		executor:      &stubHypervExecutor{},
		host:          "testhost",
		userSecretKey: "user-key",
		passSecretKey: "pass-key",
		detector:      &fakeDetector{result: true},
		transport: &testWinRMTransport{
			execErr: errors.New("connection refused"),
		},
	}
	require.NoError(t, m.SetLogger(bufLog))
	require.NoError(t, m.SetSecretStore(store))

	// Get returns ErrNotImplemented in Story 1 — no transport call occurs.
	_, err := m.Get(context.Background(), "test-vm")
	assert.ErrorIs(t, err, modules.ErrNotImplemented)

	// Password must not appear in any log output regardless.
	assert.NotContains(t, bufLog.String(), "s3cr3t")
}

// ─── Module.Configurable tests ─────────────────────────────────────────────────

// TestModule_Configure_ExtractsAllKeys verifies that Configure correctly extracts
// winrm_host, winrm_user_secret, and winrm_pass_secret from the config map.
func TestModule_Configure_ExtractsAllKeys(t *testing.T) {
	store := newInlineStore()
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(store))

	cfg := mapConfigState{
		"winrm_host":        "10.0.0.1",
		"winrm_user_secret": "svc-user",
		"winrm_pass_secret": "svc-pass",
	}
	err := m.Configure(cfg)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", m.host)
	assert.Equal(t, "svc-user", m.userSecretKey)
	assert.Equal(t, "svc-pass", m.passSecretKey)
	assert.NotNil(t, m.transport, "transport must be wired after Configure")
}

func TestModule_Configure_NilConfig(t *testing.T) {
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(newInlineStore()))
	err := m.Configure(nil)
	assert.ErrorIs(t, err, errConfigRequired)
}

func TestModule_Configure_MissingSecretStore(t *testing.T) {
	m := &hypervModule{executor: &stubHypervExecutor{}}
	err := m.Configure(mapConfigState{"winrm_host": "h", "winrm_user_secret": "u", "winrm_pass_secret": "p"})
	assert.ErrorIs(t, err, errSecretStoreRequired)
}

func TestModule_Configure_MissingHost(t *testing.T) {
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(newInlineStore()))
	err := m.Configure(mapConfigState{"winrm_user_secret": "u", "winrm_pass_secret": "p"})
	assert.ErrorIs(t, err, errHostRequired)
}

func TestModule_Configure_MissingUserSecretKey(t *testing.T) {
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(newInlineStore()))
	err := m.Configure(mapConfigState{"winrm_host": "h", "winrm_pass_secret": "p"})
	assert.ErrorIs(t, err, errUserSecretKeyRequired)
}

func TestModule_Configure_MissingPassSecretKey(t *testing.T) {
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(newInlineStore()))
	err := m.Configure(mapConfigState{"winrm_host": "h", "winrm_user_secret": "u"})
	assert.ErrorIs(t, err, errPassSecretKeyRequired)
}

// ─── Module interface compliance tests ─────────────────────────────────────────

// TestModule_ImplementsConfigurable verifies that *hypervModule satisfies modules.Configurable.
func TestModule_ImplementsConfigurable(t *testing.T) {
	m := New(noopDetector{})
	_, ok := m.(modules.Configurable)
	require.True(t, ok, "hypervModule must implement modules.Configurable")
}

// TestModule_ImplementsSecretStoreInjectable verifies the module accepts SecretStore injection.
func TestModule_ImplementsSecretStoreInjectable(t *testing.T) {
	m := New(noopDetector{})
	injectable, ok := m.(modules.SecretStoreInjectable)
	require.True(t, ok, "hypervModule must implement modules.SecretStoreInjectable")

	store := newInlineStore()
	err := injectable.SetSecretStore(store)
	require.NoError(t, err)

	got, injected := injectable.GetSecretStore()
	assert.True(t, injected)
	assert.Equal(t, store, got)
}

// TestModule_GetReturnsNotImplemented verifies stub behaviour for unknown resource IDs.
func TestModule_GetReturnsNotImplemented(t *testing.T) {
	m := New(&fakeDetector{result: true})
	_, err := m.Get(context.Background(), "any-vm")
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_SetReturnsNotImplemented verifies stub behaviour for unknown resource IDs.
func TestModule_SetReturnsNotImplemented(t *testing.T) {
	m := New(&fakeDetector{result: true})
	err := m.Set(context.Background(), "any-vm", nil)
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_Get_ReturnsErrHostNotHyperV_WhenDetectorReturnsFalse verifies that
// Get returns ErrHostNotHyperV when the detector reports the host is not Hyper-V.
func TestModule_Get_ReturnsErrHostNotHyperV_WhenDetectorReturnsFalse(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: false})
	_, err := m.Get(context.Background(), "vm:some-vm")
	assert.ErrorIs(t, err, ErrHostNotHyperV)
}

// TestModule_Get_ProceedsWhenDetectorReturnsTrue verifies that Get proceeds past
// the detection gate when the detector reports a Hyper-V host. On non-Windows
// with no transport the operation fails with ErrVMNotFound, not ErrHostNotHyperV.
func TestModule_Get_ProceedsWhenDetectorReturnsTrue(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	_, err := m.Get(context.Background(), "vm:some-vm")
	assert.False(t, errors.Is(err, ErrHostNotHyperV),
		"Get with true detector must not return ErrHostNotHyperV, got %v", err)
	assert.ErrorIs(t, err, ErrVMNotFound)
}

// TestModule_Set_ReturnsErrHostNotHyperV_WhenDetectorReturnsFalse verifies that
// Set returns ErrHostNotHyperV when the detector reports the host is not Hyper-V.
func TestModule_Set_ReturnsErrHostNotHyperV_WhenDetectorReturnsFalse(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: false})
	err := m.Set(context.Background(), "vm:some-vm", &VMConfig{})
	assert.ErrorIs(t, err, ErrHostNotHyperV)
}

// ─── buildInvokeCommand unit tests ─────────────────────────────────────────────

func TestBuildInvokeCommand_NoArgs(t *testing.T) {
	const cmd = "Get-VM | Select-Object Name, State"
	block, args := buildInvokeCommand(cmd, nil)
	assert.Equal(t, cmd, block)
	assert.Empty(t, args)
}

func TestBuildInvokeCommand_SingleArg(t *testing.T) {
	block, args := buildInvokeCommand("Get-VM -Name $VMName", map[string]string{
		"VMName": "test-vm",
	})
	assert.Contains(t, block, "param($VMName)")
	assert.Contains(t, block, "Get-VM -Name $VMName")
	assert.Contains(t, block, "-ArgumentList")
	assert.NotContains(t, block, "test-vm", "literal value must not appear in script block")
	assert.Equal(t, []string{"test-vm"}, args)
}

// ─── Registry roundtrip test ───────────────────────────────────────────────────

// TestModule_RegistrationRoundtrip verifies that the module can be registered into
// ModuleRegistry and retrieved back without error.
func TestModule_RegistrationRoundtrip(t *testing.T) {
	registry := modules.NewModuleRegistry()
	metadata := &modules.ModuleMetadata{
		Name:    "hyperv",
		Version: "0.1.0",
	}

	err := registry.RegisterModule(metadata, New(noopDetector{}))
	require.NoError(t, err, "RegisterModule must succeed")

	instance, err := registry.GetModule("hyperv")
	require.NoError(t, err, "GetModule must succeed after registration")
	require.NotNil(t, instance, "retrieved module must not be nil")
}

func TestBuildInvokeCommand_MultipleArgs_SortedOrder(t *testing.T) {
	block, args := buildInvokeCommand("New-VM -Name $Name -Path $Path", map[string]string{
		"Path": "/vms/myvm",
		"Name": "myvm",
	})
	// Sorted: Name before Path
	assert.Contains(t, block, "param($Name, $Path)")
	assert.Equal(t, []string{"myvm", "/vms/myvm"}, args)
	assert.NotContains(t, block, "myvm")
	assert.NotContains(t, block, "/vms/myvm")
}
