// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/steward/discovery"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// crlfLifecycleModule is a test double implementing both Module and
// ModuleLifecycle with controllable Initialize/Stop failures, used to drive
// features/modules/manager.go and factory_lifecycle.go through the error
// paths that log a caller-influenced error value. It is a real implementation
// of the production interfaces (not a mock of a CFGMS component under test),
// following the same pattern as the existing mockModule in registry_test.go.
type crlfLifecycleModule struct {
	initErr error
	stopErr error
}

func (m *crlfLifecycleModule) Get(ctx context.Context, resourceID string) (ConfigState, error) {
	return nil, nil
}

func (m *crlfLifecycleModule) Set(ctx context.Context, resourceID string, config ConfigState) error {
	return nil
}

func (m *crlfLifecycleModule) Initialize(ctx context.Context, config ModuleConfig) error {
	return m.initErr
}

func (m *crlfLifecycleModule) Start(ctx context.Context) error { return nil }

func (m *crlfLifecycleModule) Stop(ctx context.Context) error { return m.stopErr }

func (m *crlfLifecycleModule) Shutdown(ctx context.Context) error { return nil }

func (m *crlfLifecycleModule) Health() HealthStatus {
	return HealthStatus{Status: HealthStateHealthy, Timestamp: time.Now()}
}

// containsRawCRLF reports whether s contains a literal CR or LF byte -- the
// exact payload a forged multi-line log record needs.
func containsRawCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// TestModuleLifecycleManager_panicRecovery_sanitizesInjectedRecoverValue
// forces a panic whose message carries a CRLF injection payload through
// ModuleLifecycleManager.publishEvent's recover handler (manager.go) and
// verifies the value reaching the logger has no raw CR/LF sequence.
// logging.SanitizeLogValue must be applied at the call site, per CLAUDE.md's
// log-sanitization rule, rather than relying on any particular Logger
// implementation to strip control characters downstream.
func TestModuleLifecycleManager_panicRecovery_sanitizesInjectedRecoverValue(t *testing.T) {
	registry := NewModuleRegistry()
	mock := pkgtesting.NewMockLogger(true)
	nl := &notifyOnErrorLogger{MockLogger: mock, errCh: make(chan struct{}, 1)}
	manager := NewModuleLifecycleManager(registry, nl)

	injected := "forged\r\nWARN forged-admin-event: privilege escalated"
	listener := NewLifecycleEventHandler("crlf-panic-listener", func(event LifecycleEvent) {
		panic(injected)
	})
	manager.AddEventListener(listener)

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := manager.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	select {
	case <-nl.errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error log from panic recovery")
	}

	logs := mock.GetLogs("error")
	if len(logs) == 0 {
		t.Fatal("expected error log from panic recovery, got none")
	}

	found := false
	for i := 0; i+1 < len(logs[0].Data); i += 2 {
		key, ok := logs[0].Data[i].(string)
		if !ok || key != "recover" {
			continue
		}
		found = true
		val, ok := logs[0].Data[i+1].(string)
		if !ok {
			t.Fatalf("recover value is not a string: %#v", logs[0].Data[i+1])
		}
		if containsRawCRLF(val) {
			t.Errorf("recover value carries raw CR/LF, log-injection sink not sanitized: %q", val)
		}
		if strings.Contains(val, injected) {
			t.Errorf("recover value equals unsanitized injected payload: %q", val)
		}
	}
	if !found {
		t.Fatal("expected a \"recover\" key in the error log fields")
	}
}

// TestLifecycleAwareModuleFactory_LoadModule_sanitizesUnregisterErrorInLog
// forces factory_lifecycle.go's LoadModule to hit the unregister-after-
// load-failure Warn call with an error whose message carries a CRLF
// injection payload (via a Stop() failure surfaced through UnregisterModule)
// and verifies the value reaching the logger has no raw CR/LF sequence.
func TestLifecycleAwareModuleFactory_LoadModule_sanitizesUnregisterErrorInLog(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	injected := "stop failed for host \"h1\"\r\nInjected-Header: evil"
	fakeModule := &crlfLifecycleModule{
		initErr: errors.New("init failed"),
		stopErr: fmt.Errorf("%s", injected),
	}
	mockLoader.modules["bad-module"] = fakeModule

	mock := pkgtesting.NewMockLogger(true)
	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader, mock)

	if err := factory.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	_, err := factory.LoadModule("bad-module")
	if err == nil {
		t.Fatal("LoadModule() should return error when module Initialize fails")
	}

	warnLogs := mock.GetLogs("warn")
	if len(warnLogs) == 0 {
		t.Fatal("expected a warn log for unregister-after-load-failure, got none")
	}

	found := false
	for i := 0; i+1 < len(warnLogs[0].Data); i += 2 {
		key, ok := warnLogs[0].Data[i].(string)
		if !ok || key != "error" {
			continue
		}
		found = true
		switch v := warnLogs[0].Data[i+1].(type) {
		case error:
			t.Fatalf("raw error value logged directly instead of a sanitized string: %v", v)
		case string:
			if containsRawCRLF(v) {
				t.Errorf("error value carries raw CR/LF, log-injection sink not sanitized: %q", v)
			}
			if strings.Contains(v, injected) {
				t.Errorf("error value equals unsanitized injected payload: %q", v)
			}
		default:
			t.Fatalf("unexpected type for \"error\" field: %#v", v)
		}
	}
	if !found {
		t.Fatal("expected an \"error\" key in the warn log fields")
	}
}

// TestLifecycleAwareModuleFactory_LoadModuleWithConfig_sanitizesUnregisterErrorInLog
// is the LoadModuleWithConfig twin of the test above -- factory_lifecycle.go
// has the identical unregister-after-load-failure Warn call duplicated in
// both methods.
func TestLifecycleAwareModuleFactory_LoadModuleWithConfig_sanitizesUnregisterErrorInLog(t *testing.T) {
	discoveryRegistry := make(discovery.ModuleRegistry)
	moduleRegistry := NewModuleRegistry()
	mockLoader := newMockModuleLoader()

	injected := "stop failed for host \"h2\"\r\nInjected-Header: evil"
	fakeModule := &crlfLifecycleModule{
		initErr: errors.New("init failed"),
		stopErr: fmt.Errorf("%s", injected),
	}
	mockLoader.modules["bad-module-2"] = fakeModule

	mock := pkgtesting.NewMockLogger(true)
	factory := NewLifecycleAwareModuleFactory(discoveryRegistry, moduleRegistry, mockLoader, mock)

	if err := factory.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if stopErr := factory.Stop(); stopErr != nil {
			t.Errorf("Stop() error = %v", stopErr)
		}
	}()

	_, err := factory.LoadModuleWithConfig("bad-module-2", DefaultModuleConfig())
	if err == nil {
		t.Fatal("LoadModuleWithConfig() should return error when module Initialize fails")
	}

	warnLogs := mock.GetLogs("warn")
	if len(warnLogs) == 0 {
		t.Fatal("expected a warn log for unregister-after-load-failure, got none")
	}

	found := false
	for i := 0; i+1 < len(warnLogs[0].Data); i += 2 {
		key, ok := warnLogs[0].Data[i].(string)
		if !ok || key != "error" {
			continue
		}
		found = true
		switch v := warnLogs[0].Data[i+1].(type) {
		case error:
			t.Fatalf("raw error value logged directly instead of a sanitized string: %v", v)
		case string:
			if containsRawCRLF(v) {
				t.Errorf("error value carries raw CR/LF, log-injection sink not sanitized: %q", v)
			}
			if strings.Contains(v, injected) {
				t.Errorf("error value equals unsanitized injected payload: %q", v)
			}
		default:
			t.Fatalf("unexpected type for \"error\" field: %#v", v)
		}
	}
	if !found {
		t.Fatal("expected an \"error\" key in the warn log fields")
	}
}
