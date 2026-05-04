// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
)

// testLogEntry captures a single log call for test assertions.
type testLogEntry struct {
	Message string
	Data    []interface{}
}

// testMockLogger captures log calls for assertion without importing pkg/testing
// (which would create an import cycle via pkg/testing → pkg/audit → pkg/secrets/interfaces).
type testMockLogger struct {
	mu   sync.Mutex
	logs map[string][]testLogEntry
}

func newTestMockLogger() *testMockLogger {
	return &testMockLogger{logs: map[string][]testLogEntry{
		"debug": {}, "info": {}, "warn": {}, "error": {}, "fatal": {},
	}}
}

func (l *testMockLogger) record(level, msg string, kv []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs[level] = append(l.logs[level], testLogEntry{Message: msg, Data: kv})
}

func (l *testMockLogger) GetLogs(level string) []testLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logs[level]
}

func (l *testMockLogger) Debug(msg string, kv ...interface{}) { l.record("debug", msg, kv) }
func (l *testMockLogger) Info(msg string, kv ...interface{})  { l.record("info", msg, kv) }
func (l *testMockLogger) Warn(msg string, kv ...interface{})  { l.record("warn", msg, kv) }
func (l *testMockLogger) Error(msg string, kv ...interface{}) { l.record("error", msg, kv) }
func (l *testMockLogger) Fatal(msg string, kv ...interface{}) { l.record("fatal", msg, kv) }
func (l *testMockLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("debug", msg, kv)
}
func (l *testMockLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("info", msg, kv)
}
func (l *testMockLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("warn", msg, kv)
}
func (l *testMockLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("error", msg, kv)
}
func (l *testMockLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("fatal", msg, kv)
}

var _ logging.Logger = (*testMockLogger)(nil)

// mockSecretProvider is a minimal SecretProvider for testing the registry.
type mockSecretProvider struct {
	name        string
	description string
	version     string
	available   bool
}

func (m *mockSecretProvider) Name() string        { return m.name }
func (m *mockSecretProvider) Description() string { return m.description }
func (m *mockSecretProvider) GetVersion() string  { return m.version }
func (m *mockSecretProvider) Available() (bool, error) {
	return m.available, nil
}
func (m *mockSecretProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{}
}
func (m *mockSecretProvider) CreateSecretStore(_ map[string]interface{}) (SecretStore, error) {
	return nil, nil
}

func TestRegisterSecretsProvider_routesThroughInjectedLogger(t *testing.T) {
	// Save and clear registry
	originalProviders := make(map[string]SecretProvider)
	globalRegistry.mutex.RLock()
	for name, provider := range globalRegistry.providers {
		originalProviders[name] = provider
	}
	globalRegistry.mutex.RUnlock()

	globalRegistry.mutex.Lock()
	globalRegistry.providers = make(map[string]SecretProvider)
	globalRegistry.mutex.Unlock()

	defer func() {
		globalRegistry.mutex.Lock()
		globalRegistry.providers = originalProviders
		globalRegistry.mutex.Unlock()
	}()

	mock := newTestMockLogger()
	SetSecretsLogger(mock)
	defer SetSecretsLogger(logging.NewNoopLogger())

	testProvider := &mockSecretProvider{
		name:        "test",
		description: "test provider",
		version:     "1.0",
		available:   true,
	}
	RegisterSecretProvider(testProvider)

	logs := mock.GetLogs("info")
	if len(logs) == 0 {
		t.Fatal("expected at least one info log entry after RegisterSecretProvider")
	}
	if logs[0].Message != "Registered secrets provider: test v1.0" {
		t.Errorf("unexpected log message: %q", logs[0].Message)
	}
}

func TestSetSecretsLogger_replacesDefault(t *testing.T) {
	mock := newTestMockLogger()
	SetSecretsLogger(mock)
	defer SetSecretsLogger(logging.NewNoopLogger())

	getSecretsLogger().Warn("test warn message")
	logs := mock.GetLogs("warn")
	if len(logs) == 0 {
		t.Fatal("expected warn log to be captured by injected logger")
	}
	if logs[0].Message != "test warn message" {
		t.Errorf("unexpected message: %q", logs[0].Message)
	}
}
