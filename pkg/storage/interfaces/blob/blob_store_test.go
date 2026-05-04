// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package blob

import (
	"context"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
)

// testLogEntry captures a single log call for assertions.
type testLogEntry struct {
	Message string
	Data    []interface{}
}

// testMockLogger captures log calls without importing pkg/testing (avoids import cycle).
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

// minimalBlobProvider is a minimal BlobProvider for testing the registry.
type minimalBlobProvider struct {
	name        string
	description string
	version     string
}

func (p *minimalBlobProvider) Name() string        { return p.name }
func (p *minimalBlobProvider) Description() string { return p.description }
func (p *minimalBlobProvider) GetVersion() string  { return p.version }
func (p *minimalBlobProvider) Available() (bool, error) {
	return true, nil
}
func (p *minimalBlobProvider) CreateBlobStore(_ map[string]interface{}) (BlobStore, error) {
	return nil, nil
}

func TestSetBlobLogger_routesThroughInjectedLogger(t *testing.T) {
	// Save and clear registry
	globalBlobRegistry.mutex.Lock()
	originalProviders := globalBlobRegistry.providers
	globalBlobRegistry.providers = make(map[string]BlobProvider)
	globalBlobRegistry.mutex.Unlock()

	defer func() {
		globalBlobRegistry.mutex.Lock()
		globalBlobRegistry.providers = originalProviders
		globalBlobRegistry.mutex.Unlock()
	}()

	mock := newTestMockLogger()
	SetBlobLogger(mock)
	defer SetBlobLogger(logging.NewNoopLogger())

	provider := &minimalBlobProvider{
		name:        "test",
		description: "test blob provider",
		version:     "1.0",
	}
	RegisterBlobProvider(provider)

	logs := mock.GetLogs("info")
	if len(logs) == 0 {
		t.Fatal("expected at least one info log entry after RegisterBlobProvider")
	}
	wantPrefix := "Registered blob provider: test v1.0"
	if logs[0].Message != wantPrefix {
		t.Errorf("unexpected log message: %q, want %q", logs[0].Message, wantPrefix)
	}
}

func TestRegisterBlobProvider_nilProvider_logsWarn(t *testing.T) {
	mock := newTestMockLogger()
	SetBlobLogger(mock)
	defer SetBlobLogger(logging.NewNoopLogger())

	RegisterBlobProvider(nil)

	logs := mock.GetLogs("warn")
	if len(logs) == 0 {
		t.Fatal("expected a warn log when registering nil blob provider")
	}
}

func TestRegisterBlobProvider_emptyName_logsWarn(t *testing.T) {
	mock := newTestMockLogger()
	SetBlobLogger(mock)
	defer SetBlobLogger(logging.NewNoopLogger())

	RegisterBlobProvider(&minimalBlobProvider{name: "", description: "d", version: "1.0"})

	logs := mock.GetLogs("warn")
	if len(logs) == 0 {
		t.Fatal("expected a warn log when registering blob provider with empty name")
	}
}

func TestRegisterBlobProvider_overwrite_logsWarn(t *testing.T) {
	globalBlobRegistry.mutex.Lock()
	originalProviders := globalBlobRegistry.providers
	globalBlobRegistry.providers = make(map[string]BlobProvider)
	globalBlobRegistry.mutex.Unlock()

	defer func() {
		globalBlobRegistry.mutex.Lock()
		globalBlobRegistry.providers = originalProviders
		globalBlobRegistry.mutex.Unlock()
	}()

	mock := newTestMockLogger()
	SetBlobLogger(mock)
	defer SetBlobLogger(logging.NewNoopLogger())

	provider := &minimalBlobProvider{name: "test", description: "d", version: "1.0"}
	RegisterBlobProvider(provider)

	updated := &minimalBlobProvider{name: "test", description: "d", version: "2.0"}
	RegisterBlobProvider(updated)

	warnLogs := mock.GetLogs("warn")
	if len(warnLogs) == 0 {
		t.Fatal("expected a warn log when overwriting an existing blob provider")
	}
}

func TestGetBlobProvider_notFound(t *testing.T) {
	globalBlobRegistry.mutex.Lock()
	originalProviders := globalBlobRegistry.providers
	globalBlobRegistry.providers = make(map[string]BlobProvider)
	globalBlobRegistry.mutex.Unlock()

	defer func() {
		globalBlobRegistry.mutex.Lock()
		globalBlobRegistry.providers = originalProviders
		globalBlobRegistry.mutex.Unlock()
	}()

	_, err := GetBlobProvider("nonexistent")
	if err == nil {
		t.Fatal("expected error when getting nonexistent blob provider")
	}
}

func TestCreateBlobStoreFromConfig_notFound(t *testing.T) {
	globalBlobRegistry.mutex.Lock()
	originalProviders := globalBlobRegistry.providers
	globalBlobRegistry.providers = make(map[string]BlobProvider)
	globalBlobRegistry.mutex.Unlock()

	defer func() {
		globalBlobRegistry.mutex.Lock()
		globalBlobRegistry.providers = originalProviders
		globalBlobRegistry.mutex.Unlock()
	}()

	_, err := CreateBlobStoreFromConfig("nonexistent", nil)
	if err == nil {
		t.Fatal("expected error when creating blob store from nonexistent provider")
	}
}

func TestUnregisterBlobProvider(t *testing.T) {
	globalBlobRegistry.mutex.Lock()
	originalProviders := globalBlobRegistry.providers
	globalBlobRegistry.providers = make(map[string]BlobProvider)
	globalBlobRegistry.mutex.Unlock()

	defer func() {
		globalBlobRegistry.mutex.Lock()
		globalBlobRegistry.providers = originalProviders
		globalBlobRegistry.mutex.Unlock()
	}()

	RegisterBlobProvider(&minimalBlobProvider{name: "test", description: "d", version: "1.0"})

	if !UnregisterBlobProvider("test") {
		t.Fatal("expected UnregisterBlobProvider to return true for existing provider")
	}
	if UnregisterBlobProvider("test") {
		t.Fatal("expected UnregisterBlobProvider to return false for already-removed provider")
	}
}
