// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules

import (
	"strings"
	"testing"
	"time"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

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
