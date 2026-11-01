// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// eventLogEntry is one captured log call.
type eventLogEntry struct {
	level string
	msg   string
	kv    []interface{}
}

// eventCapturingLogger records every log call so tests can inspect the field values.
type eventCapturingLogger struct {
	mu      sync.Mutex
	entries []eventLogEntry
}

func (l *eventCapturingLogger) record(level, msg string, kv ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, eventLogEntry{level: level, msg: msg, kv: kv})
}

func (l *eventCapturingLogger) Debug(msg string, kv ...interface{}) { l.record("DEBUG", msg, kv...) }
func (l *eventCapturingLogger) Info(msg string, kv ...interface{})  { l.record("INFO", msg, kv...) }
func (l *eventCapturingLogger) Warn(msg string, kv ...interface{})  { l.record("WARN", msg, kv...) }
func (l *eventCapturingLogger) Error(msg string, kv ...interface{}) { l.record("ERROR", msg, kv...) }
func (l *eventCapturingLogger) Fatal(msg string, kv ...interface{}) { l.record("FATAL", msg, kv...) }
func (l *eventCapturingLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("DEBUG", msg, kv...)
}
func (l *eventCapturingLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("INFO", msg, kv...)
}
func (l *eventCapturingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("WARN", msg, kv...)
}
func (l *eventCapturingLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("ERROR", msg, kv...)
}
func (l *eventCapturingLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record("FATAL", msg, kv...)
}

var _ logging.Logger = (*eventCapturingLogger)(nil)

// rendered returns each captured entry as it would appear on a single log line
// (message plus key=value fields), without any newline normalisation.
func (l *eventCapturingLogger) rendered(msgPrefix string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.entries {
		if !strings.HasPrefix(e.msg, msgPrefix) {
			continue
		}
		var sb strings.Builder
		sb.WriteString(e.msg)
		for i := 0; i+1 < len(e.kv); i += 2 {
			fmt.Fprintf(&sb, " %v=%v", e.kv[i], e.kv[i+1])
		}
		out = append(out, sb.String())
	}
	return out
}

func TestHandleEventFromProvider_UnhandledEventSanitizesLogFields(t *testing.T) {
	logger := &eventCapturingLogger{}
	s := &Server{logger: logger}

	event := &controlplaneTypes.Event{
		ID:        "evt-1\nINFO forged entry",
		Type:      controlplaneTypes.EventType("custom\rtype\nforged"),
		StewardID: "steward-1\nforged",
		Timestamp: time.Now(),
	}

	require.NoError(t, s.handleEventFromProvider(context.Background(), event))

	lines := logger.rendered("Received event from steward")
	require.Len(t, lines, 1)
	assert.NotContains(t, lines[0], "\n")
	assert.NotContains(t, lines[0], "\r")
	assert.Contains(t, lines[0], "evt-1")
}

func TestHandleDNAEvent_SanitizesEventIDInLog(t *testing.T) {
	logger := &eventCapturingLogger{}
	s := &Server{
		logger:            logger,
		controllerService: service.NewControllerService(logger),
	}

	event := &controlplaneTypes.Event{
		ID:        "dna-1\nINFO forged entry",
		Type:      controlplaneTypes.EventDNAChanged,
		StewardID: "steward-1\nforged",
		Timestamp: time.Now(),
	}

	// SyncDNA may reject the unknown steward; only the log output matters here.
	_ = s.handleEventFromProvider(context.Background(), event)

	lines := logger.rendered("Received DNA change event")
	require.Len(t, lines, 1)
	assert.NotContains(t, lines[0], "\n")
	assert.NotContains(t, lines[0], "\r")
	assert.Contains(t, lines[0], "dna-1")
}

func TestHandleConfigAppliedEvent_SanitizesEventFieldsInLog(t *testing.T) {
	logger := &eventCapturingLogger{}
	s := &Server{logger: logger}

	event := &controlplaneTypes.Event{
		ID:        "cfg-1\nforged",
		Type:      controlplaneTypes.EventConfigApplied,
		StewardID: "steward-1\nforged",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"config_version": "v1",
			"status":         "ok",
			"modules": map[string]interface{}{
				"file": map[string]interface{}{"status": "ok", "message": "done"},
			},
		},
	}

	require.NoError(t, s.handleEventFromProvider(context.Background(), event))

	for _, prefix := range []string{"Received config applied event", "Configuration status report", "Module status"} {
		lines := logger.rendered(prefix)
		require.Len(t, lines, 1, prefix)
		assert.NotContains(t, lines[0], "\n", prefix)
		assert.NotContains(t, lines[0], "\r", prefix)
	}
}
