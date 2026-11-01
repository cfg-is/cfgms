// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Internal (package telemetry, not telemetry_test) so this test can reach
// Tracer's unexported provider field to attach an in-memory span recorder —
// the public Initialize/Config surface has no exporter injection point.
package telemetry

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestTracerStart_SanitizesOperationNameInSpan is the required log-injection
// regression test for pkg/telemetry (Issue #4341). Tracer.Start uses its
// caller-supplied operationName both as the exported span's name and as the
// "cfgms.operation" span attribute. A caller-influenced operation name
// carrying CR/LF would otherwise reach exported traces (and any log sink
// that later renders them) unsanitized — the same CWE-117 shape CLAUDE.md's
// log-sanitization rule targets for logger calls, applied here to trace
// attributes per this story's scope note.
func TestTracerStart_SanitizesOperationNameInSpan(t *testing.T) {
	ctx := context.Background()
	tracer, cleanup, err := Initialize(ctx, &Config{
		ServiceName: "test-service",
		Enabled:     true,
		SampleRate:  1.0, // full sampling — a fractional/zero rate would drop the span before export
	})
	require.NoError(t, err)
	defer cleanup()

	exporter := tracetest.NewInMemoryExporter()
	require.NotNil(t, tracer.provider, "tracer must hold a real SDK provider when Enabled=true")
	tracer.provider.RegisterSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter))

	const maliciousOperationName = "steward.register\r\nINJECTED: fake log line\nlevel=error msg=forged"

	_, span := tracer.Start(ctx, maliciousOperationName)
	span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	got := spans[0]
	assert.NotContains(t, got.Name, "\r")
	assert.NotContains(t, got.Name, "\n")

	foundOperationAttr := false
	for _, kv := range got.Attributes {
		if string(kv.Key) != "cfgms.operation" {
			continue
		}
		foundOperationAttr = true
		v := kv.Value.AsString()
		assert.NotContains(t, v, "\r", "cfgms.operation span attribute must not carry a raw CR")
		assert.NotContains(t, v, "\n", "cfgms.operation span attribute must not carry a raw LF")
	}
	assert.True(t, foundOperationAttr, "expected a cfgms.operation span attribute")
}

// TestAttributeString_Sanitizes verifies the public AttributeString helper —
// documented as the way callers attach caller/peer-influenced identity
// values (steward.id, tenant.id) to a span — strips CR/LF from its value
// before handing it to the OpenTelemetry attribute API.
func TestAttributeString_Sanitizes(t *testing.T) {
	kv := AttributeString("steward.id", "abc\r\nlevel=error msg=forged")
	v := kv.Value.AsString()
	assert.False(t, strings.ContainsAny(v, "\r\n"), "AttributeString must sanitize CR/LF, got %q", v)
}
