// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLinkTimeoutReport_HasStacksAndLinkState drives the diagnostic helper
// directly: the report must carry an all-goroutine dump (including this
// goroutine's own test function) and the link state the roServer can observe.
func TestLinkTimeoutReport_HasStacksAndLinkState(t *testing.T) {
	srv := newROServer(t)
	srv.recordAdmission("1234", nil)
	srv.recordAdmission("5678", fmt.Errorf("client certificate 5678 is revoked"))

	report := linkTimeoutReport(srv)

	assert.Contains(t, report, "goroutine ", "the dump has goroutine headers")
	assert.Contains(t, report, "TestLinkTimeoutReport_HasStacksAndLinkState", "the dump includes the calling test")
	assert.Contains(t, report, "admission attempts: 2")
	assert.Contains(t, report, "1234")
	assert.Contains(t, report, "5678")
	assert.Contains(t, report, "registered stewards: 0")
	assert.Contains(t, report, "is revoked", "the last admission error is reported")
}

func TestLinkTimeoutReport_NoAdmissions(t *testing.T) {
	srv := newROServer(t)

	report := linkTimeoutReport(srv)

	assert.Contains(t, report, "admission attempts: 0")
	assert.Contains(t, report, "last admission error: none")
	require.Contains(t, report, "goroutine ")
}
