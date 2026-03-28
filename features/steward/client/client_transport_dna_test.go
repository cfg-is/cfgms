// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client_test exercises the DNA-sync logic in TransportClient.
//
// These tests cover the pure, non-networked functions (delta computation,
// hash tracking) and the Heartbeat DNAHash field contract.
package client

import (
	"context"
	"testing"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger(t *testing.T) logging.Logger {
	t.Helper()
	return logging.NewLogger("debug")
}

// ---------------------------------------------------------------------------
// computeDelta
// ---------------------------------------------------------------------------

func TestComputeDelta_NilOld(t *testing.T) {
	newAttrs := map[string]string{"a": "1", "b": "2"}
	delta := computeDelta(nil, newAttrs)
	require.NotNil(t, delta)
	assert.Equal(t, newAttrs, delta,
		"when no previous state exists all attributes are included in the delta")
}

func TestComputeDelta_EmptyOld(t *testing.T) {
	newAttrs := map[string]string{"a": "1"}
	delta := computeDelta(map[string]string{}, newAttrs)
	assert.Equal(t, newAttrs, delta,
		"when previous state is empty all attributes are included in the delta")
}

func TestComputeDelta_NoChanges(t *testing.T) {
	attrs := map[string]string{"a": "1", "b": "2"}
	same := map[string]string{"a": "1", "b": "2"}
	delta := computeDelta(attrs, same)
	assert.Empty(t, delta, "identical attributes should produce an empty delta")
}

func TestComputeDelta_ChangedValue(t *testing.T) {
	old := map[string]string{"a": "1", "b": "old"}
	new := map[string]string{"a": "1", "b": "new"}
	delta := computeDelta(old, new)
	assert.Equal(t, map[string]string{"b": "new"}, delta,
		"only the changed attribute should appear in the delta")
}

func TestComputeDelta_AddedKey(t *testing.T) {
	old := map[string]string{"a": "1"}
	new := map[string]string{"a": "1", "b": "2"}
	delta := computeDelta(old, new)
	assert.Equal(t, map[string]string{"b": "2"}, delta,
		"newly added keys should appear in the delta")
}

func TestComputeDelta_MultipleChanges(t *testing.T) {
	old := map[string]string{"a": "1", "b": "2", "c": "3"}
	new := map[string]string{"a": "99", "b": "2", "c": "99"}
	delta := computeDelta(old, new)
	assert.Equal(t, map[string]string{"a": "99", "c": "99"}, delta)
}

func TestComputeDelta_IsolatesNewMap(t *testing.T) {
	old := map[string]string{}
	new := map[string]string{"k": "v"}
	delta := computeDelta(old, new)
	// Mutating delta must not affect new
	delta["extra"] = "injected"
	assert.NotContains(t, new, "extra",
		"delta should be an independent copy, not the same map reference")
}

// ---------------------------------------------------------------------------
// copyStringMap
// ---------------------------------------------------------------------------

func TestCopyStringMap_Nil(t *testing.T) {
	result := copyStringMap(nil)
	assert.Nil(t, result)
}

func TestCopyStringMap_Empty(t *testing.T) {
	result := copyStringMap(map[string]string{})
	require.NotNil(t, result)
	assert.Empty(t, result)
}

func TestCopyStringMap_DeepCopy(t *testing.T) {
	original := map[string]string{"k": "v"}
	copy := copyStringMap(original)
	assert.Equal(t, original, copy)
	// Mutate the copy — original must be unaffected
	copy["k"] = "changed"
	assert.Equal(t, "v", original["k"], "copyStringMap must return an independent copy")
}

// ---------------------------------------------------------------------------
// PublishDNAUpdate error paths
// ---------------------------------------------------------------------------

// newMinimalClient builds a TransportClient with no network connections for
// unit-testing state-only and error-path behaviour.
func newMinimalClient(t *testing.T) *TransportClient {
	t.Helper()
	c := &TransportClient{
		heartbeatStop:    make(chan struct{}),
		convergenceStop:  make(chan struct{}),
		convergeInterval: 30 * time.Minute,
		logger:           newTestLogger(t),
	}
	return c
}

func TestPublishDNAUpdate_ErrorNotRegistered(t *testing.T) {
	c := newMinimalClient(t)
	// stewardID is empty — not registered
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err == nil {
		t.Fatal("expected error when steward is not registered")
	}
	if err.Error() != "not registered" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func TestPublishDNAUpdate_ErrorControlPlaneNil(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	// controlPlane is nil — not connected
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	if err == nil {
		t.Fatal("expected error when control plane is not connected")
	}
	if err.Error() != "control plane not connected" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

func TestPublishDNAUpdate_NoDeltaSkipsPublish(t *testing.T) {
	c := newMinimalClient(t)
	c.stewardID = "steward-1"
	c.tenantID = "tenant-1"
	// Seed state so delta is empty on second call.
	c.dnaMu.Lock()
	c.lastPublishedDNA = map[string]string{"k": "v"}
	c.currentDNAHash = "some-hash"
	c.dnaMu.Unlock()

	// controlPlane is nil but delta should be empty, so we never reach the publish call.
	// The function returns nil (not an error) when no delta is detected.
	err := c.PublishDNAUpdate(context.TODO(), map[string]string{"k": "v"}, "", "")
	// We do NOT reach the "control plane not connected" error because the early
	// return for empty delta fires first.
	if err != nil {
		t.Fatalf("expected nil error when delta is empty, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Heartbeat.DNAHash field contract
// ---------------------------------------------------------------------------

func TestHeartbeat_DNAHashField(t *testing.T) {
	hb := &cpTypes.Heartbeat{
		StewardID: "steward-1",
		TenantID:  "tenant-1",
		Status:    cpTypes.StatusHealthy,
		DNAHash:   "abc123",
	}
	assert.Equal(t, "abc123", hb.DNAHash,
		"Heartbeat.DNAHash must be readable after assignment")
}

func TestHeartbeat_DNAHashOmitempty(t *testing.T) {
	hb := &cpTypes.Heartbeat{StewardID: "s1", Status: cpTypes.StatusHealthy}
	assert.Empty(t, hb.DNAHash, "DNAHash must default to empty string")
}
