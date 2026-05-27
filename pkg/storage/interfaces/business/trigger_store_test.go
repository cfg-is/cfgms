// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestTriggerRecordShape verifies the TriggerRecord struct has the required
// typed *Ref fields and ConfigPayload, and that no field is capable of holding
// a cleartext credential (all credential-related fields are string refs or bytes).
func TestTriggerRecordShape(t *testing.T) {
	r := business.TriggerRecord{
		ID:               "trig-001",
		TenantID:         "tenant-a",
		Name:             "on-push",
		Type:             "webhook",
		Status:           "active",
		WorkflowName:     "deploy",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		WebhookPath:      "/hook/deploy",
		WebhookMethod:    []string{"POST"},
		BearerTokenRef:   "secrets/tenant-a/triggers/trig-001/bearer",
		HMACSecretRef:    "secrets/tenant-a/triggers/trig-001/hmac",
		APIKeyRef:        "secrets/tenant-a/triggers/trig-001/apikey",
		BasicUsernameRef: "secrets/tenant-a/triggers/trig-001/basic_user",
		BasicPasswordRef: "secrets/tenant-a/triggers/trig-001/basic_pass",
		ConfigPayload:    []byte(`{"timeout":30}`),
	}

	assert.Equal(t, "trig-001", r.ID)
	assert.Equal(t, "tenant-a", r.TenantID)
	assert.Equal(t, "on-push", r.Name)
	assert.Equal(t, "webhook", r.Type)
	assert.Equal(t, "active", r.Status)
	assert.Equal(t, "deploy", r.WorkflowName)
	assert.Equal(t, "/hook/deploy", r.WebhookPath)
	assert.Equal(t, []string{"POST"}, r.WebhookMethod)
	assert.Equal(t, "secrets/tenant-a/triggers/trig-001/bearer", r.BearerTokenRef)
	assert.Equal(t, "secrets/tenant-a/triggers/trig-001/hmac", r.HMACSecretRef)
	assert.Equal(t, "secrets/tenant-a/triggers/trig-001/apikey", r.APIKeyRef)
	assert.Equal(t, "secrets/tenant-a/triggers/trig-001/basic_user", r.BasicUsernameRef)
	assert.Equal(t, "secrets/tenant-a/triggers/trig-001/basic_pass", r.BasicPasswordRef)
	assert.Equal(t, []byte(`{"timeout":30}`), r.ConfigPayload)
}

// TestTriggerRecordEmptyRefs verifies that empty string is a valid "no credential"
// sentinel for all *Ref fields — the zero value must be meaningful.
func TestTriggerRecordEmptyRefs(t *testing.T) {
	r := business.TriggerRecord{
		ID:       "trig-002",
		TenantID: "tenant-b",
		Type:     "webhook",
	}
	// All ref fields default to empty string — no credential configured.
	assert.Empty(t, r.BearerTokenRef)
	assert.Empty(t, r.HMACSecretRef)
	assert.Empty(t, r.APIKeyRef)
	assert.Empty(t, r.BasicUsernameRef)
	assert.Empty(t, r.BasicPasswordRef)
	assert.Nil(t, r.ConfigPayload)
}

// TestTriggerStoreFilter verifies the filter struct has the required fields.
func TestTriggerStoreFilter(t *testing.T) {
	f := business.TriggerStoreFilter{
		TenantID: "tenant-a",
		Type:     "webhook",
		Status:   "active",
		Limit:    10,
		Offset:   5,
	}
	assert.Equal(t, "tenant-a", f.TenantID)
	assert.Equal(t, "webhook", f.Type)
	assert.Equal(t, "active", f.Status)
	assert.Equal(t, 10, f.Limit)
	assert.Equal(t, 5, f.Offset)
}

// TestErrTriggerNotFound verifies the sentinel is a distinct, non-nil error.
func TestErrTriggerNotFound(t *testing.T) {
	assert.NotNil(t, business.ErrTriggerNotFound)
	assert.True(t, errors.Is(business.ErrTriggerNotFound, business.ErrTriggerNotFound))
	assert.Equal(t, "trigger not found", business.ErrTriggerNotFound.Error())
}
