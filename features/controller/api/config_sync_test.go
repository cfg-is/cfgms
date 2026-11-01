// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyncStewardConfig_PublishesUnderRecordID proves the effective-config sync
// sends its command under the delivery record's ID (Issue #4865).
func TestSyncStewardConfig_PublishesUnderRecordID(t *testing.T) {
	cp := &syncedControlPlane{}
	server, commandStore := makePushServerWithCommandStore(t, cp)
	cp.wg.Add(1)

	server.syncStewardConfig(context.Background(), "steward-sync-1", "tenant-test", "tester")

	records, err := commandStore.ListCommandsByDevice(context.Background(), "steward-sync-1")
	require.NoError(t, err)
	var ids []string
	for _, r := range records {
		if strings.HasPrefix(r.ID, "cfg-effective-") {
			ids = append(ids, r.ID)
		}
	}
	require.Len(t, ids, 1)
	assert.Equal(t, ids[0], cp.CommandIDFor("steward-sync-1"))
}

// TestHandleUpdateStewardConfig_PublishesUnderRecordID proves a config upload
// returns a command_id equal to the Command.ID the steward received.
func TestHandleUpdateStewardConfig_PublishesUnderRecordID(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithCommandStore(t, cp)
	// The upload sends one command under the delivery record ID, and the
	// save=deploy fan-out sends a second under a generated ID.
	cp.wg.Add(2)

	payload := validPushPayload()
	stewardID := registerActiveSteward(t, server.controllerService, "upd-dna-1", payload.TenantID)

	body := requiredModulesValidCfgBody(t, stewardID, nil)
	req := httptest.NewRequest("PUT", "/api/v1/stewards/"+stewardID+"/config", bytes.NewReader(body))
	req = mux.SetURLVars(withScopedPrincipal(req, payload.TenantID), map[string]string{"id": stewardID})
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	commandID, _ := resp.Data["command_id"].(string)
	require.NotEmpty(t, commandID)
	assert.Contains(t, cp.CommandIDsFor(stewardID), commandID)
}
