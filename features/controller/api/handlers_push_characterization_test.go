// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sqliteprovider "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	configstorewriter "github.com/cfgis/cfgms/pkg/entitygraph/writers/configstore"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for handleConfigPush (Issue #5873). They pin the
// externally visible behavior of each stage so the complexity refactor is
// provably behavior-preserving. Scenarios already pinned by handlers_push_test.go
// (empty selector, cross-tenant caller, selector prefix outside the subtree,
// subtree scoping) are not repeated; these cover the stages it leaves open.

// handlerspushCharDupCommandStore delegates to a real CommandStore but submits
// the last delivery record twice, so the real transaction fails on a duplicate
// primary key after the push record has been inserted.
type handlerspushCharDupCommandStore struct {
	business.CommandStore
}

func (c *handlerspushCharDupCommandStore) CreatePushAndCommandRecords(ctx context.Context, p *business.PushRecord, records []*business.CommandRecord) error {
	if len(records) > 0 {
		records = append(records, records[len(records)-1])
	}
	return c.CommandStore.CreatePushAndCommandRecords(ctx, p, records)
}

// handlerspushCharFailStatusCommandStore delegates to a real CommandStore but
// fails every delivery-status update.
type handlerspushCharFailStatusCommandStore struct {
	business.CommandStore
}

func (c *handlerspushCharFailStatusCommandStore) UpdateDeliveryStatus(_ context.Context, _ string, _ business.DeliveryStatus, _ string) error {
	return errors.New("status update failed")
}

func handlerspushCharPost(server *Server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	server.handleConfigPush(rec, req)
	return rec
}

func TestHandlersPushChar_MachinePrincipalWithoutTenant_401(t *testing.T) {
	server := setupTestServer(t)

	rec := handlerspushCharPost(server, withScopedPrincipal(newPushRequest(t, validPushPayload()), ""))

	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Equal(t, "AUTHENTICATION_REQUIRED", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersPushChar_RootCallerNeedsCrossing_403WithoutPushRecord(t *testing.T) {
	cp := &syncedControlPlane{}
	server, pushStore := makePushServerWithStore(t, cp)
	seedRootTenant(t, server)
	registerActiveSteward(t, server.controllerService, "handlerspush-char-cross", "tenant-abc")

	principal := rootScopedPrincipal("root-op")
	req := asRootOperator(newPushRequest(t, validPushPayload()), principal, nil)
	rec := handlerspushCharPost(server, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	pending, err := pushStore.GetPendingPushes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pending, "a refused crossing must not record a push")
	assert.Empty(t, cp.ReceivedIDs(), "a refused crossing must not fan out")
}

func TestHandlersPushChar_InvalidSelectorExpression_400(t *testing.T) {
	server := setupTestServer(t)
	body := validPushPayload()
	body.Selector = "bogus:value"

	rec := handlerspushCharPost(server, withAdminPrincipal(newPushRequest(t, body)))

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "unknown selector key")
}

func TestHandlersPushChar_MatchedSetFiltering_OnlyIntendedStewards(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithStore(t, cp)
	inScope := registerActiveSteward(t, server.controllerService, "handlerspush-char-in", "tenant-abc")
	registerActiveSteward(t, server.controllerService, "handlerspush-char-other", "tenant-other")
	registerActiveSteward(t, server.controllerService, "handlerspush-char-sibling", "tenant-abc-sibling")
	cp.wg.Add(1)

	rec := handlerspushCharPost(server, withAdminPrincipal(newPushRequest(t, validPushPayload())))
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	cp.wg.Wait()

	assert.ElementsMatch(t, []string{inScope}, cp.ReceivedIDs())
}

func TestHandlersPushChar_NoMatchedStewards_AcceptedWithEmptyDeliveries(t *testing.T) {
	cp := &syncedControlPlane{}
	server, commandStore := makePushServerWithCommandStore(t, cp)
	_ = commandStore

	rec := handlerspushCharPost(server, withAdminPrincipal(newPushRequest(t, validPushPayload())))

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "accepted", resp.Status)
	assert.NotEmpty(t, resp.PushID)
	assert.Empty(t, resp.Deliveries)
}

func TestHandlersPushChar_DeliveryRowWriteFailure_LeavesNoPushRecord(t *testing.T) {
	cp := &syncedControlPlane{}
	server, commandStore := makePushServerWithCommandStore(t, cp)
	server.SetCommandStore(&handlerspushCharDupCommandStore{CommandStore: commandStore})
	payload := validPushPayload()
	registerActiveSteward(t, server.controllerService, "handlerspush-char-atomic-a", payload.TenantID)
	registerActiveSteward(t, server.controllerService, "handlerspush-char-atomic-b", payload.TenantID)
	cp.wg.Add(2)

	rec := handlerspushCharPost(server, withScopedPrincipal(newPushRequest(t, payload), payload.TenantID))

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Empty(t, resp.Deliveries, "a failed transaction must not advertise delivery records")
	cp.wg.Wait()
	assert.Len(t, cp.ReceivedIDs(), 2, "best-effort fan-out still runs after the durable write fails")

	_, err := server.pushStore.GetPush(context.Background(), resp.PushID)
	assert.ErrorIs(t, err, business.ErrPushNotFound, "the push record must roll back with the delivery rows")
}

func TestHandlersPushChar_EntityGraphWriteFailure_DoesNotBlockPush(t *testing.T) {
	cp := &syncedControlPlane{}
	server, commandStore := makePushServerWithCommandStore(t, cp)
	p, err := sqliteprovider.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"))
	require.NoError(t, err)
	w, err := configstorewriter.New(p)
	require.NoError(t, err)
	require.NoError(t, p.Close())
	server.SetConfigStoreWriter(w)
	payload := validPushPayload()
	registerActiveSteward(t, server.controllerService, "handlerspush-char-eg", payload.TenantID)
	cp.wg.Add(1)

	rec := handlerspushCharPost(server, withScopedPrincipal(newPushRequest(t, payload), payload.TenantID))

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	cp.wg.Wait()
	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Deliveries, 1)
	_, err = commandStore.GetCommandRecord(context.Background(), resp.Deliveries[0].CommandID)
	require.NoError(t, err)
	pushRec, err := server.pushStore.GetPush(context.Background(), resp.PushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusCompleted, pushRec.Status)
}

func TestHandlersPushChar_DeliveryStatusUpdateFailure_DoesNotBlockPush(t *testing.T) {
	cp := &syncedControlPlane{}
	server, commandStore := makePushServerWithCommandStore(t, cp)
	server.SetCommandStore(&handlerspushCharFailStatusCommandStore{CommandStore: commandStore})
	payload := validPushPayload()
	registerActiveSteward(t, server.controllerService, "handlerspush-char-status", payload.TenantID)
	cp.wg.Add(1)

	rec := handlerspushCharPost(server, withScopedPrincipal(newPushRequest(t, payload), payload.TenantID))

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	cp.wg.Wait()
	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Deliveries, 1)
	assert.Equal(t, string(business.DeliveryStatusPending), resp.Deliveries[0].Status,
		"a failed status write leaves the response row pending")
}

func TestHandlersPushChar_PushRecordCarriesPrincipalAndPayload(t *testing.T) {
	cp := &syncedControlPlane{}
	server, _ := makePushServerWithCommandStore(t, cp)
	payload := validPushPayload()
	payload.Policies = map[string]interface{}{"k": "v"}
	steward := registerActiveSteward(t, server.controllerService, "handlerspush-char-record", payload.TenantID)
	cp.wg.Add(1)

	rec := handlerspushCharPost(server, withScopedPrincipal(newPushRequest(t, payload), payload.TenantID))
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	cp.wg.Wait()

	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	pushRec, err := server.pushStore.GetPush(context.Background(), resp.PushID)
	require.NoError(t, err)
	assert.Equal(t, "api-key:"+payload.TenantID, pushRec.InitiatedBy)
	assert.Equal(t, payload.ConfigID, pushRec.ConfigID)
	assert.Equal(t, payload.TenantID, pushRec.TenantID)
	assert.Equal(t, payload.Version, pushRec.Version)
	assert.Equal(t, []string{steward}, pushRec.TargetStewardIDs)
}

func TestHandlersPushChar_FailedDeliveryStatusWriteFailure_DoesNotBlockPush(t *testing.T) {
	cp := &failingControlPlane{sendErr: errors.New("simulated delivery failure")}
	server, commandStore := makePushServerWithCommandStore(t, cp)
	server.SetCommandStore(&handlerspushCharFailStatusCommandStore{CommandStore: commandStore})
	payload := validPushPayload()
	registerActiveSteward(t, server.controllerService, "handlerspush-char-failstatus", payload.TenantID)
	cp.wg.Add(1)

	rec := handlerspushCharPost(server, withScopedPrincipal(newPushRequest(t, payload), payload.TenantID))

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var resp ConfigPushResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Deliveries, 1)
	assert.Equal(t, string(business.DeliveryStatusPending), resp.Deliveries[0].Status)
	pushRec, err := server.pushStore.GetPush(context.Background(), resp.PushID)
	require.NoError(t, err)
	assert.Equal(t, business.PushStatusFailed, pushRec.Status)
}
