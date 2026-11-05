// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/service"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// lockdownStore returns the real predicate over a real steward store, with
// "tampered-1" tampered and "normal-1" active.
func lockdownStore(t *testing.T) (*fleet.Lockdown, business.StewardStore) {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	for id, st := range map[string]business.StewardStatus{
		"tampered-1": business.StewardStatusTampered,
		"normal-1":   business.StewardStatusActive,
	} {
		require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
			ID: id, TenantID: "default", Hostname: id, Platform: "linux", Status: st,
			RegisteredAt: time.Now(), LastSeen: time.Now(),
		}))
	}
	return fleet.NewLockdown(store, logging.NewNoopLogger()), store
}

func requireLockedDown(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, controlplaneInterfaces.IsLockedDown(err), "refusal must carry the typed lockdown detail, got %v", err)
}

// ---------------------------------------------------------------------------
// SyncConfig
// ---------------------------------------------------------------------------

func TestSyncConfig_Lockdown(t *testing.T) {
	ld, _ := lockdownStore(t)
	ca := newTestCA(t)
	svc := createTestService(t)
	ctrl := service.NewControllerService(logging.NewNoopLogger())
	for _, id := range []string{"tampered-1", "normal-1"} {
		require.NoError(t, ctrl.RegisterSteward(id, "default", "localhost:4433", "connected"))
		require.NoError(t, svc.SetConfiguration(ctxkeys.WithSystem(context.Background()), "default", id, minimalStewardConfig(id)))
	}
	h := NewConfigHandler(svc, logging.NewNoopLogger(), newTestSignerFromCA(t, ca)).
		WithControllerService(ctrl).WithLockdown(ld)

	t.Run("tampered steward is refused with the typed error and sent nothing", func(t *testing.T) {
		stream := &testConfigStream{}
		err := h.HandleGRPC(peerContextWithCA(t, ca, "tampered-1"), &transportpb.ConfigSyncRequest{StewardId: "tampered-1"}, stream)
		requireLockedDown(t, err)
		assert.Empty(t, stream.chunks)
	})

	t.Run("normal steward succeeds", func(t *testing.T) {
		stream := &testConfigStream{}
		require.NoError(t, h.HandleGRPC(peerContextWithCA(t, ca, "normal-1"), &transportpb.ConfigSyncRequest{StewardId: "normal-1"}, stream))
		assert.NotEmpty(t, stream.chunks)
	})

	t.Run("body naming another steward neither bypasses nor triggers the gate", func(t *testing.T) {
		// Tampered peer naming a normal steward: refused, never served.
		stream := &testConfigStream{}
		err := h.HandleGRPC(peerContextWithCA(t, ca, "tampered-1"), &transportpb.ConfigSyncRequest{StewardId: "normal-1"}, stream)
		require.Error(t, err)
		assert.Empty(t, stream.chunks)
		// Normal peer naming the tampered steward: refused as a mismatch, not served.
		stream = &testConfigStream{}
		err = h.HandleGRPC(peerContextWithCA(t, ca, "normal-1"), &transportpb.ConfigSyncRequest{StewardId: "tampered-1"}, stream)
		require.Error(t, err)
		assert.Empty(t, stream.chunks)
	})

	t.Run("unknown steward fails closed", func(t *testing.T) {
		stream := &testConfigStream{}
		err := h.HandleGRPC(peerContextWithCA(t, ca, "ghost-1"), &transportpb.ConfigSyncRequest{StewardId: "ghost-1"}, stream)
		requireLockedDown(t, err)
		assert.Empty(t, stream.chunks)
	})
}

// ---------------------------------------------------------------------------
// FetchModuleBundle
// ---------------------------------------------------------------------------

func TestFetchModuleBundle_Lockdown(t *testing.T) {
	ld, _ := lockdownStore(t)
	f := newModuleFixture(t)
	f.h.WithLockdown(ld)
	f.ingest(testutil.BundleOptions{Version: "1.0.0"}, true)
	f.steward("tampered-1", "tenant-x", requireWidget)
	f.steward("normal-1", "tenant-x", requireWidget)

	st, err := f.fetch("tampered-1", req("1.0.0", "linux-amd64"))
	requireLockedDown(t, err)
	assert.Empty(t, st.chunks, "a tampered steward receives no bundle byte")

	st, err = f.fetch("normal-1", req("1.0.0", "linux-amd64"))
	require.NoError(t, err)
	assert.NotEmpty(t, st.chunks)
}

// ---------------------------------------------------------------------------
// IssueInitialCredential (secret material)
// ---------------------------------------------------------------------------

func TestIssueInitialCredential_Lockdown(t *testing.T) {
	ld, _ := lockdownStore(t)
	f := newCredFixture(t)
	f.h.WithLockdown(ld)
	f.steward("tampered-1", "tenant-x", "alice")
	f.steward("normal-1", "tenant-x", "alice")

	_, err := f.issue("tampered-1", "alice")
	requireLockedDown(t, err)
	pw, err := f.issue("normal-1", "alice")
	require.NoError(t, err)
	assert.Len(t, pw, credentials.PasswordLength)
}

// ---------------------------------------------------------------------------
// BulkTransfer: uploads stay open, controller-to-steward chunks are refused
// ---------------------------------------------------------------------------

func TestBulkTransfer_Lockdown(t *testing.T) {
	ld, _ := lockdownStore(t)
	ca := newTestCA(t)
	h := NewBulkHandler(logging.NewNoopLogger(), NewTenantQueue()).WithLockdown(ld)
	upload := &transportpb.BulkChunk{TransferId: "report-1", Data: []byte("report"), TotalSize: 6, IsLast: true}

	t.Run("tampered steward upload is accepted", func(t *testing.T) {
		stream := newTestBulkStream(peerContextWithCA(t, ca, "tampered-1"), upload)
		require.NoError(t, h.HandleGRPC(stream))
		assert.Empty(t, stream.outChunks)
	})

	t.Run("controller-to-steward chunk is refused for a tampered steward", func(t *testing.T) {
		inner := newTestBulkStream(peerContextWithCA(t, ca, "tampered-1"))
		gated := &gatedBulkStream{BidiStreamingServer: inner, checker: ld, stewardID: "tampered-1"}
		requireLockedDown(t, gated.Send(&transportpb.BulkChunk{TransferId: "pkg-1", Data: []byte("x")}))
		assert.Empty(t, inner.outChunks, "nothing reaches the endpoint")
	})

	t.Run("HandleGRPC installs the gate on the stream handed to the send path", func(t *testing.T) {
		var sendErr error
		hd := NewBulkHandler(logging.NewNoopLogger(), NewTenantQueue()).WithLockdown(ld)
		hd.downstream = func(s grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
			sendErr = s.Send(&transportpb.BulkChunk{TransferId: "pkg-1", Data: []byte("x")})
			return nil
		}
		inner := newTestBulkStream(peerContextWithCA(t, ca, "tampered-1"))
		require.NoError(t, hd.HandleGRPC(inner))
		requireLockedDown(t, sendErr)
		assert.Empty(t, inner.outChunks)

		inner = newTestBulkStream(peerContextWithCA(t, ca, "normal-1"))
		require.NoError(t, hd.HandleGRPC(inner))
		require.NoError(t, sendErr)
		assert.Len(t, inner.outChunks, 1)
	})

	t.Run("controller-to-steward chunk reaches a normal steward", func(t *testing.T) {
		inner := newTestBulkStream(peerContextWithCA(t, ca, "normal-1"))
		gated := &gatedBulkStream{BidiStreamingServer: inner, checker: ld, stewardID: "normal-1"}
		require.NoError(t, gated.Send(&transportpb.BulkChunk{TransferId: "pkg-1", Data: []byte("x")}))
		assert.Len(t, inner.outChunks, 1)
	})

	t.Run("lookup failure refuses the downstream chunk", func(t *testing.T) {
		inner := newTestBulkStream(peerContextWithCA(t, ca, "normal-1"))
		gated := &gatedBulkStream{BidiStreamingServer: inner, checker: failingChecker{}, stewardID: "normal-1"}
		requireLockedDown(t, gated.Send(&transportpb.BulkChunk{}))
	})
}

type failingChecker struct{}

func (failingChecker) IsLockedDown(context.Context, string) (bool, error) {
	return true, errors.New("store unavailable")
}

// ---------------------------------------------------------------------------
// Telemetry: inbound open, downstream TelemetryRequest operator-only
// ---------------------------------------------------------------------------

func TestTelemetry_Lockdown(t *testing.T) {
	ld, _ := lockdownStore(t)
	ca := newTestCA(t)

	t.Run("inbound snapshot from a tampered steward is accepted", func(t *testing.T) {
		h := NewTelemetryHandler(logging.NewNoopLogger(), nil).WithLockdown(ld)
		ctx, cancel := context.WithTimeout(peerContextWithCA(t, ca, "tampered-1"), 5*time.Second)
		defer cancel()
		stream := newTestTelemetryStream(ctx)
		wait := startHandleGRPC(t, h, stream)
		_, ch, _ := h.addSubscriber("tampered-1")
		stream.recvCh <- &transportpb.TelemetrySnapshot{}
		select {
		case msg := <-ch:
			assert.NotNil(t, msg.snap, "the snapshot is fanned out")
		case <-time.After(2 * time.Second):
			t.Fatal("snapshot from a tampered steward was not accepted")
		}
		close(stream.recvCh)
		require.NoError(t, wait())
	})

	serve := func(h *TelemetryHandler, stewardID string, ctx context.Context) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/telemetry/ws/"+stewardID, nil).WithContext(ctx)
		r = mux.SetURLVars(r, map[string]string{"id": stewardID})
		rec := httptest.NewRecorder()
		h.ServeWebSocket(rec, r)
		return rec
	}

	t.Run("subscription to a tampered steward without the operator marker is refused", func(t *testing.T) {
		h := NewTelemetryHandler(logging.NewNoopLogger(), nil).WithLockdown(ld)
		rec := serve(h, "tampered-1", context.Background())
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "locked down")
		assert.Empty(t, h.stewards["tampered-1"], "no subscriber is registered")
	})

	t.Run("subscription with the operator marker is allowed", func(t *testing.T) {
		h := NewTelemetryHandler(logging.NewNoopLogger(), nil).WithLockdown(ld)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = mux.SetURLVars(r.WithContext(commands.NewOperatorOrigin(r.Context(), "operator-1")), map[string]string{"id": "tampered-1"})
			h.ServeWebSocket(w, r)
		}))
		defer srv.Close()
		hdr := http.Header{"Origin": []string{srv.URL}}
		conn, resp, err := websocket.DefaultDialer.Dial("ws"+srv.URL[len("http"):], hdr)
		require.NoError(t, err)
		defer conn.Close() //nolint:errcheck // test cleanup
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	})

	t.Run("subscription to a normal steward needs no marker", func(t *testing.T) {
		h := NewTelemetryHandler(logging.NewNoopLogger(), nil).WithLockdown(ld)
		rec := serve(h, "normal-1", context.Background())
		assert.NotContains(t, rec.Body.String(), "locked down")
	})

	t.Run("browsers waiting before a steward was tampered are not sent a subscribe", func(t *testing.T) {
		h := NewTelemetryHandler(logging.NewNoopLogger(), nil).WithLockdown(ld)
		h.addSubscriber("tampered-1")
		ctx, cancel := context.WithTimeout(peerContextWithCA(t, ca, "tampered-1"), 5*time.Second)
		defer cancel()
		stream := newTestTelemetryStream(ctx)
		close(stream.recvCh)
		require.NoError(t, h.HandleGRPC(stream))
		assert.Empty(t, stream.getSent())
	})
}
