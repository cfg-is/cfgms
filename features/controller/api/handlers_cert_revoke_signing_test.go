// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// sharedStoreCertManager builds a Manager on the shared test CA whose revocation
// and signing-cursor stores are the ones passed in, so two Managers built with
// the same stores behave as two controller nodes of one cluster.
func sharedStoreCertManager(t *testing.T, rev certinterfaces.RevocationStore, cur certinterfaces.SigningCursorStore) *cert.Manager {
	t.Helper()
	path := t.TempDir()
	seedSharedTestCA(t, path)
	m, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:        path,
		LoadExistingCA:     true,
		RevocationStore:    rev,
		SigningCursorStore: cur,
	})
	require.NoError(t, err)
	return m
}

type revokeFixture struct {
	server   *Server
	mgrA     *cert.Manager
	mgrB     *cert.Manager
	audit    *audit.Manager
	rotated  *cert.Certificate // the superseded signing certificate (rotating serial)
	current  *cert.Certificate
	stewards map[string]chan *types.SignedCommand
}

func newRevokeFixture(t *testing.T) *revokeFixture {
	t.Helper()
	setTestSecretsEnv(t)
	shared := t.TempDir()
	rev, err := cert.NewFileRevocationStore(shared)
	require.NoError(t, err)
	cur, err := cert.NewFileSigningCursorStore(shared)
	require.NoError(t, err)

	mgrA := sharedStoreCertManager(t, rev, cur)
	ensureSharedSigningCertificate(t, mgrA)
	mgrB := sharedStoreCertManager(t, rev, cur)

	server, rotationSvc, auditMgr := setupRotationTestServerWith(t, mgrA)

	// One connected steward, reachable through a real in-process control plane.
	ctx := context.Background()
	bus := memory.NewBus()
	cp := memory.New(memory.ModeServer)
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(func() { _ = cp.Stop(context.Background()) })

	controllerSvc := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, controllerSvc.RegisterSteward("steward-1", "root", "", "active"))
	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-1"}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	ch := make(chan *types.SignedCommand, 8)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-1", func(_ context.Context, sc *types.SignedCommand) error {
		ch <- sc
		return nil
	}))

	publisher, err := commands.New(&commands.Config{ControlPlane: cp, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	rotationSvc.SetPublisher(publisher)
	rotationSvc.SetControllerService(controllerSvc)
	retire := service.NewSigningRetirementService(rotationSvc, nil, logging.NewNoopLogger())
	server.SetSigningRetirementService(retire)

	// Two rotations so the first rotated-out certificate is the cursor's rotating
	// serial with its overlap window still open.
	rootCtx := context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
	first, err := rotationSvc.Rotate(rootCtx, "setup", 30, true)
	require.NoError(t, err)
	second, err := rotationSvc.Rotate(rootCtx, "setup", 30, true)
	require.NoError(t, err)
	drain(ch)

	cursor, err := mgrA.GetSigningCursorState()
	require.NoError(t, err)
	require.Equal(t, first.NewSerial, cursor.RotatingSerial)
	require.Equal(t, second.NewSerial, cursor.CurrentSerial)

	return &revokeFixture{
		server: server, mgrA: mgrA, mgrB: mgrB, audit: auditMgr,
		rotated:  &cert.Certificate{SerialNumber: first.NewSerial},
		current:  &cert.Certificate{SerialNumber: second.NewSerial},
		stewards: map[string]chan *types.SignedCommand{"steward-1": ch},
	}
}

func drain(ch chan *types.SignedCommand) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func revokeRequest(principal *Principal, scope ctxkeys.TenantScope, body string) *http.Request {
	ctx := context.WithValue(context.Background(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	return httptest.NewRequest("POST", "/api/v1/certificates/signing/revoke", bytes.NewBufferString(body)).WithContext(ctx)
}

func strongRootPrincipal() *Principal {
	return &Principal{ID: "admin", Assurance: session.AssuranceStrong, CertSerial: "operator-serial-1"}
}

func TestHandleRevokeSigningCert_DeniesUnderprivilegedCallers(t *testing.T) {
	f := newRevokeFixture(t)
	body := `{"serial":"` + f.rotated.SerialNumber + `","reason":"x"}`

	cases := map[string]struct {
		principal *Principal
		scope     ctxkeys.TenantScope
	}{
		"non_strong":     {&Principal{ID: "weak", Assurance: session.AssuranceMachine, CertSerial: "s"}, ctxkeys.NewRootScope()},
		"tenant_scoped":  {&Principal{ID: "scoped", Assurance: session.AssuranceStrong, TenantID: "client-1", CertSerial: "s"}, ctxkeys.NewTenantScope("client-1")},
		"no_cert_serial": {&Principal{ID: "noserial", Assurance: session.AssuranceStrong}, ctxkeys.NewRootScope()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.server.handleRevokeSigningCert(rec, revokeRequest(tc.principal, tc.scope, body))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}

	revoked, err := f.mgrB.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Empty(t, revoked, "a denied request records nothing")
}

func TestHandleRevokeSigningCert_RejectsCurrentSerialAndMalformedSerial(t *testing.T) {
	f := newRevokeFixture(t)

	rec := httptest.NewRecorder()
	f.server.handleRevokeSigningCert(rec, revokeRequest(strongRootPrincipal(), ctxkeys.NewRootScope(),
		`{"serial":"`+f.current.SerialNumber+`","reason":"x"}`))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "rotate first")

	for _, body := range []string{
		`{"serial":"../../etc/passwd","reason":"x"}`,
		`{"serial":"","reason":"x"}`,
		`not json`,
	} {
		rec = httptest.NewRecorder()
		f.server.handleRevokeSigningCert(rec, revokeRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), body))
		assert.Equal(t, http.StatusBadRequest, rec.Code, "body %q: %s", body, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	long := bytes.Repeat([]byte("a"), 257)
	f.server.handleRevokeSigningCert(rec, revokeRequest(strongRootPrincipal(), ctxkeys.NewRootScope(),
		`{"serial":"`+f.rotated.SerialNumber+`","reason":"`+string(long)+`"}`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	revoked, err := f.mgrB.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Empty(t, revoked, "refused requests record nothing")
}

func TestHandleRevokeSigningCert_RecordsRetiresFansOutAndAudits(t *testing.T) {
	f := newRevokeFixture(t)

	rec := httptest.NewRecorder()
	f.server.handleRevokeSigningCert(rec, revokeRequest(strongRootPrincipal(), ctxkeys.NewRootScope(),
		`{"serial":"`+f.rotated.SerialNumber+`","reason":"key exposed"}`))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data RevokeSigningCertResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, f.rotated.SerialNumber, resp.Data.Serial)
	assert.Equal(t, 1, resp.Data.StewardsNotified)
	assert.True(t, resp.Data.RetiredFromCursor)

	// Recorded with the signing reason, visible to a second Manager on the shared store.
	serials, err := f.mgrB.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Equal(t, []string{f.rotated.SerialNumber}, serials)
	entries, err := f.mgrB.ListRevoked()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Reason, cert.RevocationReasonSigningCert)

	// Cleared from the cursor.
	cursor, err := f.mgrB.GetSigningCursorState()
	require.NoError(t, err)
	require.NotNil(t, cursor.RetiredAt)

	// The steward is told to retire exactly that serial, as a JSON array. Pushes
	// from the fixture's setup rotations may still be in flight ahead of it.
	var retire []string
	var raw map[string]string
	require.Eventually(t, func() bool {
		select {
		case sc := <-f.stewards["steward-1"]:
			r := sc.RawParams
			if r == nil {
				r = types.InterfaceParamsToStringMap(sc.Command.Params)
			}
			if sc.Command.Type != types.CommandPushSigningCert || r["retire_serials"] == "" {
				return false
			}
			raw = r
			return json.Unmarshal([]byte(r["retire_serials"]), &retire) == nil
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "steward must receive a push carrying retire_serials")
	assert.Equal(t, []string{f.rotated.SerialNumber}, retire)
	assert.Equal(t, f.current.SerialNumber, raw["serial"])

	// Audit event: operator serial, serial, reason, count; no PEM.
	require.NoError(t, f.audit.Flush(context.Background()))
	all, err := f.audit.QueryEntries(context.Background(), &business.AuditFilter{TenantID: audit.SystemTenantID})
	require.NoError(t, err)
	entry := findAuditEntryByAction(t, all, "signing_certificate_revoked")
	assert.Equal(t, f.rotated.SerialNumber, entry.ResourceID)
	assert.Equal(t, "operator-serial-1", entry.Details["operator_serial"])
	assert.Equal(t, f.rotated.SerialNumber, entry.Details["serial"])
	assert.Equal(t, "key exposed", entry.Details["reason"])
	assert.EqualValues(t, 1, entry.Details["stewards_notified"])
	entryJSON, err := json.Marshal(entry)
	require.NoError(t, err)
	assert.NotContains(t, string(entryJSON), "-----BEGIN")
}

func TestHandleRevokeSigningCert_RoutedThroughAdminCertificate(t *testing.T) {
	f := newRevokeFixture(t)
	issued, err := f.mgrA.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "operator-admin", Organization: "CFGMS", ValidityDays: 1, TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(issued.CertificatePEM)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/certificates/signing/revoke",
		bytes.NewBufferString(`{"serial":"`+f.rotated.SerialNumber+`","reason":"via router"}`))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}
