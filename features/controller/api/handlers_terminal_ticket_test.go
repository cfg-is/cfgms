// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
)

const ttSteward = "steward-1"

type ticketNode struct {
	t      *testing.T
	server *Server
	router *mux.Router
}

func newTicketNode(t *testing.T, server *Server) *ticketNode {
	t.Helper()
	seedScopeTenants(t, server)
	require.NoError(t, server.controllerService.RegisterSteward(ttSteward, saTenant, "addr", "active"))
	router := mux.NewRouter()
	registerTerminalRoutes(server, router)
	return &ticketNode{t: t, server: server, router: router}
}

func (n *ticketNode) do(path string, p *Principal, body interface{}) *httptest.ResponseRecorder {
	n.t.Helper()
	raw, ok := body.([]byte)
	if !ok {
		var err error
		raw, err = json.Marshal(body)
		require.NoError(n.t, err)
	}
	req := withPrincipal(httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)), p)
	rec := httptest.NewRecorder()
	n.router.ServeHTTP(rec, req)
	return rec
}

func terminalEnvelope(t *testing.T, steward, shell string, targets []string, nonce string, exp time.Time) operatorpayload.Envelope {
	t.Helper()
	content, err := operatorpayload.TerminalContent(steward, shell)
	require.NoError(t, err)
	return operatorpayload.Envelope{Content: content, Shell: operatorpayload.TerminalShell, Targets: targets, Nonce: nonce, ExpiresAt: exp}
}

func ticketBody(shell, nonce string, exp time.Time, targets []string, proof *OperatorProof) map[string]interface{} {
	b := map[string]interface{}{
		"terminal_shell": shell, "nonce": nonce, "expires_at": exp.UTC().Format(time.RFC3339), "targets": targets,
	}
	if proof != nil {
		if proof.X509 != nil {
			b["signature"] = proof.X509
		}
		if proof.WebAuthn != nil {
			b["webauthn"] = proof.WebAuthn
		}
	}
	return b
}

func (n *ticketNode) signedTicketBody(steward, shell string) map[string]interface{} {
	n.t.Helper()
	exp := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	env := terminalEnvelope(n.t, steward, shell, []string{steward}, "n-term", exp)
	proof, _ := signActionX509(n.t, n.server, env, cert.SetPayloadSigningMarker)
	return ticketBody(shell, "n-term", exp, []string{steward}, proof)
}

func ticketCount(s *Server) int { return syncMapLen(&s.terminalTickets) }

func decodeTicket(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.Ticket)
	return resp.Data.Ticket
}

func newTicketX509Node(t *testing.T) *ticketNode {
	t.Helper()
	return newTicketNode(t, newActionX509Server(t))
}

func TestTerminalTicket_NoProofAndWrongShellRefused(t *testing.T) {
	n := newTicketX509Node(t)
	p := actionPrincipal("op-1")
	exp := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)

	rec := n.do("/terminal/tickets/"+ttSteward, p, ticketBody("bash", "n1", exp, []string{ttSteward}, nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "INVALID_SIGNATURE", errorCode(t, rec))

	// A proof signed for the steward-action shell over the same steward.
	env := actionEnvelope(t, testAction(), []string{ttSteward}, "n1", exp)
	proof, _ := signActionX509(t, n.server, env, cert.SetPayloadSigningMarker)
	rec = n.do("/terminal/tickets/"+ttSteward, p, ticketBody("bash", "n1", exp, []string{ttSteward}, proof))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "INVALID_SIGNATURE", errorCode(t, rec))
	assert.Zero(t, ticketCount(n.server))
}

func TestTerminalTicket_ProofFailuresAre403AndStoreNothing(t *testing.T) {
	n := newTicketX509Node(t)
	p := actionPrincipal("op-1")
	cases := map[string]func() map[string]interface{}{
		"both proofs": func() map[string]interface{} {
			b := n.signedTicketBody(ttSteward, "bash")
			b["webauthn"] = &OperatorWebAuthnProof{}
			return b
		},
		"expired": func() map[string]interface{} {
			exp := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
			env := terminalEnvelope(t, ttSteward, "bash", []string{ttSteward}, "n", exp)
			proof, _ := signActionX509(t, n.server, env, cert.SetPayloadSigningMarker)
			return ticketBody("bash", "n", exp, []string{ttSteward}, proof)
		},
		"ttl too long": func() map[string]interface{} {
			exp := time.Now().Add(operatorpayload.TerminalEnvelopeMaxTTL + time.Hour).UTC().Truncate(time.Second)
			env := terminalEnvelope(t, ttSteward, "bash", []string{ttSteward}, "n", exp)
			proof, _ := signActionX509(t, n.server, env, cert.SetPayloadSigningMarker)
			return ticketBody("bash", "n", exp, []string{ttSteward}, proof)
		},
		"extra target": func() map[string]interface{} {
			exp := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
			tg := []string{ttSteward, "other"}
			env := terminalEnvelope(t, ttSteward, "bash", tg, "n", exp)
			proof, _ := signActionX509(t, n.server, env, cert.SetPayloadSigningMarker)
			return ticketBody("bash", "n", exp, tg, proof)
		},
		"shell differs from signed": func() map[string]interface{} {
			b := n.signedTicketBody(ttSteward, "bash")
			b["terminal_shell"] = "zsh"
			return b
		},
		"bad expires_at": func() map[string]interface{} {
			b := n.signedTicketBody(ttSteward, "bash")
			b["expires_at"] = "soon"
			return b
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			rec := n.do("/terminal/tickets/"+ttSteward, p, mk())
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "INVALID_SIGNATURE", errorCode(t, rec))
			assert.Zero(t, ticketCount(n.server))
		})
	}
}

func TestTerminalTicket_MalformedAndBadShell(t *testing.T) {
	n := newTicketX509Node(t)
	p := actionPrincipal("op-1")
	rec := n.do("/terminal/tickets/"+ttSteward, p, []byte(`{not json`))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	for _, sh := range []string{"", "fish"} {
		b := n.signedTicketBody(ttSteward, "bash")
		b["terminal_shell"] = sh
		rec = n.do("/terminal/tickets/"+ttSteward, p, b)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}
	assert.Zero(t, ticketCount(n.server))
}

func TestTerminalTicket_ProofForOtherStewardRefused(t *testing.T) {
	n := newTicketX509Node(t)
	require.NoError(t, n.server.controllerService.RegisterSteward("steward-2", saTenant, "addr", "active"))
	body := n.signedTicketBody(ttSteward, "bash") // signed for steward A
	rec := n.do("/terminal/tickets/steward-2", actionPrincipal("op-1"), body)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "INVALID_SIGNATURE", errorCode(t, rec))
	assert.Zero(t, ticketCount(n.server))
}

func TestTerminalTicket_OtherTenantGets404(t *testing.T) {
	n := newTicketX509Node(t)
	foreign := actionPrincipal("op-b")
	foreign.TenantID = "msp-b"
	rec := n.do("/terminal/tickets/"+ttSteward, foreign, n.signedTicketBody(ttSteward, "bash"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Zero(t, ticketCount(n.server))
}

func TestTerminalTicket_X509MintsBoundTicketConsumedOnce(t *testing.T) {
	n := newTicketX509Node(t)
	p := actionPrincipal("op-1")
	body := n.signedTicketBody(ttSteward, "bash")
	ticket := decodeTicket(t, n.do("/terminal/tickets/"+ttSteward, p, body))

	hash := hashTerminalTicket(ticket)
	n.server.terminalTickets.Range(func(k, _ any) bool {
		assert.NotEqual(t, ticket, k, "plaintext ticket must not be a stored key")
		assert.Equal(t, hash, k)
		return true
	})
	raw, ok := n.server.terminalTickets.Load(hash)
	require.True(t, ok)
	stored := raw.(*terminalTicketRecord)
	assert.Equal(t, "op-1", stored.principalID)
	assert.Equal(t, saTenant, stored.tenantID)
	assert.Equal(t, ttSteward, stored.stewardID)
	assert.Equal(t, "bash", stored.terminalShell)
	assert.NotNil(t, stored.x509)
	assert.WithinDuration(t, time.Now().Add(terminalTicketTTL), stored.expires, 5*time.Second)

	rec, out := n.server.takeTerminalTicket(context.Background(), hash)
	require.Equal(t, ceremonyOK, out)
	assert.Equal(t, stored, rec)
	_, out = n.server.takeTerminalTicket(context.Background(), hash)
	assert.Equal(t, ceremonyNotFound, out)
}

func TestTerminalTicket_WebAuthnMintsTicketWithManifest(t *testing.T) {
	f := newWebAuthnActionFixture(t)
	server := f.server
	server.certManager = newTLSTestCertManager(t)
	ensureSharedSigningCertificate(t, server.certManager)
	acct, err := server.getAccount(context.Background(), f.username)
	require.NoError(t, err)
	acct.RootScope = true
	require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
	server.cacheAccount(acct)
	n := newTicketNode(t, server)

	exp := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	env := terminalEnvelope(t, ttSteward, "bash", []string{ttSteward}, "n-wa", exp)
	proof := f.proofFor(t, env)
	p := &Principal{ID: f.username, Name: f.username, TenantID: saTenant, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	ticket := decodeTicket(t, n.do("/terminal/tickets/"+ttSteward, p, ticketBody("bash", "n-wa", exp, []string{ttSteward}, &proof)))

	n.server.terminalTickets.Range(func(k, _ any) bool {
		assert.NotEqual(t, ticket, k)
		return true
	})
	rec, out := n.server.takeTerminalTicket(context.Background(), hashTerminalTicket(ticket))
	require.Equal(t, ceremonyOK, out)
	assert.NotNil(t, rec.webAuthn)
	assert.NotEmpty(t, rec.manifest)
}

func TestTerminalTicket_ClusterModeWithoutNonceStoreIs503(t *testing.T) {
	f := newClusterFixture(t)
	server := f.join(newActionX509Server(t))
	server.SetNonceStore(nil)
	n := newTicketNode(t, server)
	rec := n.do("/terminal/tickets/"+ttSteward, actionPrincipal("op-1"), n.signedTicketBody(ttSteward, "bash"))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Zero(t, ticketCount(server))
}

func TestTerminalTicket_ClusterModeMintOnOneNodeTakeOnAnother(t *testing.T) {
	f := newClusterFixture(t)
	a := newTicketNode(t, f.join(newActionX509Server(t)))
	b := f.join(setupTestServer(t))
	ticket := decodeTicket(t, a.do("/terminal/tickets/"+ttSteward, actionPrincipal("op-1"), a.signedTicketBody(ttSteward, "bash")))
	assert.Zero(t, ticketCount(a.server), "ClusterMode must not use the node-local map")
	rec, out := b.takeTerminalTicket(context.Background(), hashTerminalTicket(ticket))
	require.Equal(t, ceremonyOK, out)
	assert.Equal(t, "op-1", rec.principalID)
	assert.Equal(t, ttSteward, rec.stewardID)
	_, out = a.server.takeTerminalTicket(context.Background(), hashTerminalTicket(ticket))
	assert.Equal(t, ceremonyNotFound, out)
}

func concurrentTakes(s *Server, hash string, n int) int32 {
	var won int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, out := s.takeTerminalTicket(context.Background(), hash); out == ceremonyOK {
				atomic.AddInt32(&won, 1)
			}
		}()
	}
	wg.Wait()
	return won
}

func TestTakeTerminalTicket_ConcurrentSingleUse(t *testing.T) {
	rec := func() *terminalTicketRecord {
		return &terminalTicketRecord{principalID: "op", stewardID: ttSteward, terminalShell: "bash", expires: time.Now().Add(time.Minute)}
	}
	t.Run("node-local", func(t *testing.T) {
		s := setupTestServer(t)
		require.Equal(t, ceremonyOK, s.putTerminalTicket(context.Background(), "h", rec()))
		assert.EqualValues(t, 1, concurrentTakes(s, "h", 32))
	})
	t.Run("cluster", func(t *testing.T) {
		f := newClusterFixture(t)
		s1, s2 := f.join(setupTestServer(t)), f.join(setupTestServer(t))
		require.Equal(t, ceremonyOK, s1.putTerminalTicket(context.Background(), "h", rec()))
		var won int32
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(s *Server) {
				defer wg.Done()
				if _, out := s.takeTerminalTicket(context.Background(), "h"); out == ceremonyOK {
					atomic.AddInt32(&won, 1)
				}
			}([]*Server{s1, s2}[i%2])
		}
		wg.Wait()
		assert.EqualValues(t, 1, won)
	})
}

func TestTakeTerminalTicket_ExpiredNotReturned(t *testing.T) {
	expired := &terminalTicketRecord{principalID: "op", expires: time.Now().Add(-time.Second)}
	t.Run("node-local", func(t *testing.T) {
		s := setupTestServer(t)
		s.terminalTickets.Store("h", expired)
		_, out := s.takeTerminalTicket(context.Background(), "h")
		assert.Equal(t, ceremonyNotFound, out)
	})
	t.Run("cluster", func(t *testing.T) {
		f := newClusterFixture(t)
		s := f.join(setupTestServer(t))
		w := expired.toWire()
		require.Equal(t, ceremonyOK, s.putClusterCeremony(context.Background(), ceremonyPrefixTerminalTicket, "h", w, 50*time.Millisecond))
		time.Sleep(200 * time.Millisecond)
		_, out := s.takeTerminalTicket(context.Background(), "h")
		assert.Equal(t, ceremonyNotFound, out)
	})
}

func TestTerminalTicket_PrefixIsolatedFromPresenceTokens(t *testing.T) {
	f := newClusterFixture(t)
	s := f.join(setupTestServer(t))
	ctx := context.Background()

	require.Equal(t, ceremonyOK, s.putTerminalTicket(ctx, "h", &terminalTicketRecord{principalID: "op", expires: time.Now().Add(time.Minute)}))
	_, out := takeClusterCeremony[presenceTokenWire](s, ctx, ceremonyPrefixPresenceToken, "h")
	assert.Equal(t, ceremonyNotFound, out, "a ticket hash must not be consumable as a presence token")
	_, out = s.takeTerminalTicket(ctx, "h")
	assert.Equal(t, ceremonyOK, out, "the ticket must survive the cross-prefix attempt")

	require.Equal(t, ceremonyOK, s.putPresenceToken(ctx, "h", &presenceTokenRecord{principalID: "op", expires: time.Now().Add(time.Minute)}))
	_, out = s.takeTerminalTicket(ctx, "h")
	assert.Equal(t, ceremonyNotFound, out, "a presence token must not be consumable as a ticket")
	_, out = s.takePresenceToken(ctx, "h")
	assert.Equal(t, ceremonyOK, out)

	assert.NotEqual(t, ceremonyPrefixTerminalTicket, ceremonyPrefixPresenceToken)
}

func TestTerminalPrepare(t *testing.T) {
	n := newTicketX509Node(t)
	require.NoError(t, n.server.controllerService.RegisterStewardWithAttributes("win-1", saTenant, "addr", "active", map[string]string{"os": "windows"}))
	require.NoError(t, n.server.controllerService.RegisterStewardWithAttributes("lin-1", saTenant, "addr", "active", map[string]string{"os": "linux"}))
	require.NoError(t, n.server.controllerService.RegisterStewardWithAttributes("mac-1", saTenant, "addr", "active", map[string]string{"os": "darwin"}))
	p := actionPrincipal("op-1")

	type prep struct {
		Data map[string]string `json:"data"`
	}
	run := func(steward, shell string) (*httptest.ResponseRecorder, prep) {
		rec := n.do("/terminal/prepare/"+steward, p, map[string]string{"terminal_shell": shell})
		var out prep
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	for steward, want := range map[string]string{"win-1": "powershell", "lin-1": "bash", "mac-1": "bash"} {
		rec, out := run(steward, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, want, out.Data["terminal_shell"], steward)
		assert.Equal(t, operatorpayload.TerminalShell, out.Data["shell"])
		got, err := base64.StdEncoding.DecodeString(out.Data["content"])
		require.NoError(t, err)
		wantContent, err := operatorpayload.TerminalContent(steward, want)
		require.NoError(t, err)
		assert.Equal(t, wantContent, got)
	}

	rec, out := run("win-1", "bash")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "bash", out.Data["terminal_shell"], "an explicit shell is honoured")

	rec, _ = run(ttSteward, "") // registered without DNA
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.NotContains(t, rec.Body.String(), "content")

	rec, _ = run("win-1", "fish")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	foreign := actionPrincipal("op-b")
	foreign.TenantID = "msp-b"
	assert.Equal(t, http.StatusNotFound, n.do("/terminal/prepare/win-1", foreign, map[string]string{}).Code)
}

func TestTerminalRoutes_UseTerminalCreatePermission(t *testing.T) {
	n := newTicketX509Node(t)
	p := actionPrincipal("op-1")
	p.ImplicitAdmin = false
	p.Permissions = []string{"steward:service-control"}
	assert.Equal(t, http.StatusForbidden, n.do("/terminal/prepare/"+ttSteward, p, map[string]string{"terminal_shell": "bash"}).Code)
	assert.Equal(t, http.StatusForbidden, n.do("/terminal/tickets/"+ttSteward, p, n.signedTicketBody(ttSteward, "bash")).Code)
	assert.Zero(t, ticketCount(n.server))
}
