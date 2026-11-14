// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// senderLogCapture records every log call; an Error call is prefixed so a test can
// tell the level.
type senderLogCapture struct{ captureAllLogger }

func (l *senderLogCapture) Error(msg string, kvs ...interface{}) { l.record("ERROR "+msg, kvs...) }

// attachMSPSender stores a sender for mspID that delivers to smtp. An empty
// password leaves the record without one (an incomplete sender). The story-2 test
// seams admit the loopback test server: the port allow-list, the extra provider
// keys carrying its CA, and the connect-time guard's loopback switch.
func attachMSPSender(t *testing.T, server *Server, mspID string, smtp *emailTestSMTPServer, password string) {
	t.Helper()
	ctx := context.Background()
	if server.MSPEmailSenderStore() == nil {
		_, cs := newApprovalStore(t)
		st, err := NewMSPEmailSenderStore(cs)
		require.NoError(t, err)
		server.SetMSPEmailSenderStore(st)
	}
	orig := mspEmailAllowedPorts
	mspEmailAllowedPorts = []int{smtp.Port}
	t.Cleanup(func() { mspEmailAllowedPorts = orig })
	server.emailMu.Lock()
	server.mspEmailExtra = map[string]interface{}{"root_ca_pem": smtp.CAPEM}
	server.emailMu.Unlock()
	t.Cleanup(pkgconfig.AllowLoopbackForTesting())

	_, err := server.MSPEmailSenderStore().Put(ctx, mspID, MSPEmailSender{
		Host: "localhost", Port: smtp.Port, TLSMode: "implicit_tls", From: "ops@msp-a.example", Username: testSMTPUser,
	}, "alice")
	require.NoError(t, err)
	if password != "" {
		require.NoError(t, server.storeMSPEmailPassword(ctx, mspID, password, "alice"))
	}
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// pointMSPSenderAtClosedPort re-stores mspID's sender with a port nothing listens
// on, keeping its password, so a send fails at connect time. It must follow
// attachMSPSender, whose port allow-list restore it relies on.
func pointMSPSenderAtClosedPort(t *testing.T, server *Server, mspID string) {
	t.Helper()
	port := closedPort(t)
	mspEmailAllowedPorts = append(mspEmailAllowedPorts, port)
	_, err := server.MSPEmailSenderStore().Put(context.Background(), mspID, MSPEmailSender{
		Host: "localhost", Port: port, TLSMode: "implicit_tls", From: "ops@msp-a.example", Username: testSMTPUser,
	}, "alice")
	require.NoError(t, err)
}

// senderFixture is a tamper fixture with a platform mail server and an MSP mail
// server, and a log capture.
type senderFixture struct {
	*tamperFixture
	platform *emailTestSMTPServer
	msp      *emailTestSMTPServer
	logs     *senderLogCapture
}

func newSenderFixture(t *testing.T) *senderFixture {
	t.Helper()
	logs := &senderLogCapture{}
	server := setupTestServerWithLogger(t, logs)
	seedTenantTree(t, server)
	f := &senderFixture{
		tamperFixture: &tamperFixture{server: server, store: wireSharedStewardStore(t, server)},
		platform:      newEmailTestSMTPServer(t),
		msp:           newEmailTestSMTPServer(t),
		logs:          logs,
	}
	attachEmail(t, server, f.platform)
	setContacts(t, server, "admin@acme-corp.example")
	setTenantContacts(t, server, "client-1", "admin@client-1.example")
	return f
}

func (f *senderFixture) alarm(t *testing.T, tenantID string) *business.AuditEntry {
	t.Helper()
	id := f.steward(t, "host-"+tenantID, tenantID, business.StewardStatusActive)
	f.server.HandleStewardTamperAlarm(context.Background(), id, tamperReasons)
	events := alarmEvents(t, f.server, tenantID, id)
	require.Len(t, events, 1)
	return events[0]
}

func TestResolveEmailSender_Rules(t *testing.T) {
	ctx := context.Background()
	f := newSenderFixture(t)
	s := f.server

	t.Run("owning MSP rule without a sender falls back to platform", func(t *testing.T) {
		n, src := s.resolveEmailSender(ctx, emailRuleOwningMSPWithPlatformFallback, "client-1")
		require.NotNil(t, n)
		assert.Equal(t, emailSourcePlatform, src)
	})
	t.Run("platform-only rule returns the platform notifier", func(t *testing.T) {
		n, src := s.resolveEmailSender(ctx, emailRulePlatformOnly, "client-1")
		require.NotNil(t, n)
		assert.Equal(t, emailSourcePlatform, src)
	})
	t.Run("unknown rule is treated as platform-only", func(t *testing.T) {
		_, src := s.resolveEmailSender(ctx, emailSenderRule(0), "client-1")
		assert.Equal(t, emailSourcePlatform, src)
	})

	attachMSPSender(t, s, "msp-a", f.msp, testSMTPPassword)

	t.Run("owning MSP rule uses a complete MSP sender", func(t *testing.T) {
		for _, tenantID := range []string{"msp-a", "client-1"} {
			n, src := s.resolveEmailSender(ctx, emailRuleOwningMSPWithPlatformFallback, tenantID)
			require.NotNil(t, n, tenantID)
			assert.Equal(t, emailSourceMSP, src, tenantID)
		}
	})
	t.Run("another MSP's tenant does not use it", func(t *testing.T) {
		_, src := s.resolveEmailSender(ctx, emailRuleOwningMSPWithPlatformFallback, "msp-b")
		assert.Equal(t, emailSourcePlatform, src)
	})
	t.Run("root and unknown tenants use the platform sender", func(t *testing.T) {
		for _, tenantID := range []string{testRootTenantID, "missing", ""} {
			_, src := s.resolveEmailSender(ctx, emailRuleOwningMSPWithPlatformFallback, tenantID)
			assert.Equal(t, emailSourcePlatform, src, tenantID)
		}
	})
	t.Run("platform-only ignores a complete MSP sender", func(t *testing.T) {
		_, src := s.resolveEmailSender(ctx, emailRulePlatformOnly, "client-1")
		assert.Equal(t, emailSourcePlatform, src)
	})

	t.Run("no platform notifier and no MSP sender is none", func(t *testing.T) {
		s.emailMu.Lock()
		s.emailNotifier = nil
		s.emailMu.Unlock()
		n, src := s.resolveEmailSender(ctx, emailRulePlatformOnly, "client-1")
		assert.Nil(t, n)
		assert.Equal(t, emailSourceNone, src)
		n, src = s.resolveEmailSender(ctx, emailRuleOwningMSPWithPlatformFallback, "msp-b")
		assert.Nil(t, n)
		assert.Equal(t, emailSourceNone, src)
		// The MSP's own sender is still found without a platform sender.
		_, src = s.resolveEmailSender(ctx, emailRuleOwningMSPWithPlatformFallback, "client-1")
		assert.Equal(t, emailSourceMSP, src)
	})
}

func TestResolveEmailSender_RecordWithoutPasswordFallsBackToPlatform(t *testing.T) {
	f := newSenderFixture(t)
	attachMSPSender(t, f.server, "msp-a", f.msp, "")

	_, src := f.server.resolveEmailSender(context.Background(), emailRuleOwningMSPWithPlatformFallback, "client-1")
	assert.Equal(t, emailSourcePlatform, src)

	entry := f.alarm(t, "client-1")
	assert.Equal(t, "platform", entry.Details["sender"])
	assert.Equal(t, "sent", entry.Details["notification"])
	assert.Empty(t, f.msp.Messages())
	assert.Len(t, f.platform.Messages(), 1)
}

func TestTamperAlert_OwningMSPSenderCarriesIt(t *testing.T) {
	f := newSenderFixture(t)
	attachMSPSender(t, f.server, "msp-a", f.msp, testSMTPPassword)

	entry := f.alarm(t, "client-1")

	assert.Equal(t, "msp", entry.Details["sender"])
	assert.Equal(t, "sent", entry.Details["notification"])
	assert.Len(t, f.msp.Messages(), 1, "the MSP server carries the alert")
	assert.Empty(t, f.platform.Messages(), "the platform server receives nothing")
}

func TestTamperAlert_MSPWithoutSenderUsesPlatform(t *testing.T) {
	f := newSenderFixture(t)

	entry := f.alarm(t, "client-1")

	assert.Equal(t, "platform", entry.Details["sender"])
	assert.Equal(t, "sent", entry.Details["notification"])
	assert.Len(t, f.platform.Messages(), 1)
	assert.Empty(t, f.msp.Messages())
}

func TestTamperAlert_NoSenderAtAllAuditsNone(t *testing.T) {
	f := newSenderFixture(t)
	f.server.emailMu.Lock()
	f.server.emailNotifier = nil
	f.server.emailMu.Unlock()

	entry := f.alarm(t, "client-1")

	assert.Equal(t, "none", entry.Details["sender"])
	assert.Equal(t, "not_configured", entry.Details["notification"])
}

// A failed MSP send is not retried on the platform sender: the MSP chose its
// sender and the platform must not carry mail the MSP's own sender refused.
func TestTamperAlert_FailedMSPSendIsNotRetriedOnPlatform(t *testing.T) {
	const wrongPassword = "Wr0ng-msp-password-must-not-leak"
	for name, setup := range map[string]func(t *testing.T, f *senderFixture){
		"wrong password": func(t *testing.T, f *senderFixture) {
			attachMSPSender(t, f.server, "msp-a", f.msp, wrongPassword)
		},
		"unreachable host": func(t *testing.T, f *senderFixture) {
			attachMSPSender(t, f.server, "msp-a", f.msp, testSMTPPassword)
			pointMSPSenderAtClosedPort(t, f.server, "msp-a")
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSenderFixture(t)
			setup(t, f)

			entry := f.alarm(t, "client-1")

			assert.Equal(t, "failed", entry.Details["notification"])
			assert.Equal(t, "msp", entry.Details["sender"])
			assert.Empty(t, f.platform.Messages(), "no retry on the platform sender")
			assert.Empty(t, f.msp.Messages())
			logged := f.logs.captured()
			assert.Contains(t, logged, "ERROR Tamper notification email failed")
			assert.Contains(t, logged, "msp_tenant_id msp-a")
			assert.NotContains(t, logged, wrongPassword)
			assert.NotContains(t, logged, testSMTPPassword)
		})
	}
}

func TestBreakGlass_UsesPlatformSenderOnlyAndAuditsIt(t *testing.T) {
	smtpPlatform := newEmailTestSMTPServer(t)
	smtpMSP := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachEmail(t, server, smtpPlatform)
	attachMSPSender(t, server, "msp-a", smtpMSP, testSMTPPassword)
	setContacts(t, server, "ops@acme-corp.example")

	rec := invokeLoud(t, server, "account_recovery")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	assert.Equal(t, "sent", notifiedOutcome(t, server))
	assert.Len(t, smtpPlatform.Messages(), 1)
	assert.Empty(t, smtpMSP.Messages(), "the MSP's sender never carries a break-glass notice")
	e := findAuditEntryByAction(t, auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_notified")
	assert.Equal(t, "platform", e.Details["sender"])
}

func TestBreakGlass_NotConfiguredAuditsSenderNone(t *testing.T) {
	smtpMSP := newEmailTestSMTPServer(t)
	server := breakGlassServer(t)
	attachMSPSender(t, server, "msp-a", smtpMSP, testSMTPPassword)
	setContacts(t, server, "ops@acme-corp.example")

	rec := invokeLoud(t, server, "account_recovery")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	assert.Equal(t, "not_configured", notifiedOutcome(t, server), "an MSP sender alone does not carry a break-glass notice")
	e := findAuditEntryByAction(t, auditEntries(t, server, "msp-a"), "tenant.crossing_break_glass_notified")
	assert.Equal(t, "none", e.Details["sender"])
	assert.Empty(t, smtpMSP.Messages())
}

// The break-glass notice does not depend on the MSP sender: it is delivered when
// that sender's host is unreachable or its password is wrong.
func TestBreakGlass_DeliveredWhenMSPSenderIsBroken(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, server *Server, msp *emailTestSMTPServer){
		"wrong password": func(t *testing.T, server *Server, msp *emailTestSMTPServer) {
			attachMSPSender(t, server, "msp-a", msp, "Wr0ng-msp-password")
		},
		"unreachable host": func(t *testing.T, server *Server, msp *emailTestSMTPServer) {
			attachMSPSender(t, server, "msp-a", msp, testSMTPPassword)
			pointMSPSenderAtClosedPort(t, server, "msp-a")
		},
	} {
		t.Run(name, func(t *testing.T) {
			smtpPlatform := newEmailTestSMTPServer(t)
			smtpMSP := newEmailTestSMTPServer(t)
			server := breakGlassServer(t)
			attachEmail(t, server, smtpPlatform)
			setup(t, server, smtpMSP)
			setContacts(t, server, "ops@acme-corp.example")

			rec := invokeLoud(t, server, "account_recovery")
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

			assert.Equal(t, "sent", notifiedOutcome(t, server))
			assert.Len(t, smtpPlatform.Messages(), 1)
			assert.Empty(t, smtpMSP.Messages())
		})
	}
}

// The tamper source tenant check: the tamper reason code is exercised through the
// real heartbeat entry point, so the sender decision is made on the real path.
func TestTamperAlert_UsesRealAlarmPath(t *testing.T) {
	f := newSenderFixture(t)
	attachMSPSender(t, f.server, "msp-a", f.msp, testSMTPPassword)
	id := f.steward(t, "path-host", "client-1", business.StewardStatusActive)

	f.server.HandleStewardTamperAlarm(context.Background(), id, []controlplaneTypes.HealthReason{
		{Component: "integrity", Code: controlplaneTypes.ReasonCodeTamperDataDir},
	})
	f.server.crossingNotifyWG.Wait()

	assert.Len(t, f.msp.Messages(), 1)
	assert.Empty(t, f.platform.Messages())
}
