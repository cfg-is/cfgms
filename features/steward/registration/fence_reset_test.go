// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuedCertSet is a real CFGMS-issued steward identity: a CA created by pkg/cert
// and a client certificate signed by it. No mocks — the same central provider the
// controller uses to issue enrollment certificates issues these.
type issuedCertSet struct {
	clientCert string
	clientKey  string
	caCert     string
}

// newIssuedCertSet generates a fresh CA and a client certificate signed by it,
// mirroring what the controller returns from a claimed registration
// (features/controller/api/handlers_registration.go:549).
func newIssuedCertSet(t *testing.T) issuedCertSet {
	t.Helper()

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Test CA",
		Country:      "US",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "steward-abc",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-abc",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	return issuedCertSet{
		clientCert: string(clientCert.CertificatePEM),
		clientKey:  string(clientCert.PrivateKeyPEM),
		caCert:     string(caPEM),
	}
}

// TestRegistration_FenceRatchet_AuthenticatedReset verifies the two-part
// guarantee for the enrollment-path ratchet reset (Story #3437):
//
// (a) Completing an enrollment through the real client — HTTPClient.Register
//
//	against a controller returning an approved response with a genuinely issued
//	certificate set — clears the persisted ratchet, so a command carrying a term
//	below the pre-reset baseline is accepted on the next startup.
//
// (b) No call path from features/steward/client to the reset exists — the
//
//	command-receive path cannot trigger it. resetFenceRatchetOnEnrollment is
//	unexported, so that package cannot name it at all; the AST-walk test
//	TestNoRatchetClearCallerOutsideRegistration in architecture_test.go proves no
//	wrapper reintroduces the path.
func TestRegistration_FenceRatchet_AuthenticatedReset(t *testing.T) {
	dir := t.TempDir()
	certSet := newIssuedCertSet(t)

	// Set up the ratchet at a nonzero baseline (term 10), simulating a steward
	// that has processed commands from a controller cluster at Raft term 10.
	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 10), "Save must succeed")

	// Verify the pre-reset state: a command at term 5 would be rejected.
	preRatchetSet, preHighest, err := r.Load()
	require.NoError(t, err)
	require.True(t, preRatchetSet, "ratchet must be set before reset")
	require.Equal(t, uint64(10), preHighest, "high-water must be 10 before reset")

	// Drive the reset through the actual enrollment path: the controller approves
	// the registration immediately (HTTP 200) and returns the issued certificate set.
	body, err := json.Marshal(RegistrationResponse{
		Success:    true,
		StewardID:  "steward-abc",
		TenantID:   "test-tenant",
		ClientCert: certSet.clientCert,
		ClientKey:  certSet.clientKey,
		CACert:     certSet.caCert,
	})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		CertStoreDir:  dir,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	regResp, pendingResp, err := client.Register(context.Background(), RegistrationRequest{Token: "test-token"})
	require.NoError(t, err)
	require.Nil(t, pendingResp)
	require.NotNil(t, regResp)

	// (a) After the enrollment completes, a fresh Load must return zero values —
	// proving the ratchet is genuinely cleared and starts fresh on next startup.
	ratchetSet, highestTermSeen, err := r.Load()
	require.NoError(t, err, "Load after reset must succeed")
	assert.False(t, ratchetSet, "ratchet-set flag must be cleared by enrollment reset")
	assert.Equal(t, uint64(0), highestTermSeen, "high-water term must be zero after enrollment reset")

	// A command at term 5 (below the pre-reset baseline of 10) is now accepted:
	// with ratchetSet=false the fence is in the "never seen a stamped command"
	// state and admits any command regardless of term.
	const staleCommandTerm = uint64(5)
	wouldBeRejected := ratchetSet && staleCommandTerm < highestTermSeen
	assert.False(t, wouldBeRejected,
		"term-%d command must be accepted after reset (ratchet cleared: ratchetSet=%v, highest=%d)",
		staleCommandTerm, ratchetSet, highestTermSeen)
}

// TestRegistration_FenceRatchet_ResetOnApprovedPoll verifies that the operator-approval
// path resets the ratchet as well: PollStatus returning status="claimed" with the issued
// certificate set is the same enrollment completion as an immediate HTTP 200.
func TestRegistration_FenceRatchet_ResetOnApprovedPoll(t *testing.T) {
	dir := t.TempDir()
	certSet := newIssuedCertSet(t)

	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 12))

	body, err := json.Marshal(RegistrationStatusResponse{
		Status:     enrollmentStatusClaimed,
		StewardID:  "steward-abc",
		TenantID:   "test-tenant",
		ClientCert: certSet.clientCert,
		ClientKey:  certSet.clientKey,
		CACert:     certSet.caCert,
	})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		CertStoreDir:  dir,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	statusResp, err := client.PollStatus(context.Background(), "pending-1", "test-token", 0, 0)
	require.NoError(t, err)
	require.Equal(t, enrollmentStatusClaimed, statusResp.Status)

	ratchetSet, highest, err := r.Load()
	require.NoError(t, err)
	assert.False(t, ratchetSet, "claimed poll with a verified cert set must clear the ratchet")
	assert.Equal(t, uint64(0), highest)
}

// TestRegistration_FenceRatchet_NoResetWithoutVerifiedCertSet is the negative case for
// the reset's verification gate. A response that claims success but carries certificate
// material that does not verify must leave the persisted fence exactly as it was —
// fail-closed, because a cleared fence re-opens the dual-authority window.
func TestRegistration_FenceRatchet_NoResetWithoutVerifiedCertSet(t *testing.T) {
	issued := newIssuedCertSet(t)
	foreign := newIssuedCertSet(t)

	cases := []struct {
		name string
		resp RegistrationResponse
	}{
		{
			name: "no certificate material at all",
			resp: RegistrationResponse{Success: true, StewardID: "steward-abc"},
		},
		{
			name: "certificate present but key and CA missing",
			resp: RegistrationResponse{Success: true, ClientCert: issued.clientCert},
		},
		{
			name: "non-PEM garbage in every field",
			resp: RegistrationResponse{
				Success:    true,
				ClientCert: "cert-pem",
				ClientKey:  "key-pem",
				CACert:     "ca-pem",
			},
		},
		{
			name: "key belongs to a different certificate",
			resp: RegistrationResponse{
				Success:    true,
				ClientCert: issued.clientCert,
				ClientKey:  foreign.clientKey,
				CACert:     issued.caCert,
			},
		},
		{
			name: "certificate does not chain to the delivered CA",
			resp: RegistrationResponse{
				Success:    true,
				ClientCert: issued.clientCert,
				ClientKey:  issued.clientKey,
				CACert:     foreign.caCert,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			r := stewardconfig.NewFenceRatchet(dir)
			require.NoError(t, r.Save(true, 10))

			body, err := json.Marshal(tc.resp)
			require.NoError(t, err)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			client, err := NewHTTPClient(&HTTPConfig{
				ControllerURL: srv.URL,
				CertStoreDir:  dir,
				Logger:        logging.NewLogger("debug"),
			})
			require.NoError(t, err)

			_, _, err = client.Register(context.Background(), RegistrationRequest{Token: "test-token"})
			require.NoError(t, err, "an unverifiable cert set must not fail the registration call itself")

			ratchetSet, highest, err := r.Load()
			require.NoError(t, err)
			assert.True(t, ratchetSet, "ratchet-set flag must survive an unverified enrollment response")
			assert.Equal(t, uint64(10), highest, "high-water term must survive an unverified enrollment response")
		})
	}
}

// TestRegistration_FenceRatchet_NoResetOnPendingRegistration verifies that a quarantined
// registration (HTTP 202, no certificates issued) is not treated as an enrollment
// completion. An attacker who can only elicit a 202 gains nothing.
func TestRegistration_FenceRatchet_NoResetOnPendingRegistration(t *testing.T) {
	dir := t.TempDir()
	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 9))

	body, err := json.Marshal(RegistrationPendingResponse{
		PendingID: "pending-1", StewardID: "steward-abc", Status: "pending",
	})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		CertStoreDir:  dir,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	_, pendingResp, err := client.Register(context.Background(), RegistrationRequest{Token: "test-token"})
	require.NoError(t, err)
	require.NotNil(t, pendingResp)

	ratchetSet, highest, err := r.Load()
	require.NoError(t, err)
	assert.True(t, ratchetSet, "a pending registration must not clear the ratchet")
	assert.Equal(t, uint64(9), highest)
}

// TestRegistration_FenceRatchet_NoResetOnGoneStatus verifies that the synthetic
// "claimed" response PollStatus returns for HTTP 410 (record already claimed elsewhere)
// carries no certificate set and therefore never resets the fence.
func TestRegistration_FenceRatchet_NoResetOnGoneStatus(t *testing.T) {
	dir := t.TempDir()
	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 11))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		CertStoreDir:  dir,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	statusResp, err := client.PollStatus(context.Background(), "pending-1", "test-token", 0, 0)
	require.NoError(t, err)
	require.Equal(t, enrollmentStatusClaimed, statusResp.Status)

	ratchetSet, highest, err := r.Load()
	require.NoError(t, err)
	assert.True(t, ratchetSet, "a 410 already-claimed poll must not clear the ratchet")
	assert.Equal(t, uint64(11), highest)
}

// TestRegistration_FenceRatchet_NoRatchetConfigured verifies that a client built
// without CertStoreDir owns no durable ratchet and completes an enrollment without
// error (and without a nil dereference).
func TestRegistration_FenceRatchet_NoRatchetConfigured(t *testing.T) {
	certSet := newIssuedCertSet(t)

	body, err := json.Marshal(RegistrationResponse{
		Success:    true,
		StewardID:  "steward-abc",
		ClientCert: certSet.clientCert,
		ClientKey:  certSet.clientKey,
		CACert:     certSet.caCert,
	})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		Timeout:       5 * time.Second,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)
	assert.Nil(t, client.fenceRatchet, "no CertStoreDir means no durable ratchet to reset")

	regResp, _, err := client.Register(context.Background(), RegistrationRequest{Token: "test-token"})
	require.NoError(t, err)
	require.NotNil(t, regResp)

	// The reset primitive itself is a no-op (not an error) with a verified cert set
	// and no configured ratchet.
	require.NoError(t, resetFenceRatchetOnEnrollment(nil, regResp.enrollmentCertSet()))
}

// TestRegistration_FenceRatchet_ResetIdempotent verifies that completing enrollment
// twice does not produce an error — the second reset operates on an already-cleared
// ratchet and must be a no-op.
func TestRegistration_FenceRatchet_ResetIdempotent(t *testing.T) {
	dir := t.TempDir()
	certSet := newIssuedCertSet(t)

	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 7))

	set := enrollmentCertSet{
		stewardID:  "steward-abc",
		clientCert: certSet.clientCert,
		clientKey:  certSet.clientKey,
		caCert:     certSet.caCert,
	}

	require.NoError(t, resetFenceRatchetOnEnrollment(r, set), "first reset must succeed")
	require.NoError(t, resetFenceRatchetOnEnrollment(r, set), "second reset must also succeed (idempotent)")
}

// TestRegistration_FenceRatchet_VerificationRejectsUnverifiedMaterial pins the
// verification contract at the unit level: resetFenceRatchetOnEnrollment must return an
// error, and leave the ratchet untouched, for material that does not verify.
func TestRegistration_FenceRatchet_VerificationRejectsUnverifiedMaterial(t *testing.T) {
	dir := t.TempDir()
	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 4))

	err := resetFenceRatchetOnEnrollment(r, enrollmentCertSet{stewardID: "steward-abc"})
	require.Error(t, err, "an empty certificate set must be rejected")
	assert.Contains(t, err.Error(), "fence ratchet retained")

	ratchetSet, highest, loadErr := r.Load()
	require.NoError(t, loadErr)
	assert.True(t, ratchetSet)
	assert.Equal(t, uint64(4), highest)
}
