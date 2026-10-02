// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
// and a client certificate signed by it, with its own internally generated
// keypair — deliberately unrelated to any steward's own CSR. No mocks — the same
// central provider the controller uses to issue enrollment certificates issues
// these. Used directly (bypassing the wire) by tests that hand-build an
// enrollmentCertSet, and as a "certificate signed for someone else's key" fixture
// for tests that exercise the wire (Issue #3780: the wire carries no client_key
// field, so this is the only way a response can hand back a cert that doesn't
// pair with the steward's local key).
type issuedCertSet struct {
	clientCert string
	clientKey  string
	caCert     string
}

// newIssuedCertSet generates a fresh CA and a client certificate signed by it,
// mirroring what the controller returns from a claimed registration
// (features/controller/api/handlers_registration.go buildClaimResponse).
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

// issuingCA wraps a real pkg/cert CA that signs whatever CSR the steward under
// test submits, mirroring the controller's own SignClientCertificateRequest call
// (Issue #3780). This is what lets these tests drive the real HTTPClient end to
// end: the certificate a mock server hands back via signCSR is always issued for
// the exact keypair the client generated for its own CSR, so
// verifyEnrollmentCertSet sees a genuinely matching pair — never a static
// pre-baked one standing in for it.
type issuingCA struct {
	ca    *cfgcert.CA
	caPEM string
}

func newIssuingCA(t *testing.T) issuingCA {
	t.Helper()
	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Test Issuing CA",
		Country:      "US",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)
	return issuingCA{ca: ca, caPEM: string(caPEM)}
}

// signCSR parses csrPEM (as submitted by the real HTTPClient under test) and
// signs its public key into a client certificate, mirroring the controller's
// handleRegister / buildClaimResponse (Issue #3780).
func (i issuingCA) signCSR(t *testing.T, csrPEM, stewardID string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "CSR must be valid PEM")
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	issued, err := i.ca.SignClientCertificateRequest(csr.PublicKey, &cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		Organization: "CFGMS Stewards",
		ClientID:     stewardID,
		ValidityDays: 365,
	})
	require.NoError(t, err)
	return string(issued.CertificatePEM)
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
	issuer := newIssuingCA(t)

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
	// the registration immediately (HTTP 200), signing whatever CSR the real
	// steward keypair submits (Issue #3780).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var regReq RegistrationRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&regReq))
		body, err := json.Marshal(RegistrationResponse{
			Success:    true,
			StewardID:  "steward-abc",
			TenantID:   "test-tenant",
			ClientCert: issuer.signCSR(t, regReq.CSRPEM, "steward-abc"),
			CACert:     issuer.caPEM,
		})
		require.NoError(t, err)
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
// certificate set is the same enrollment completion as an immediate HTTP 200. The claimed
// certificate must be signed for the keypair Register generated when it originally
// submitted the CSR (Issue #3780) — this test drives Register then PollStatus on the
// same client instance, exactly as the steward's poll loop does.
func TestRegistration_FenceRatchet_ResetOnApprovedPoll(t *testing.T) {
	dir := t.TempDir()
	issuer := newIssuingCA(t)

	r := stewardconfig.NewFenceRatchet(dir)
	require.NoError(t, r.Save(true, 12))

	var gotCSRPEM string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodPost {
			var regReq RegistrationRequest
			require.NoError(t, json.NewDecoder(req.Body).Decode(&regReq))
			gotCSRPEM = regReq.CSRPEM
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"pending_id":"pending-1","steward_id":"steward-abc","status":"pending"}`))
			return
		}
		body, err := json.Marshal(RegistrationStatusResponse{
			Status:     enrollmentStatusClaimed,
			StewardID:  "steward-abc",
			TenantID:   "test-tenant",
			ClientCert: issuer.signCSR(t, gotCSRPEM, "steward-abc"),
			CACert:     issuer.caPEM,
		})
		require.NoError(t, err)
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
	require.NotEmpty(t, gotCSRPEM, "Register must submit a CSR")

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
	cases := []struct {
		name      string
		buildResp func(t *testing.T, issuer issuingCA, csrPEM string) RegistrationResponse
	}{
		{
			name: "no certificate material at all",
			buildResp: func(t *testing.T, issuer issuingCA, csrPEM string) RegistrationResponse {
				return RegistrationResponse{Success: true, StewardID: "steward-abc"}
			},
		},
		{
			name: "certificate present but CA missing",
			buildResp: func(t *testing.T, issuer issuingCA, csrPEM string) RegistrationResponse {
				return RegistrationResponse{Success: true, ClientCert: issuer.signCSR(t, csrPEM, "steward-abc")}
			},
		},
		{
			name: "non-PEM garbage in every field",
			buildResp: func(t *testing.T, issuer issuingCA, csrPEM string) RegistrationResponse {
				return RegistrationResponse{Success: true, ClientCert: "cert-pem", CACert: "ca-pem"}
			},
		},
		{
			name: "certificate was not issued for the steward's own key",
			buildResp: func(t *testing.T, issuer issuingCA, csrPEM string) RegistrationResponse {
				// The registration wire contract carries no client_key field to
				// disagree with directly (Issue #3780); the only way a response can
				// hand back a mismatched pair is a certificate signed for an
				// unrelated key, never the CSR this steward actually submitted.
				foreign := newIssuedCertSet(t)
				return RegistrationResponse{Success: true, ClientCert: foreign.clientCert, CACert: foreign.caCert}
			},
		},
		{
			name: "certificate does not chain to the delivered CA",
			buildResp: func(t *testing.T, issuer issuingCA, csrPEM string) RegistrationResponse {
				foreign := newIssuedCertSet(t)
				return RegistrationResponse{Success: true, ClientCert: issuer.signCSR(t, csrPEM, "steward-abc"), CACert: foreign.caCert}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			r := stewardconfig.NewFenceRatchet(dir)
			require.NoError(t, r.Save(true, 10))

			issuer := newIssuingCA(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var regReq RegistrationRequest
				require.NoError(t, json.NewDecoder(req.Body).Decode(&regReq))
				body, err := json.Marshal(tc.buildResp(t, issuer, regReq.CSRPEM))
				require.NoError(t, err)
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
	issuer := newIssuingCA(t)

	var gotCSRPEM string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var regReq RegistrationRequest
		require.NoError(t, json.NewDecoder(req.Body).Decode(&regReq))
		gotCSRPEM = regReq.CSRPEM
		body, err := json.Marshal(RegistrationResponse{
			Success:    true,
			StewardID:  "steward-abc",
			ClientCert: issuer.signCSR(t, regReq.CSRPEM, "steward-abc"),
			CACert:     issuer.caPEM,
		})
		require.NoError(t, err)
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
	require.NotEmpty(t, gotCSRPEM, "Register must submit a CSR")

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
