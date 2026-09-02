// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegister_202_ReturnsPendingResponse verifies that the real HTTPClient (the CFGMS component
// under test) correctly parses a 202 Accepted response and returns a non-nil
// *RegistrationPendingResponse with PendingID populated. The httptest.Server is a standard
// Go HTTP fixture — not a mock of a CFGMS component — used here because the steward package
// cannot import the controller package without inverting the dependency direction.
func TestRegister_202_ReturnsPendingResponse(t *testing.T) {
	pending := RegistrationPendingResponse{
		PendingID: "pending-1234567890",
		StewardID: "steward-abc",
		TenantID:  "test-tenant",
		Group:     "prod",
		Status:    "pending",
	}
	body, err := json.Marshal(pending)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		ControllerURL: srv.URL,
		Logger:        logging.NewLogger("debug"),
	})
	require.NoError(t, err)

	regResp, pendingResp, err := client.Register(context.Background(), RegistrationRequest{Token: "test-token"})
	require.NoError(t, err)
	assert.Nil(t, regResp, "RegistrationResponse must be nil on 202")
	require.NotNil(t, pendingResp, "RegistrationPendingResponse must be non-nil on 202")
	assert.Equal(t, "pending-1234567890", pendingResp.PendingID, "PendingID must be populated")
	assert.Equal(t, "test-tenant", pendingResp.TenantID)
	assert.Equal(t, "pending", pendingResp.Status)
}

// TestRegister_ErrorStatus_ReturnsError verifies that the HTTP client surfaces a non-nil
// error when the controller returns a non-200/202 status (e.g., 403 Forbidden on reject,
// 401 Unauthorized on invalid token). Neither RegistrationResponse nor
// RegistrationPendingResponse should be returned.
func TestRegister_ErrorStatus_ReturnsError(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "403 Forbidden", statusCode: http.StatusForbidden, body: "Registration rejected\n"},
		{name: "401 Unauthorized", statusCode: http.StatusUnauthorized, body: "Invalid or expired registration token\n"},
		{name: "500 InternalServerError", statusCode: http.StatusInternalServerError, body: "Server misconfiguration\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, tc.body, tc.statusCode)
			}))
			defer srv.Close()

			client, err := NewHTTPClient(&HTTPConfig{
				ControllerURL: srv.URL,
				Logger:        logging.NewLogger("debug"),
			})
			require.NoError(t, err)

			regResp, pendingResp, err := client.Register(context.Background(), RegistrationRequest{Token: "test-token"})
			require.Error(t, err, "non-200/202 status must return an error")
			assert.Nil(t, regResp, "RegistrationResponse must be nil on error status")
			assert.Nil(t, pendingResp, "RegistrationPendingResponse must be nil on error status")
			assert.Contains(t, err.Error(), "registration failed with status")
		})
	}
}

// TestRegistrationResponse_JSONFieldNames is a regression guard that ensures
// the wire format of RegistrationResponse has not changed. The JSON field names
// client_cert, client_key, and ca_cert are consumed by stewards in production;
// any rename would silently break existing deployments.
func TestRegistrationResponse_JSONFieldNames(t *testing.T) {
	resp := RegistrationResponse{
		ClientCert: "cert-pem",
		ClientKey:  "key-pem",
		CACert:     "ca-pem",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, raw, "client_cert", "wire field client_cert must not be renamed")
	assert.Contains(t, raw, "client_key", "wire field client_key must not be renamed")
	assert.Contains(t, raw, "ca_cert", "wire field ca_cert must not be renamed")
	assert.Equal(t, "cert-pem", raw["client_cert"])
	assert.Equal(t, "key-pem", raw["client_key"])
	assert.Equal(t, "ca-pem", raw["ca_cert"])
}

func TestNewHTTPClientAlwaysVerifiesTLS(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("empty CACertPath uses system roots with nil TLSClientConfig", func(t *testing.T) {
		client, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			Logger:        logger,
		})
		require.NoError(t, err)

		transport, ok := client.httpClient.Transport.(*http.Transport)
		require.True(t, ok, "transport must be *http.Transport")
		assert.Nil(t, transport.TLSClientConfig, "nil TLSClientConfig means system root CAs are used")
	})

	t.Run("valid CACertPath populates RootCAs and never sets InsecureSkipVerify", func(t *testing.T) {
		tmpDir := t.TempDir()

		ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
			Organization: "Test CA",
			Country:      "US",
			ValidityDays: 365,
		})
		require.NoError(t, err)
		require.NoError(t, ca.Initialize(nil))

		caPEM, err := ca.GetCACertificate()
		require.NoError(t, err)

		caPath := filepath.Join(tmpDir, "ca.crt")
		require.NoError(t, os.WriteFile(caPath, caPEM, 0600))

		client, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			CACertPath:    caPath,
			Logger:        logger,
		})
		require.NoError(t, err)

		transport, ok := client.httpClient.Transport.(*http.Transport)
		require.True(t, ok, "transport must be *http.Transport")
		require.NotNil(t, transport.TLSClientConfig, "TLSClientConfig must be set when CACertPath is provided")
		assert.NotNil(t, transport.TLSClientConfig.RootCAs, "RootCAs must be populated from the CA cert file")
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify, "InsecureSkipVerify must never be true")
	})

	t.Run("missing CACertPath file returns error", func(t *testing.T) {
		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			CACertPath:    "/nonexistent/path/ca.crt",
			Logger:        logger,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA cert")
	})

	t.Run("invalid PEM in CACertPath file returns error", func(t *testing.T) {
		tmpDir := t.TempDir()
		caPath := filepath.Join(tmpDir, "ca.crt")
		require.NoError(t, os.WriteFile(caPath, []byte("not-valid-pem"), 0600))

		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			CACertPath:    caPath,
			Logger:        logger,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create TLS config")
	})

	t.Run("empty ControllerURL returns error", func(t *testing.T) {
		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "",
			Logger:        logger,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "controller URL is required")
	})

	t.Run("nil Logger returns error", func(t *testing.T) {
		_, err := NewHTTPClient(&HTTPConfig{
			ControllerURL: "https://controller.example.com",
			Logger:        nil,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// TestPollStatus_JitterRange samples 100 intervals with base=90s and jitter=30s and
// asserts every result is in [90s, 120s). This proves the jitter never causes an underrun
// (below base) and never exceeds base+jitter.
func TestPollStatus_JitterRange(t *testing.T) {
	const base = 90 * time.Second
	const jitter = 30 * time.Second
	for i := 0; i < 100; i++ {
		got := computePollInterval(base, jitter)
		assert.GreaterOrEqual(t, got, base, "interval must be >= base (iteration %d)", i)
		assert.Less(t, got, base+jitter, "interval must be < base+jitter (iteration %d)", i)
	}
}

// TestComputePollInterval_ZeroJitter verifies that zero jitter returns exactly base.
func TestComputePollInterval_ZeroJitter(t *testing.T) {
	assert.Equal(t, 90*time.Second, computePollInterval(90*time.Second, 0))
}

// TestPollStatus_Pending verifies that a 200 with status="pending" is returned correctly.
func TestPollStatus_Pending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/registration/status/pending-123", r.URL.Path)
		assert.Equal(t, "Bearer reg-token-abc", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := client.PollStatus(context.Background(), "pending-123", "reg-token-abc", 0, 0)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "pending", resp.Status)
}

// TestPollStatus_Claimed_Returns410AsClaimedStatus verifies that HTTP 410 Gone is surfaced
// as RegistrationStatusResponse{Status:"claimed"} without an error, so the steward loop can
// stop without treating a second poll as an error condition.
func TestPollStatus_Claimed_Returns410AsClaimedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := client.PollStatus(context.Background(), "pending-xyz", "tok", 0, 0)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "claimed", resp.Status)
}

// TestPollStatus_Denied_IsTerminal verifies that a "denied" status is returned without error
// so the steward can cleanly exit the poll loop.
func TestPollStatus_Denied_IsTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := client.PollStatus(context.Background(), "pending-denied", "tok", 0, 0)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "denied", resp.Status)
}

// TestPollStatus_ApprovedWithCerts verifies that a claimed response with cert fields is decoded.
func TestPollStatus_ApprovedWithCerts(t *testing.T) {
	body := `{"status":"claimed","steward_id":"s1","tenant_id":"t1","client_cert":"CERT","client_key":"KEY","ca_cert":"CA"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := client.PollStatus(context.Background(), "pending-approved", "tok", 0, 0)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "claimed", resp.Status)
	assert.Equal(t, "CERT", resp.ClientCert)
	assert.Equal(t, "KEY", resp.ClientKey)
	assert.Equal(t, "CA", resp.CACert)
	assert.Equal(t, "s1", resp.StewardID)
}

// TestPollStatus_ErrorStatus_ReturnsError verifies that non-200/non-410 statuses return an error.
func TestPollStatus_ErrorStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := client.PollStatus(context.Background(), "pending-unauth", "bad-tok", 0, 0)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "status poll failed with HTTP 401")
}

// TestRegistrationRequest_IncludesDeviceIDAndIdentityKeyPub verifies that the new fields
// are serialised to JSON and sent to the controller.
func TestRegistrationRequest_IncludesDeviceIDAndIdentityKeyPub(t *testing.T) {
	var gotBody RegistrationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"steward_id":"s1","transport_address":"ctrl:4433"}`))
	}))
	defer srv.Close()

	client, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	req := RegistrationRequest{
		Token:          "tok",
		DeviceID:       "abcd1234",
		IdentityKeyPub: "base64pubkey==",
	}
	_, _, err = client.Register(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "tok", gotBody.Token)
	assert.Equal(t, "abcd1234", gotBody.DeviceID)
	assert.Equal(t, "base64pubkey==", gotBody.IdentityKeyPub)
}

// TestRefreshChallenge_200_ReturnsChallengeResponse verifies that a 200 response is decoded correctly.
func TestRefreshChallenge_200_ReturnsChallengeResponse(t *testing.T) {
	const deviceID = "aabbccdd"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/stewards/"+deviceID+"/refresh/challenge", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"nonce":"dGVzdG5vbmNl","server_ts":1234567890,"expires_in":60}`))
	}))
	defer srv.Close()

	cl, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := cl.RefreshChallenge(context.Background(), deviceID)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "dGVzdG5vbmNl", resp.Nonce)
	assert.Equal(t, uint64(1234567890), resp.ServerTS)
	assert.Equal(t, 60, resp.ExpiresIn)
}

// TestRefreshChallenge_403_ReturnsErrRefreshRejected verifies that HTTP 403 maps to ErrRefreshRejected.
func TestRefreshChallenge_403_ReturnsErrRefreshRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "revoked", http.StatusForbidden)
	}))
	defer srv.Close()

	cl, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := cl.RefreshChallenge(context.Background(), "device-id")
	assert.Nil(t, resp)
	require.ErrorIs(t, err, ErrRefreshRejected)
}

// TestRefreshComplete_200_ReturnsCerts verifies that HTTP 200 with cert fields is decoded.
func TestRefreshComplete_200_ReturnsCerts(t *testing.T) {
	const deviceID = "aabbccdd"
	body := `{"client_cert":"CERT","client_key":"KEY","ca_cert":"CA","server_cert":"SRV","transport_address":"ctrl:4433"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/stewards/"+deviceID+"/refresh/complete", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cl, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := cl.RefreshComplete(context.Background(), deviceID, "tenant-x", "nonce123", 1234567890, []byte("signature"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "CERT", resp.ClientCert)
	assert.Equal(t, "KEY", resp.ClientKey)
	assert.Equal(t, "CA", resp.CACert)
	assert.Equal(t, "ctrl:4433", resp.TransportAddress)
}

// TestRefreshComplete_202_ReturnsErrRefreshPending verifies that HTTP 202 maps to ErrRefreshPending.
func TestRefreshComplete_202_ReturnsErrRefreshPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	cl, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := cl.RefreshComplete(context.Background(), "device-id", "", "nonce", 0, []byte("sig"))
	assert.Nil(t, resp)
	require.ErrorIs(t, err, ErrRefreshPending)
}

// TestRefreshComplete_403_ReturnsErrRefreshRejected verifies that HTTP 403 maps to ErrRefreshRejected.
func TestRefreshComplete_403_ReturnsErrRefreshRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rejected", http.StatusForbidden)
	}))
	defer srv.Close()

	cl, err := NewHTTPClient(&HTTPConfig{ControllerURL: srv.URL, Logger: logging.NewLogger("debug")})
	require.NoError(t, err)

	resp, err := cl.RefreshComplete(context.Background(), "device-id", "", "nonce", 0, []byte("sig"))
	assert.Nil(t, resp)
	require.ErrorIs(t, err, ErrRefreshRejected)
}

// newIntermediateBackedEnrollmentCertSet builds a real CFGMS root CA, signs a
// subordinate (regional intermediate) from it, and issues a leaf from that
// intermediate — mirroring what a controller cell backed by an imported regional
// intermediate returns from a claimed registration (Issue #3778). Returns the
// full enrollmentCertSet plus the root-only PEM a steward would have pinned at
// its original enrollment.
func newIntermediateBackedEnrollmentCertSet(t *testing.T) (set enrollmentCertSet, rootCertPEM []byte) {
	t.Helper()

	rootMgr, err := cfgcert.NewManager(&cfgcert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &cfgcert.CAConfig{
			Organization:  "CFGMS Test Root",
			Country:       "US",
			ValidityDays:  3650,
			PathLength:    1,
			PathLengthSet: true,
		},
	})
	require.NoError(t, err)

	rootCertPEM, err = rootMgr.GetCACertificate()
	require.NoError(t, err)

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subCert, err := rootMgr.SignSubordinateCA(&subKey.PublicKey, &cfgcert.SubordinateCAConfig{
		CommonName:   "CFGMS Test Regional Intermediate",
		Organization: "CFGMS Test",
		ValidityDays: 3650,
		PathLength:   0,
	})
	require.NoError(t, err)

	subKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(subKey),
	})

	intermediateMgr, err := cfgcert.NewManagerFromCAMaterial(&cfgcert.ManagerConfig{
		StoragePath: t.TempDir(),
	}, subCert.CertificatePEM, subKeyPEM, rootCertPEM)
	require.NoError(t, err)

	leaf, err := intermediateMgr.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "steward-intermediate",
		Organization: "CFGMS Stewards",
		ClientID:     "steward-intermediate",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NotEmpty(t, leaf.IssuerChainPEM, "leaf issued by an intermediate-backed manager must carry a non-empty issuer chain")

	return enrollmentCertSet{
		stewardID:   "steward-intermediate",
		clientCert:  string(leaf.CertificatePEM),
		clientKey:   string(leaf.PrivateKeyPEM),
		caCert:      string(rootCertPEM),
		issuerChain: string(leaf.IssuerChainPEM),
	}, rootCertPEM
}

// TestVerifyEnrollmentCertSet_IntermediateChain_SucceedsWithRootOnlyPin proves
// the steward's TLS verification (verifyEnrollmentCertSet) succeeds against a
// leaf presented with its intermediate when only the root is pre-trusted — the
// real pkg/cert-generated chain, no static test certs. [REQUIRED TEST]
func TestVerifyEnrollmentCertSet_IntermediateChain_SucceedsWithRootOnlyPin(t *testing.T) {
	set, _ := newIntermediateBackedEnrollmentCertSet(t)

	err := verifyEnrollmentCertSet(set)
	assert.NoError(t, err, "leaf + delivered issuer chain must verify against a root-only trust pool")
}

// TestVerifyEnrollmentCertSet_IntermediateChain_FailsWithoutChain proves the
// chain is actually load-bearing: the same leaf, presented WITHOUT its issuer
// chain, must fail to verify against the same root-only pool — otherwise the
// success above would be vacuous.
func TestVerifyEnrollmentCertSet_IntermediateChain_FailsWithoutChain(t *testing.T) {
	set, _ := newIntermediateBackedEnrollmentCertSet(t)
	set.issuerChain = ""

	err := verifyEnrollmentCertSet(set)
	assert.Error(t, err, "a leaf from an intermediate CA must not verify against a root-only pool without its issuer chain")
}
