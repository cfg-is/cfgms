// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	cfgapi "github.com/cfgis/cfgms/features/controller/api"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// seedModuleBundle stores a real, signed bundle in c and returns its address.
// Mirrors features/controller/api/handlers_module_approval_test.go's makePendingBundle —
// this package cannot import that test-only helper, so the construction is duplicated.
func seedModuleBundle(t *testing.T, c *cache.ModuleCache, publisher, name, version string) bundle.ContentAddress {
	t.Helper()
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	meta := &modules.ModuleMetadata{
		Name:      name,
		Version:   version,
		Publisher: publisher,
		Executors: []string{"steward"},
	}
	binaries := map[string][]byte{"linux-amd64": []byte("fake-binary-" + name)}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	contentHash, err := bundle.ComputeContentHash(binaries, manifestBytes)
	require.NoError(t, err)

	sig := ed25519.Sign(privKey, []byte(contentHash))
	b := &bundle.Bundle{
		Manifest: meta,
		Binaries: map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures: []bundle.BundleSignature{
			{Publisher: publisher, Algorithm: "ed25519", Signature: sig},
		},
		ContentHash: contentHash,
	}

	require.NoError(t, c.Put(b))
	return b.ContentAddress()
}

// moduleCacheDirFor mirrors features/controller/server/server.go's
// filepath.Join(resolveDNADataRoot(cfg), "module-cache"): resolveDNADataRoot returns
// cfg.DataDir unmodified whenever it is already an absolute path, which is true of
// every controllerConfig.Config built by newHealthTestControllerConfig (rooted under
// t.TempDir()).
func moduleCacheDirFor(cfg *controllerConfig.Config) string {
	return filepath.Join(cfg.DataDir, "module-cache")
}

// decodeEnvelope unwraps the standard {"data": ..., "timestamp": ...} APIResponse
// envelope (features/controller/api/middleware.go's writeSuccessResponse) into v.
func decodeEnvelope(t *testing.T, body []byte, v interface{}) {
	t.Helper()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	require.NoError(t, json.Unmarshal(envelope.Data, v))
}

// TestModuleListAndApprove_EndToEnd is the AC4 [REQUIRED TEST]: against a real
// controller (real storage, real certs, real HTTP — mirroring
// TestHealthDetailRoutes_EndToEnd's pattern), seed one pending and one approved
// bundle directly in the on-disk module cache the controller will read at startup,
// then exercise GET /api/v1/modules (Issue #4270's new route) and the
// GET /api/v1/modules/approvals lookup cfg module approve performs before resolving
// an address to POST.
//
// The actual POST .../approve mutation is now exercised through the real HTTP path
// (Issue #4287), driven through the full CLI presence relay a real cfg module
// approve run would use: lodge -> a genuine WebAuthn ceremony (real ECDSA P-256
// registration and assertion, verified by the same wa.FinishRegistration/FinishLogin
// production uses) -> collect -> retry with X-Presence-Token. module:approve carries
// RequireUserPresence: true (ADR-021 Decision 4); before Issue #4287 the CLI had no
// way to complete that ceremony at all (cmd/cfg/cmd/stepup.go's
// errPresenceCeremonyUnsupported failed fast), which is why this test previously
// bypassed the presence gate via a direct approval.ApprovalWorkflow call. This test
// proves both what #4270 changed — (1) the new GET /api/v1/modules route serves the
// real cache contents end-to-end, and (2) the address resolved from
// GET /api/v1/modules/approvals is the exact value runModuleApprove POSTs to — and
// what #4287 changed: that POST now succeeds for real, end to end.
func TestModuleListAndApprove_EndToEnd(t *testing.T) {
	var seedCache *cache.ModuleCache
	var pendingAddr, approvedAddr bundle.ContentAddress

	ctrl, _, base, _, client := startHealthTestControllerWithConfig(t, func(cfg *controllerConfig.Config) {
		var err error
		seedCache, err = cache.New(moduleCacheDirFor(cfg))
		require.NoError(t, err, "seed module cache")

		pendingAddr = seedModuleBundle(t, seedCache, "cfgms", "hyperv", "0.2.1")
		approvedAddr = seedModuleBundle(t, seedCache, "cfgms", "firewall", "1.0.0")
		require.NoError(t, seedCache.SetApprovalStatus(approvedAddr, cache.ApprovalStatusApproved))
	})

	t.Run("GET /api/v1/modules returns every status", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/modules")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Modules []struct {
				Publisher   string `json:"publisher"`
				Name        string `json:"name"`
				Version     string `json:"version"`
				ContentHash string `json:"content_hash"`
				Status      string `json:"status"`
			} `json:"modules"`
			Total int `json:"total"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Modules, 2)
		assert.Equal(t, 2, result.Total)

		byName := map[string]string{}
		for _, m := range result.Modules {
			byName[m.Name] = m.Status
		}
		assert.Equal(t, string(cache.ApprovalStatusPending), byName["hyperv"])
		assert.Equal(t, string(cache.ApprovalStatusApproved), byName["firewall"])
	})

	t.Run("GET /api/v1/modules?status=pending returns only the pending entry", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/modules?status=pending")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Modules []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"modules"`
			Total int `json:"total"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Modules, 1)
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "hyperv", result.Modules[0].Name)
		assert.Equal(t, string(cache.ApprovalStatusPending), result.Modules[0].Status)
	})

	var pendingAddress string
	t.Run("GET /api/v1/modules/approvals resolves the address cfg module approve POSTs to", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/modules/approvals")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Pending []struct {
				Address   string `json:"address"`
				Publisher string `json:"publisher"`
				Name      string `json:"name"`
				Version   string `json:"version"`
			} `json:"pending"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Pending, 1, "only the unapproved bundle is queued for review")
		entry := result.Pending[0]
		assert.Equal(t, pendingAddr.Publisher, entry.Publisher)
		assert.Equal(t, pendingAddr.Name, entry.Name)
		assert.Equal(t, pendingAddr.Version, entry.Version)
		require.NotEmpty(t, entry.Address)
		pendingAddress = entry.Address
	})

	t.Run("POST .../approve without a presence token is a registered-but-gated route, not a 404", func(t *testing.T) {
		require.NotEmpty(t, pendingAddress, "requires the previous subtest to have resolved an address")
		resp, err := client.Post(base+"/api/v1/modules/approvals/"+pendingAddress+"/approve", "application/json", nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		// AC5's own route-registration test treats this exact body as proof a path is
		// unregistered; asserting its absence here pins that this route is real.
		body, _ := io.ReadAll(resp.Body)
		assert.NotContains(t, string(body), routerCatchAll404)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"module:approve requires a presence token (ADR-021 Decision 4); a bare admin mTLS request gets a step-up challenge, not success or 404")
	})

	t.Run("approving via the real HTTP path — CLI presence relay end to end — is reflected through GET /api/v1/modules", func(t *testing.T) {
		// Issue #4287 [REQUIRED TEST]: cfg module approve succeeds end to end against
		// a real controller enforcing module:approve's RequireUserPresence: true.
		// This replaces the former approval.ApprovalWorkflow direct-call bypass (the
		// prior version of this subtest) with the real HTTP approve path, driven
		// through the full CLI presence relay: lodge -> browser-side WebAuthn
		// ceremony (a real ECDSA P-256 assertion, verified by wa.FinishLogin exactly
		// as production does) -> collect -> retry with X-Presence-Token. No mocks:
		// every step is a real HTTP request against the real running controller.
		require.NotEmpty(t, pendingAddress, "requires the earlier subtest to have resolved an address")

		wa, err := cfgapi.NewWebAuthnFromConfig("localhost", "localhost", []string{presenceRelayOrigin(t, base)})
		require.NoError(t, err)
		apiServer := ctrl.GetAPIServer()
		require.NotNil(t, apiServer, "controller must expose its underlying API server")
		apiServer.SetWebAuthn(wa)

		approver, approverCert := newAdminMTLSClient(t, ctrl, "presence-relay-approver")

		// Create a real account and bind this test's own admin cert to it, so every
		// subsequent request from `approver` resolves to this account's principal
		// (not the certless bootstrap-fallback admin) — the presence relay's account
		// checks (Desired State 3) require a real, resolvable account on both ends.
		createAcctBody, err := json.Marshal(map[string]interface{}{
			"username":   "presence-relay-approver",
			"root_scope": true,
		})
		require.NoError(t, err)
		acctResp, err := approver.Post(base+"/api/v1/accounts", "application/json", bytes.NewReader(createAcctBody))
		require.NoError(t, err)
		acctBody, err := io.ReadAll(acctResp.Body)
		require.NoError(t, err)
		_ = acctResp.Body.Close()
		require.Equal(t, http.StatusCreated, acctResp.StatusCode, "create account: %s", string(acctBody))

		bindBody, err := json.Marshal(map[string]string{
			"serial":      approverCert.SerialNumber.String(),
			"fingerprint": certFingerprint(approverCert),
			"label":       "presence-relay integration test",
		})
		require.NoError(t, err)
		bindResp, err := approver.Post(base+"/api/v1/accounts/presence-relay-approver/certs/bind", "application/json", bytes.NewReader(bindBody))
		require.NoError(t, err)
		bindRespBody, err := io.ReadAll(bindResp.Body)
		require.NoError(t, err)
		_ = bindResp.Body.Close()
		require.Equal(t, http.StatusCreated, bindResp.StatusCode, "bind cert: %s", string(bindRespBody))

		// Register a real WebAuthn credential on the account via the real HTTP
		// registration ceremony (begin + a genuine "none"-format attestation) — no
		// credential is injected directly; every byte here is what a real
		// authenticator would produce.
		priv, credID, cosePubKey := generateVirtualAuthenticatorCredential(t)
		registerVirtualCredential(t, approver, base, "presence-relay-approver", "localhost", presenceRelayOrigin(t, base), credID, cosePubKey)

		// 1. Lodge a presence request bound to the exact pending action.
		approvePath := "/api/v1/modules/approvals/" + pendingAddress + "/approve"
		emptyBodyHash := sha256.Sum256(nil)
		// The lodge body is the action binding and nothing else — there is no
		// human-readable description field, because the confirmation page renders the
		// bound values themselves as its consent text (ADR-021 Amendment 7 Decision 1).
		lodgeBody, err := json.Marshal(map[string]string{
			"method":      http.MethodPost,
			"path":        approvePath,
			"body_sha256": fmt.Sprintf("%x", emptyBodyHash),
			"permission":  "module:approve",
		})
		require.NoError(t, err)
		lodgeResp, err := approver.Post(base+"/api/v1/cli-presence/lodge", "application/json", bytes.NewReader(lodgeBody))
		require.NoError(t, err)
		lodgeRespBody, err := io.ReadAll(lodgeResp.Body)
		require.NoError(t, err)
		_ = lodgeResp.Body.Close()
		require.Equal(t, http.StatusCreated, lodgeResp.StatusCode, "lodge presence request: %s", string(lodgeRespBody))
		var lodged struct {
			Data struct {
				RequestID string `json:"request_id"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(lodgeRespBody, &lodged))
		require.NotEmpty(t, lodged.Data.RequestID)

		// 2. GET the pending request — the relay page's own read. What it returns is
		// what the page renders as consent text, so it must be the four values
		// requirePermission enforces in step 5 below, not a caller-authored string.
		getResp, err := approver.Get(base + "/api/v1/cli-presence/" + lodged.Data.RequestID)
		require.NoError(t, err)
		getRespBody, err := io.ReadAll(getResp.Body)
		require.NoError(t, err)
		_ = getResp.Body.Close()
		require.Equal(t, http.StatusOK, getResp.StatusCode, "read presence request: %s", string(getRespBody))
		var presenceRead struct {
			Data struct {
				Permission string `json:"permission"`
				Method     string `json:"method"`
				Path       string `json:"path"`
				BodyHash   string `json:"body_sha256"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(getRespBody, &presenceRead))
		require.Equal(t, "module:approve", presenceRead.Data.Permission)
		require.Equal(t, http.MethodPost, presenceRead.Data.Method)
		require.Equal(t, approvePath, presenceRead.Data.Path)
		require.Equal(t, fmt.Sprintf("%x", emptyBodyHash), presenceRead.Data.BodyHash)

		// 3. Run the real WebAuthn presence ceremony: begin, sign the challenge with
		// the registered credential's private key, finish bound to the lodged
		// request — mints an action-bound presence token and hands it to the
		// durable request record.
		beginResp, err := approver.Post(base+"/api/v1/webauthn/presence/begin", "application/json", nil)
		require.NoError(t, err)
		beginRespBody, err := io.ReadAll(beginResp.Body)
		require.NoError(t, err)
		_ = beginResp.Body.Close()
		require.Equal(t, http.StatusOK, beginResp.StatusCode, "presence begin: %s", string(beginRespBody))
		var beginEnvelope struct {
			Data struct {
				PublicKey struct {
					Challenge string `json:"challenge"`
				} `json:"publicKey"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(beginRespBody, &beginEnvelope))
		require.NotEmpty(t, beginEnvelope.Data.PublicKey.Challenge)

		assertionBody := buildVirtualAssertion(t, priv, credID, "localhost", presenceRelayOrigin(t, base), beginEnvelope.Data.PublicKey.Challenge, 1)
		finishURL := base + "/api/v1/webauthn/presence/finish?cli_presence_request_id=" + lodged.Data.RequestID
		finishResp, err := approver.Post(finishURL, "application/json", bytes.NewReader(assertionBody))
		require.NoError(t, err)
		finishRespBody, err := io.ReadAll(finishResp.Body)
		require.NoError(t, err)
		_ = finishResp.Body.Close()
		require.Equal(t, http.StatusOK, finishResp.StatusCode, "presence finish: %s", string(finishRespBody))

		// 4. Collect the minted presence token.
		collectResp, err := approver.Post(base+"/api/v1/cli-presence/"+lodged.Data.RequestID+"/collect", "application/json", nil)
		require.NoError(t, err)
		collectRespBody, err := io.ReadAll(collectResp.Body)
		require.NoError(t, err)
		_ = collectResp.Body.Close()
		require.Equal(t, http.StatusOK, collectResp.StatusCode, "collect presence token: %s", string(collectRespBody))
		var collected struct {
			Data struct {
				Status        string `json:"status"`
				PresenceToken string `json:"presence_token"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(collectRespBody, &collected))
		require.Equal(t, "collected", collected.Data.Status)
		require.NotEmpty(t, collected.Data.PresenceToken)

		// 5. Retry the original module-approve request, this time with the
		// action-bound presence token attached — this is cfg module approve's own
		// real HTTP path succeeding end to end.
		approveReq, err := http.NewRequest(http.MethodPost, base+approvePath, nil)
		require.NoError(t, err)
		approveReq.Header.Set("X-Presence-Token", collected.Data.PresenceToken)
		approveResp, err := approver.Do(approveReq)
		require.NoError(t, err)
		approveRespBody, err := io.ReadAll(approveResp.Body)
		require.NoError(t, err)
		_ = approveResp.Body.Close()
		require.Equal(t, http.StatusOK, approveResp.StatusCode, "module approve with presence token: %s", string(approveRespBody))

		resp, err := client.Get(base + "/api/v1/modules?status=approved")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Modules []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"modules"`
			Total int `json:"total"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Modules, 2, "both bundles are now approved")
		names := map[string]bool{}
		for _, m := range result.Modules {
			assert.Equal(t, string(cache.ApprovalStatusApproved), m.Status)
			names[m.Name] = true
		}
		assert.True(t, names["hyperv"], "the formerly-pending bundle must now show as approved")
		assert.True(t, names["firewall"])
	})
}

// presenceRelayOrigin derives the WebAuthn RP origin for this test's controller:
// "localhost", not "127.0.0.1" — go-webauthn refuses an IP-address RPID
// (TestNewWebAuthnFromConfig_RejectsIPAddressRPID), and the test controller's TLS
// certificate already carries "localhost" as a SAN (newHealthTestControllerConfig),
// so the WebAuthn ceremony's origin can reference it even though every actual HTTP
// request in this test still dials the same 127.0.0.1 listener.
func presenceRelayOrigin(t *testing.T, base string) string {
	t.Helper()
	return strings.Replace(base, "127.0.0.1", "localhost", 1)
}

// newAdminMTLSClient generates a fresh admin-marked mTLS client certificate against
// ctrl's own certificate manager and returns an *http.Client authenticated with it,
// alongside the parsed leaf certificate (needed for the cert-binding serial and
// fingerprint). Mirrors startHealthTestControllerWithConfig's own admin bundle
// construction (health_routes_test.go), duplicated here because that helper does not
// expose the raw certificate.
func newAdminMTLSClient(t *testing.T, ctrl interface {
	GetCertificateManager() *cert.Manager
}, commonName string) (*http.Client, *x509.Certificate) {
	t.Helper()
	certMgr := ctrl.GetCertificateManager()
	require.NotNil(t, certMgr)

	bundle, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       commonName,
		Organization:     "CFGMS",
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(bundle.CertificatePEM, bundle.PrivateKeyPEM)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
	return client, leaf
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of cert's raw DER bytes,
// mirroring extractAdminPrincipal's own fingerprint computation (middleware.go).
func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return fmt.Sprintf("%x", sum)
}

// padCoord left-pads b to 32 bytes — the fixed EC2 coordinate length a P-256 COSE key
// requires.
func padCoord(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// generateVirtualAuthenticatorCredential creates a real ECDSA P-256 keypair and
// returns it alongside a credential ID and the COSE-encoded public key bytes — the
// same construction technique features/controller/api's own webauthn tests use
// (generateSyntheticCredential in handlers_operator_payload_sign_test.go), duplicated
// here because this package cannot import that test-only helper across the package
// boundary.
func generateVirtualAuthenticatorCredential(t *testing.T) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   2, // EC2
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: padCoord(priv.X.Bytes()),
		YCoord: padCoord(priv.Y.Bytes()),
	}
	pubKeyBytes, err := webauthncbor.Marshal(coseKey)
	require.NoError(t, err)

	credID := []byte("presence-relay-virtual-credential-1")
	return priv, credID, pubKeyBytes
}

// buildNoneAttestationObject assembles a real, spec-shaped "none"-format
// attestationObject: authData (rpIDHash || flags || signCount || AAGUID ||
// credIDLen || credID || COSE public key) wrapped as {"fmt":"none","attStmt":{},
// "authData":<bytes>} — the exact CBOR map shape protocol.AttestationObject decodes
// (attestation.go's attestationObjectEncoded), built with real bytes, not a mock.
func buildNoneAttestationObject(t *testing.T, rpID string, credID, cosePubKey []byte) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))

	authData := make([]byte, 0, 32+1+4+16+2+len(credID)+len(cosePubKey))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x45) // UP | UV | AT
	authData = append(authData, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID: zeroed (no vendor identity asserted)
	authData = append(authData, byte(len(credID)>>8), byte(len(credID)))
	authData = append(authData, credID...)
	authData = append(authData, cosePubKey...)

	attObj, err := webauthncbor.Marshal(map[string]interface{}{
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
		"authData": authData,
	})
	require.NoError(t, err)
	return attObj
}

// registerVirtualCredential drives the real HTTP WebAuthn registration ceremony
// (begin + finish) for username against a real running controller, using a genuine
// "none"-format attestation built from credID/cosePubKey — no credential is injected
// directly into any store.
func registerVirtualCredential(t *testing.T, client *http.Client, base, username, rpID, origin string, credID, cosePubKey []byte) {
	t.Helper()

	beginResp, err := client.Post(base+"/api/v1/accounts/"+username+"/webauthn/register/begin", "application/json", nil)
	require.NoError(t, err)
	beginBody, err := io.ReadAll(beginResp.Body)
	require.NoError(t, err)
	_ = beginResp.Body.Close()
	require.Equal(t, http.StatusOK, beginResp.StatusCode, "register begin: %s", string(beginBody))

	var beginEnvelope struct {
		Data struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(beginBody, &beginEnvelope))
	require.NotEmpty(t, beginEnvelope.Data.PublicKey.Challenge)

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": beginEnvelope.Data.PublicKey.Challenge,
		"origin":    origin,
	})
	require.NoError(t, err)

	attObj := buildNoneAttestationObject(t, rpID, credID, cosePubKey)

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	finishBody, err := json.Marshal(map[string]interface{}{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
		},
	})
	require.NoError(t, err)

	finishResp, err := client.Post(base+"/api/v1/accounts/"+username+"/webauthn/register/finish", "application/json", bytes.NewReader(finishBody))
	require.NoError(t, err)
	finishRespBody, err := io.ReadAll(finishResp.Body)
	require.NoError(t, err)
	_ = finishResp.Body.Close()
	require.Equal(t, http.StatusCreated, finishResp.StatusCode, "register finish: %s", string(finishRespBody))
}

// buildVirtualAssertion signs challengeB64 (the base64url challenge the server
// issued) with priv and returns a JSON PublicKeyCredential assertion response body,
// using authenticator flags UP|UV (0x05) and the given sign count — the same real
// ECDSA-signature construction features/controller/api's own webauthn tests use
// (buildSignAssertionBody in handlers_operator_payload_sign_test.go), duplicated here
// for the same package-boundary reason as generateVirtualAuthenticatorCredential.
func buildVirtualAssertion(t *testing.T, priv *ecdsa.PrivateKey, credID []byte, rpID, origin, challengeB64 string, signCount uint32) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData[:32], rpIDHash[:])
	authData[32] = 0x05 // UP | UV
	authData[33] = byte(signCount >> 24)
	authData[34] = byte(signCount >> 16)
	authData[35] = byte(signCount >> 8)
	authData[36] = byte(signCount)

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": challengeB64,
		"origin":    origin,
	})
	require.NoError(t, err)

	clientDataHash := sha256.Sum256(clientData)
	sigData := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(sigData)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	require.NoError(t, err)

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	body, err := json.Marshal(map[string]interface{}{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	})
	require.NoError(t, err)
	return body
}
