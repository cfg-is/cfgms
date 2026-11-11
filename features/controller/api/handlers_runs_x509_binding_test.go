// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configsignature "github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The X.509 operator proof is bound to the authenticated principal's account: these tests drive
// POST /api/v1/runs/command through the real handler with certificates issued by the real
// certificate manager.

const bindingContent = "hostname"

func bindingPrincipal(id string) *Principal {
	return runPrincipal(id, []string{"steward:execute-scripts"}, "test-tenant")
}

// certSerial returns the serial of the certificate in a signature block's public_key.
func certSerial(t *testing.T, fields map[string]interface{}) string {
	t.Helper()
	sig := fields["signature"].(map[string]interface{})
	block, _ := pem.Decode([]byte(sig["public_key"].(string)))
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return parsed.SerialNumber.String()
}

func commandBodyWith(fields map[string]interface{}) map[string]interface{} {
	return withEnvelopeFields(map[string]interface{}{
		"target":  "id:steward-1",
		"content": base64.StdEncoding.EncodeToString([]byte(bindingContent)),
		"shell":   "bash",
	}, fields)
}

// deniedDispatchAudit returns the denied dispatch audit entry; entries come back in no
// guaranteed order, so it is selected by result rather than position.
func deniedDispatchAudit(t *testing.T, audits []*business.AuditEntry) *business.AuditEntry {
	t.Helper()
	for _, e := range audits {
		if e.Result == business.AuditResultDenied {
			return e
		}
	}
	require.Fail(t, "no denied dispatch audit record was written")
	return nil
}

func dispatchAudits(t *testing.T, server *Server) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	var out []*business.AuditEntry
	for _, e := range entries {
		if e.Action == "operator_payload.dispatch" {
			out = append(out, e)
		}
	}
	return out
}

// [REQUIRED TEST] a request authenticated as principal B carrying a valid certificate bound to
// principal A is refused with the generic error and a denied audit record naming B and the
// certificate serial; the same request authenticated as A is accepted.
func TestPostRunCommand_X509CertificateBoundToAnotherPrincipalRefused(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "test-tenant"}}
	server, _, queue := setupRunServer(t, stewards)
	principalA, principalB := bindingPrincipal("acct-a"), bindingPrincipal("acct-b")
	seedOperatorAccount(t, server, "acct-b", true)
	fields := signedOperatorEnvelopeFields(t, server, "acct-a", []byte(bindingContent), "bash", []string{"steward-1"})
	serial := certSerial(t, fields)

	rec := postRunCommand(t, server, principalB, commandBodyWith(fields))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalid operator signature")
	assert.Contains(t, rec.Body.String(), "INVALID_SIGNATURE")
	assert.Empty(t, queue.PeekForDevice("steward-1"), "a refused proof must not queue anything")

	audits := dispatchAudits(t, server)
	require.Len(t, audits, 1, "a binding failure must be audited")
	assert.Equal(t, business.AuditResultDenied, audits[0].Result)
	assert.Equal(t, "acct-b", audits[0].UserID, "the audit names the dispatching principal")
	assert.Equal(t, serial, audits[0].ResourceID, "the audit names the certificate serial")
	assert.Equal(t, "signing certificate is not bound to the dispatching principal", audits[0].Details["rejection_reason"])

	rec = postRunCommand(t, server, principalA, commandBodyWith(fields))
	require.Equal(t, http.StatusOK, rec.Code, "the same request authenticated as the owner must be accepted: %s", rec.Body.String())
	assert.NotEmpty(t, queue.PeekForDevice("steward-1"))
}

// [REQUIRED TEST] a certificate issued to an account through a CLI session and used from a web
// session of the same account is accepted: the binding is the account ID, not the CommonName.
func TestPostRunCommand_X509CertificateAcceptedFromAnotherSessionOfSameAccount(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)
	acct := seedOperatorAccount(t, server, "acct-shared", true)

	// Issued through the real endpoint as a CLI Bearer session of the account.
	cliSession := &Principal{
		Channel: AuthChannelCfgBearer, ID: acct.ID, Name: "session:" + acct.ID, Assurance: session.AssuranceStrong,
		TenantID: "test-tenant", AccountBound: true,
	}
	issued := issueSigningCredentialAs(t, server, cliSession)

	webSession := &Principal{
		Channel: AuthChannelWebCookie, ID: acct.ID, Name: "web-session:" + acct.ID, Assurance: session.AssuranceStrong,
		Permissions: []string{"steward:execute-scripts"}, TenantID: "test-tenant", AccountBound: true,
	}
	assert.NotEqual(t, cliSession.Name, webSession.Name, "the two sessions are distinct principals of one account")
	fields := signedFieldsWithIssuedCredential(t, issued, []byte(bindingContent), "bash", []string{"steward-1"})
	rec := postRunCommand(t, server, webSession, commandBodyWith(fields))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// [REQUIRED TEST] the owning account was disabled, or lost operator-payload:sign, after
// issuance: the certificate is refused on the next request.
func TestPostRunCommand_X509OwnerDisabledOrLostGrantRefused(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "test-tenant"}}

	for name, mutate := range map[string]func(*account){
		"account disabled": func(a *account) { a.Disabled = true },
		"grant removed":    func(a *account) { a.Permissions = nil },
		"grant to other":   func(a *account) { a.Permissions = []string{"steward:read-scripts"} },
	} {
		t.Run(name, func(t *testing.T) {
			server, _, queue := setupRunServer(t, stewards)
			p := bindingPrincipal("acct-owner")
			acct := seedOperatorAccount(t, server, p.ID, true)
			fields := signedOperatorEnvelopeFields(t, server, p.ID, []byte(bindingContent), "bash", []string{"steward-1"})
			require.Equal(t, http.StatusOK, postRunCommand(t, server, p, commandBodyWith(fields)).Code, "sanity: accepted while authorized")

			mutate(acct)
			require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
			server.cacheAccount(acct)

			before := len(queue.PeekForDevice("steward-1"))
			rec := postRunCommand(t, server, p, commandBodyWith(fields))
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "invalid operator signature")
			assert.Len(t, queue.PeekForDevice("steward-1"), before, "nothing may be queued for a refused proof")

			denied := deniedDispatchAudit(t, dispatchAudits(t, server))
			assert.Equal(t, p.ID, denied.UserID)
			assert.Contains(t, denied.Details["rejection_reason"], OperatorPayloadSignGrant)
		})
	}
}

// [REQUIRED TEST] a payload-signing certificate with no account binding is refused, and so is a
// principal that is not account-bound even when it presents a certificate bound to its ID.
func TestPostRunCommand_X509UnboundCertificateAndAccountlessPrincipalRefused(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "test-tenant"}}
	server, _, queue := setupRunServer(t, stewards)
	p := bindingPrincipal("acct-owner")
	seedOperatorAccount(t, server, p.ID, true)

	t.Run("certificate without the binding extension", func(t *testing.T) {
		fields := signedOperatorEnvelopeFieldsWithMarker(t, server, []byte(bindingContent), "bash", []string{"steward-1"}, cert.SetPayloadSigningMarker)
		rec := postRunCommand(t, server, p, commandBodyWith(fields))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "invalid operator signature")
		denied := deniedDispatchAudit(t, dispatchAudits(t, server))
		assert.Equal(t, "signing certificate is not bound to an account", denied.Details["rejection_reason"])
	})
	t.Run("principal that is not account-bound", func(t *testing.T) {
		fields := signedOperatorEnvelopeFields(t, server, p.ID, []byte(bindingContent), "bash", []string{"steward-1"})
		bootstrap := bindingPrincipal(p.ID)
		bootstrap.AccountBound = false // the bootstrap mTLS admin, an API key, an unbound CLI session
		rec := postRunCommand(t, server, bootstrap, commandBodyWith(fields))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "invalid operator signature")
	})
	assert.Empty(t, queue.PeekForDevice("steward-1"))
}

// [REQUIRED TEST] an X.509 verification failure body carries no certificate, chain or
// revocation detail, whatever the cause.
func TestPostRunCommand_X509FailureBodyCarriesNoDetail(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)
	p := bindingPrincipal("acct-owner")
	seedOperatorAccount(t, server, p.ID, true)

	foreignCA := newTLSTestCertManager(t)
	foreign, err := foreignCA.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "x", ValidityDays: 1, KeySize: 2048, TemplateModifier: boundSigningMarker(p.ID),
	})
	require.NoError(t, err)

	revoked := signedOperatorEnvelopeFields(t, server, p.ID, []byte(bindingContent), "bash", []string{"steward-1"})
	require.NoError(t, server.certManager.Revoke(certSerial(t, revoked)))

	cases := map[string]map[string]interface{}{
		"revoked certificate": revoked,
		"admin-marked only":   signedOperatorEnvelopeFieldsWithMarker(t, server, []byte(bindingContent), "bash", []string{"steward-1"}, cert.SetAdminMarker),
		"unbound":             signedOperatorEnvelopeFieldsWithMarker(t, server, []byte(bindingContent), "bash", []string{"steward-1"}, cert.SetPayloadSigningMarker),
		"foreign CA": {
			"signature": map[string]interface{}{"algorithm": "rsa-sha256", "value": "AAAA", "public_key": string(foreign.CertificatePEM)},
			"targets":   []string{"steward-1"}, "nonce": "n", "expires_at": "2099-01-01T00:00:00Z",
		},
		"not a certificate": {
			"signature": map[string]interface{}{"algorithm": "rsa-sha256", "value": "AAAA", "public_key": "not pem"},
			"targets":   []string{"steward-1"}, "nonce": "n", "expires_at": "2099-01-01T00:00:00Z",
		},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			rec := postRunCommand(t, server, p, commandBodyWith(fields))
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			var resp ErrorResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.Equal(t, "INVALID_SIGNATURE", resp.Error.Code)
			assert.Equal(t, "invalid operator signature", resp.Error.Message)
			body := strings.ToLower(rec.Body.String())
			for _, leak := range []string{"revoked", "chain", "certificate", "payload-signing", "bound", "trusted", "marker", "x509", "grant"} {
				assert.NotContains(t, body, leak, "the failure body must not describe why the proof failed")
			}
		})
	}
}

// A successful dispatch records both the dispatching principal and the signing certificate serial.
func TestPostRunCommand_X509SuccessAuditNamesPrincipalAndSerial(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)
	p := bindingPrincipal("acct-owner")
	fields := signedOperatorEnvelopeFields(t, server, p.ID, []byte(bindingContent), "bash", []string{"steward-1"})

	require.Equal(t, http.StatusOK, postRunCommand(t, server, p, commandBodyWith(fields)).Code)

	audits := dispatchAudits(t, server)
	require.Len(t, audits, 1)
	assert.Equal(t, business.AuditResultSuccess, audits[0].Result)
	assert.Equal(t, p.ID, audits[0].UserID)
	assert.Equal(t, certSerial(t, fields), audits[0].ResourceID)
}

// issuedSigningCredential is a payload-signing credential as handleRequestSigningCredential
// returns it, with the private key that never left the test.
type issuedSigningCredential struct {
	priv    *ecdsa.PrivateKey
	certPEM string
	serial  string
}

// issueSigningCredentialAs requests a payload-signing credential through the real handler,
// authenticated as principal.
func issueSigningCredentialAs(t *testing.T, server *Server, principal *Principal) issuedSigningCredential {
	t.Helper()
	priv, pubPEM := generateSigningCredentialTestKey(t)
	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signing-credential/request", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(principal.TenantID))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleRequestSigningCredential(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp struct {
		Data SigningCredentialResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return issuedSigningCredential{priv: priv, certPEM: resp.Data.CertificatePEM, serial: resp.Data.SerialNumber}
}

// signedFieldsWithIssuedCredential signs an operator envelope over content with an issued
// credential and returns the run-command request fields, like signedOperatorEnvelopeFields does
// for a certificate the test mints directly.
func signedFieldsWithIssuedCredential(t *testing.T, issued issuedSigningCredential, content []byte, shell string, targets []string) map[string]interface{} {
	t.Helper()
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	envelope := operatorpayload.Envelope{
		Content: content, Shell: shell, Targets: targets,
		Nonce: hex.EncodeToString(nonce), ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	canonical, err := operatorpayload.CanonicalBytes(envelope)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(issued.priv)
	require.NoError(t, err)
	signer, err := configsignature.NewSigner(&configsignature.SignerConfig{
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		CertificatePEM: []byte(issued.certPEM),
	})
	require.NoError(t, err)
	signed, err := signer.Sign(canonical)
	require.NoError(t, err)
	return map[string]interface{}{
		"signature": map[string]interface{}{
			"algorithm": string(signed.Algorithm), "value": signed.Signature, "public_key": issued.certPEM,
		},
		"targets": envelope.Targets, "nonce": envelope.Nonce,
		"expires_at": envelope.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// Issuance: the credential carries the owning account's ID, never derived from the CommonName.
func TestHandleRequestSigningCredential_BindsCertificateToAccount(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	acct := seedOperatorAccount(t, server, "acct-issue", true)
	p := &Principal{
		Channel: AuthChannelCfgBearer, ID: acct.ID, Name: "session:display-name-not-the-account",
		Assurance: session.AssuranceStrong, TenantID: "test-tenant", AccountBound: true,
	}
	issued := issueSigningCredentialAs(t, server, p)

	parsed, err := cert.ParseCertificateFromPEM([]byte(issued.certPEM))
	require.NoError(t, err)
	bound, ok := cert.AccountBindingFromCertificate(parsed)
	require.True(t, ok, "an issued payload-signing certificate must carry the account binding")
	assert.Equal(t, acct.ID, bound)
	assert.NotEqual(t, parsed.Subject.CommonName, bound, "the CommonName is display-only; the binding is the account ID")
	assert.True(t, cert.HasPayloadSigningMarker(parsed))
}

// [REQUIRED TEST] a principal that is not account-bound is refused a payload-signing certificate
// and nothing is issued: the bootstrap mTLS admin, an API-key-shaped principal and an unbound
// CLI session have no account to bind.
func TestHandleRequestSigningCredential_AccountlessPrincipalRefused(t *testing.T) {
	for name, p := range map[string]*Principal{
		"bootstrap mTLS admin": {Channel: AuthChannelMTLS, ID: "bootstrap-admin", Name: "mtls-admin:bootstrap-admin", Assurance: session.AssuranceStrong, ImplicitAdmin: true, TenantID: "test-tenant"},
		"unbound CLI session":  {Channel: AuthChannelCfgBearer, ID: "cli-principal", Name: "session:cli-principal", Assurance: session.AssuranceStrong, ImplicitAdmin: true, TenantID: "test-tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			server, _, _ := setupRunServer(t, nil)
			before, err := server.certManager.ListCertificates()
			require.NoError(t, err)

			_, pubPEM := generateSigningCredentialTestKey(t)
			body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/signing-credential/request", bytes.NewReader(body))
			ctx := context.WithValue(req.Context(), principalContextKey, p)
			ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(p.TenantID))
			rec := httptest.NewRecorder()
			server.handleRequestSigningCredential(rec, req.WithContext(ctx))

			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "ACCOUNT_BINDING_REQUIRED")
			after, err := server.certManager.ListCertificates()
			require.NoError(t, err)
			assert.Len(t, after, len(before), "a refused request must not issue a certificate")
			assert.Empty(t, auditEntriesByAction(t, server, "signing_credential_issued"))
		})
	}
}

// The credential-request and renewal issuance paths stamp the same binding as the signing
// credential endpoint, because a payload-signing certificate without one is refused everywhere.
func TestCredentialMarkerModifier_PayloadSigningIsBoundToTheAccount(t *testing.T) {
	stamp := func(markers []string, accountID string) *x509.Certificate {
		tpl := &x509.Certificate{}
		credentialMarkerModifier(markers, accountID)(tpl)
		return &x509.Certificate{Extensions: append([]pkix.Extension{}, tpl.ExtraExtensions...)}
	}

	bound := stamp([]string{credentialMarkerPayloadSigning}, "acct-collect")
	assert.True(t, cert.HasPayloadSigningMarker(bound))
	id, ok := cert.AccountBindingFromCertificate(bound)
	require.True(t, ok)
	assert.Equal(t, "acct-collect", id)

	adminOnly := stamp([]string{credentialMarkerAdmin}, "acct-collect")
	assert.True(t, cert.HasAdminMarker(adminOnly))
	_, ok = cert.AccountBindingFromCertificate(adminOnly)
	assert.False(t, ok, "an admin transport bundle carries no account binding")

	unbindable := stamp([]string{credentialMarkerPayloadSigning}, "")
	assert.False(t, cert.HasPayloadSigningMarker(unbindable),
		"a payload-signing marker is never stamped without a binding to go with it")
}
