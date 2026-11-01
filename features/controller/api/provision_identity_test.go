// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/controlplane/internaldelivery"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// TestProvisionCertificate_NeverMintsAControllerPeerIdentity guards Issue #4665:
// the internal-delivery peer authorizer admits a controller-CA leaf whose
// CommonName is a cluster node ID unless it carries the steward Organization.
// Provisioning therefore always stamps that Organization, refuses any other, and
// refuses an identity naming a cluster node — for a root session and for an mTLS
// admin certificate alike — and a certificate it does mint is refused by the
// peer authorizer even when its CommonName is a cluster node's.
func TestProvisionCertificate_NeverMintsAControllerPeerIdentity(t *testing.T) {
	server, _, _ := setupProvisionTestServer(t)
	const nodeID = "ctrl-node-1"
	server.deliveryPeerNodeIDs = func() []string { return []string{nodeID} }

	callers := []struct {
		name string
		ctx  func(context.Context) context.Context
	}{
		{"root session", func(ctx context.Context) context.Context {
			return context.WithValue(withCallerTenant(ctx, ""), principalContextKey, boundRootOperator("provision-root-op"))
		}},
		{"mTLS admin certificate", func(ctx context.Context) context.Context {
			return context.WithValue(withCallerTenant(ctx, ""), principalContextKey, &Principal{
				ID: "provision-cert-admin", Assurance: session.AssuranceStrong, GlobalScope: true,
				ImplicitAdmin: true, CertSerial: "provision-cert-serial",
			})
		}},
	}
	provision := func(t *testing.T, ctx func(context.Context) context.Context, body map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/provision", bytes.NewReader(raw))
		req = req.WithContext(ctx(req.Context()))
		rec := httptest.NewRecorder()
		server.handleProvisionCertificate(rec, req)
		return rec
	}

	for _, c := range callers {
		t.Run(c.name, func(t *testing.T) {
			refused := []map[string]string{
				{"steward_id": nodeID},
				{"steward_id": "new-device-" + c.name, "common_name": nodeID},
				{"steward_id": "new-device-" + c.name, "organization": "CFGMS Controllers"},
			}
			for _, body := range refused {
				rec := provision(t, c.ctx, body)
				assert.Equal(t, http.StatusForbidden, rec.Code, "%v must be refused: %s", body, rec.Body.String())
			}

			rec := provision(t, c.ctx, map[string]string{"steward_id": "minted-" + c.name})
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			var resp struct {
				Data struct {
					CertificatePEM string `json:"certificate_pem"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			block, _ := pem.Decode([]byte(resp.Data.CertificatePEM))
			require.NotNil(t, block)
			leaf, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, []string{internaldelivery.StewardCertOrganization}, leaf.Subject.Organization)

			// Even an authorizer that lists the leaf's own CommonName as a cluster
			// node refuses it: the steward Organization is what keeps it out.
			authorizer := internaldelivery.NewPeerAuthorizer(func() []string { return []string{leaf.Subject.CommonName} }, nil)
			peerCtx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}},
			}})
			assert.Error(t, authorizer.Authorize(peerCtx), "a provisioned steward certificate must never pass the peer authorizer")
		})
	}
}

// TestRotateSigningCert_RequiresCertificate guards Issue #4665: binding root
// sessions to the root tenant gives them root scope, but signing-CA rotation —
// the largest-blast-radius certificate operation — stays with a
// certificate-authenticated root principal, as before.
func TestRotateSigningCert_RequiresCertificate(t *testing.T) {
	server := setupTestServer(t)
	// The certificate gate refuses before the service is used, so an unwired
	// service is enough to reach it.
	server.SetSigningRotationService(service.NewSigningRotationService(nil, logging.NewNoopLogger()))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/signing/rotate", bytes.NewReader([]byte(`{}`)))
	req = req.WithContext(context.WithValue(withCallerTenant(req.Context(), ""), principalContextKey, boundRootOperator("rotate-root-op")))
	rec := httptest.NewRecorder()
	server.handleRotateSigningCert(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}
