// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestCertManagerForProvisioning creates a real cert.Manager with a CA and a
// signing cert in a temp dir, for certificate provisioning tests.
func newTestCertManagerForProvisioning(t *testing.T) *cert.Manager {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Test",
			Country:      "US",
			ValidityDays: 1,
			KeySize:      2048,
		},
		StoragePath: t.TempDir(),
	})
	require.NoError(t, err)
	require.NoError(t, mgr.EnsureSigningCertificate(nil))
	return mgr
}

// TestProvisionCertificate_ValidityCeilingRejected is the required test for
// Issue #4346: a certificate request whose ValidityDays exceeds
// MaxCertificateValidityDays must be refused outright, not silently clamped.
func TestProvisionCertificate_ValidityCeilingRejected(t *testing.T) {
	certMgr := newTestCertManagerForProvisioning(t)
	svc := NewCertificateProvisioningService(certMgr, logging.NewNoopLogger())

	resp, err := svc.ProvisionCertificate(context.Background(), &CertificateProvisioningRequest{
		StewardID:    "steward-1",
		ValidityDays: MaxCertificateValidityDays + 1,
	})
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Success)
	assert.Empty(t, resp.CertificatePEM, "no certificate must be issued for a refused request")
}

// TestProvisionCertificate_ValidityAtCeilingAccepted proves the ceiling itself
// is not refused — only a request exceeding it.
func TestProvisionCertificate_ValidityAtCeilingAccepted(t *testing.T) {
	certMgr := newTestCertManagerForProvisioning(t)
	svc := NewCertificateProvisioningService(certMgr, logging.NewNoopLogger())

	resp, err := svc.ProvisionCertificate(context.Background(), &CertificateProvisioningRequest{
		StewardID:    "steward-1",
		ValidityDays: MaxCertificateValidityDays,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// stubStewardTenantResolver is a real, minimal StewardTenantResolver backed by
// a plain map — not a mock of ProvisionCertificate's own behaviour, just a
// fixed lookup table for the one method the interface declares.
type stubStewardTenantResolver map[string]string

func (r stubStewardTenantResolver) TenantForDevice(deviceID string) (string, bool) {
	tenantID, known := r[deviceID]
	return tenantID, known
}

// TestProvisionCertificate_CrossTenantDenied is the required test for Issue
// #4346: a caller authenticated to tenant-a must be refused when provisioning
// a certificate for a steward that authoritatively belongs to tenant-b.
func TestProvisionCertificate_CrossTenantDenied(t *testing.T) {
	certMgr := newTestCertManagerForProvisioning(t)
	svc := NewCertificateProvisioningService(certMgr, logging.NewNoopLogger())
	svc.SetTenantResolver(stubStewardTenantResolver{"steward-b": "tenant-b"})

	tenantACtx := context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a"))
	resp, err := svc.ProvisionCertificate(tenantACtx, &CertificateProvisioningRequest{
		StewardID: "steward-b",
	})
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Success)
	assert.Empty(t, resp.CertificatePEM, "no certificate must be issued for a refused cross-tenant request")
}

// TestProvisionCertificate_SameTenantAllowed proves the containment check is
// not simply fail-closed for every tenant-scoped caller — a caller whose scope
// contains the steward's real tenant must still succeed.
func TestProvisionCertificate_SameTenantAllowed(t *testing.T) {
	certMgr := newTestCertManagerForProvisioning(t)
	svc := NewCertificateProvisioningService(certMgr, logging.NewNoopLogger())
	svc.SetTenantResolver(stubStewardTenantResolver{"steward-a": "tenant-a"})

	tenantACtx := context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a"))
	resp, err := svc.ProvisionCertificate(tenantACtx, &CertificateProvisioningRequest{
		StewardID: "steward-a",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestProvisionCertificate_RootScopeBypassesContainment proves a root-scoped
// caller may provision for any steward, mirroring the REST handler's own
// root/unscoped exemption (Issue #4334).
func TestProvisionCertificate_RootScopeBypassesContainment(t *testing.T) {
	certMgr := newTestCertManagerForProvisioning(t)
	svc := NewCertificateProvisioningService(certMgr, logging.NewNoopLogger())
	svc.SetTenantResolver(stubStewardTenantResolver{"steward-b": "tenant-b"})

	rootCtx := context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
	resp, err := svc.ProvisionCertificate(rootCtx, &CertificateProvisioningRequest{
		StewardID: "steward-b",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestProvisionCertificate_UnknownStewardNotDeniedByServiceLayer proves the
// service-layer check does not newly 404/403 a steward the resolver cannot
// place (e.g. not yet registered) — that containment decision belongs to the
// REST handler (Issue #4334), which resolves via both the live registry and
// the durable store and denies unattributable stewards itself. The
// service-layer check here is a narrower, resolver-only safety net.
func TestProvisionCertificate_UnknownStewardNotDeniedByServiceLayer(t *testing.T) {
	certMgr := newTestCertManagerForProvisioning(t)
	svc := NewCertificateProvisioningService(certMgr, logging.NewNoopLogger())
	svc.SetTenantResolver(stubStewardTenantResolver{})

	tenantACtx := context.WithValue(context.Background(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a"))
	resp, err := svc.ProvisionCertificate(tenantACtx, &CertificateProvisioningRequest{
		StewardID: "steward-never-registered",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}
