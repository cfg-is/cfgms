// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const ccTestToken = "ghp_Qx7-credential-token-9921"

var ccRoutePut = m365Route{http.MethodPut, "/config-source/credential", "tenant", "manage",
	func(s *Server) http.HandlerFunc { return s.handlePutTenantConfigSourceCredential }}

// ccUsePublicResolver makes every host name resolve to a public documentation address,
// so admission performs no real DNS lookup.
func ccUsePublicResolver(t *testing.T) {
	t.Helper()
	t.Cleanup(cfgpkg.UseHostResolverForTesting(ccPublicResolver{}))
}

type ccPublicResolver struct{}

func (ccPublicResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
}

func ccPut(t *testing.T, env *m365Env, id, url, token string) *httptest.ResponseRecorder {
	t.Helper()
	ccUsePublicResolver(t)
	return m365Do(t, env.server, m365AdminPrincipal(), ccRoutePut, id, map[string]interface{}{"url": url, "token": token})
}

func ccStored(t *testing.T, env *m365Env, id string) *secretsif.Secret {
	t.Helper()
	sec, err := env.server.secretStore.GetSecret(context.Background(), id+"/config-source-git")
	require.NoError(t, err)
	return sec
}

// ccGitServer is a TLS git smart-HTTP stub that advertises an empty repository only to
// a caller presenting wantToken as the basic-auth password.
func ccGitServer(t *testing.T, wantToken string) string {
	t.Helper()
	ccUsePublicResolver(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pw, ok := r.BasicAuth(); !ok || pw != wantToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = fmt.Fprint(w, pkt("# service=git-upload-pack\n")+"0000"+
			pkt("0000000000000000000000000000000000000000 capabilities^{}\x00agent=test\n")+"0000")
	}))
	t.Cleanup(srv.Close)
	return fmt.Sprintf("https://localhost:%d/repo", srv.Listener.Addr().(*net.TCPAddr).Port)
}

func TestConfigSourceCredential_StoresBoundSecret(t *testing.T) {
	env := newM365Env(t)
	repo := ccGitServer(t, ccTestToken)

	rec := ccPut(t, env, "client-a1", repo, ccTestToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Data configSourceCredentialResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "client-a1/config-source-git", body.Data.CredentialRef)
	assert.Equal(t, cfgpkg.NormalizeRepositoryURL(repo), body.Data.BoundRepositoryURL)
	assert.NotContains(t, rec.Body.String(), ccTestToken)

	sec := ccStored(t, env, "client-a1")
	assert.Equal(t, ccTestToken, sec.Value)
	assert.Equal(t, body.Data.BoundRepositoryURL, sec.Metadata[cfgpkg.SecretMetaKeyBoundRepositoryURL])
	require.NoError(t, cfgpkg.CheckCredentialBinding(sec, repo))
	assert.Error(t, cfgpkg.CheckCredentialBinding(sec, repo+"-other"))

	// The git router and ValidateMountPoint read this same store: the stored credential
	// authenticates against a remote that accepts only the token.
	info := &cfgpkg.ConfigSourceInfo{Type: cfgpkg.ConfigSourceTypeGit, URL: repo, CredentialRef: body.Data.CredentialRef}
	v := cfgpkg.NewDefaultMountPointValidator(cfgpkg.WithInsecureSkipTLS())
	require.NoError(t, v.ValidateMountPoint(context.Background(), info, env.server.secretStore))

	// The credential_ref is accepted for a tenant that has a parent (flat tenant ID).
	_, err := env.server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{
		ID: "client-a9", Name: "Client-A9", ParentID: "msp-a",
		Metadata: map[string]string{cfgpkg.MetaKeyConfigSourceCredential: "client-a9/config-source-git"},
	})
	require.NoError(t, err)
	rec = ccPut(t, env, "client-a9", repo, ccTestToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	td, err := env.server.tenantManager.GetTenant(context.Background(), "client-a9")
	require.NoError(t, err)
	assert.Equal(t, "client-a9/config-source-git", td.Metadata[cfgpkg.MetaKeyConfigSourceCredential])
	_, err = env.server.tenantManager.UpdateTenant(context.Background(), "client-a1", &tenant.TenantRequest{
		Name:     "Client-A1",
		Metadata: map[string]string{cfgpkg.MetaKeyConfigSourceCredential: body.Data.CredentialRef},
	})
	require.NoError(t, err)
}

func TestConfigSourceCredential_SecondPutReplaces(t *testing.T) {
	env := newM365Env(t)
	require.Equal(t, http.StatusOK, ccPut(t, env, "client-a1", "https://git.example.com/a/one.git", "token-one").Code)
	rec := ccPut(t, env, "client-a1", "https://Git.Example.com:443/a/two/", "token-two")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	sec := ccStored(t, env, "client-a1")
	assert.Equal(t, "token-two", sec.Value)
	assert.Equal(t, "https://git.example.com/a/two", sec.Metadata[cfgpkg.SecretMetaKeyBoundRepositoryURL])
	assert.Contains(t, rec.Body.String(), `"bound_repository_url":"https://git.example.com/a/two"`)
}

func TestConfigSourceCredential_PermissionAndScope(t *testing.T) {
	env := newM365Env(t)

	updateOnly := &Principal{ID: "updater", Name: "updater", Assurance: session.AssuranceStrong,
		TenantID: "msp-a", Permissions: []string{"tenant:update"}, CertSerial: "cc-test-serial"}
	rec := m365Do(t, env.server, updateOnly, ccRoutePut, "client-a1",
		map[string]interface{}{"url": "https://git.example.com/a/one", "token": ccTestToken})
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	_, err := env.server.secretStore.GetSecret(context.Background(), "client-a1/config-source-git")
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound)

	other := &Principal{ID: "msp-b-admin", Name: "msp-b-admin", Assurance: session.AssuranceStrong,
		TenantID: "msp-b", ImplicitAdmin: true, CertSerial: "cc-test-serial"}
	rec = m365Do(t, env.server, other, ccRoutePut, "client-a1",
		map[string]interface{}{"url": "https://git.example.com/a/one", "token": ccTestToken})
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	rec = ccPut(t, env, "ghost", "https://git.example.com/a/one", ccTestToken)
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	_, err = env.server.secretStore.GetSecret(context.Background(), "client-a1/config-source-git")
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound)
}

func TestConfigSourceCredential_RejectsBadInputAndKeepsExisting(t *testing.T) {
	env := newM365Env(t)
	const goodURL = "https://git.example.com/a/one"
	// Nothing stored yet: a refused request stores nothing.
	for name, tc := range map[string]struct{ url, token string }{
		"plain http":      {"http://git.example.com/a/one", ccTestToken},
		"private address": {"https://10.0.0.5/a/one", ccTestToken},
		"loopback":        {"https://127.0.0.1/a/one", ccTestToken},
		"missing url":     {"", ccTestToken},
		"empty token":     {goodURL, ""},
	} {
		rec := ccPut(t, env, "client-a1", tc.url, tc.token)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name+": "+rec.Body.String())
		assert.NotContains(t, rec.Body.String(), ccTestToken)
		_, err := env.server.secretStore.GetSecret(context.Background(), "client-a1/config-source-git")
		assert.ErrorIs(t, err, secretsif.ErrSecretNotFound, name)
	}

	require.Equal(t, http.StatusOK, ccPut(t, env, "client-a1", goodURL, "original-token").Code)
	for name, body := range map[string]map[string]interface{}{
		"empty token":   {"url": "https://git.example.com/a/changed", "token": ""},
		"missing token": {"url": "https://git.example.com/a/changed"},
		"bad url":       {"url": "http://git.example.com/a/changed", "token": "new-token"},
		"unknown field": {"url": goodURL, "token": "new-token", "bound_repository_url": "https://x.example.com/y"},
	} {
		rec := m365Do(t, env.server, m365AdminPrincipal(), ccRoutePut, "client-a1", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name+": "+rec.Body.String())
	}
	sec := ccStored(t, env, "client-a1")
	assert.Equal(t, "original-token", sec.Value)
	assert.Equal(t, goodURL, sec.Metadata[cfgpkg.SecretMetaKeyBoundRepositoryURL])
}

func TestConfigSourceCredential_TokenNeverLoggedAuditNamesBinding(t *testing.T) {
	capLog := &auditCapturingLogger{}
	env := newM365EnvWithServer(t, setupCrossingTestServerWithLogger(t, capLog))

	rec := ccPut(t, env, "client-a1", "https://git.example.com/a/one", ccTestToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	_ = ccPut(t, env, "client-a1", "http://git.example.com/a/one", ccTestToken)
	assert.NotContains(t, capLog.formattedOutput(), ccTestToken)

	require.NoError(t, env.server.auditManager.Flush(context.Background()))
	entries, err := env.server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "client-a1"})
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), ccTestToken)
		if e.Action == configSourceCredentialAuditAction {
			found = true
			assert.Contains(t, string(raw), "https://git.example.com/a/one")
			assert.Contains(t, string(raw), "admin-1")
			assert.Contains(t, string(raw), "client-a1")
		}
	}
	assert.True(t, found, "the credential write emits an audit event")
}
