// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package moduleserver_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	entrauser "github.com/cfgis/cfgms/features/workflow/modules/m365/entra_user"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/moduleserver"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
)

// newControllerSecretStore opens a real sops secret store over a flatfile root
// with a temp key file, the shape api.NewSecretStore builds for the controller.
func newControllerSecretStore(t *testing.T) secretsif.SecretStore {
	t.Helper()
	base := t.TempDir()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	store, err := secretsif.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": filepath.Join(base, "data")},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

type rewriteTransport struct{ target *url.URL }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = r.target.Scheme
	clone.URL.Host = r.target.Host
	clone.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

// [REQUIRED TEST] Issue #4891: the connection the #4551 write path stores is the
// one a module's GetAccessToken uses, end to end across the module contract.
func TestModuleServer_UsesTokenMintedFromStoredConnection(t *testing.T) {
	const (
		cfgmsTenant = "client-tenant-1"
		m365Tenant  = "11111111-2222-3333-4444-555555555555"
		clientID    = "stored-client-id"
		secretValue = "stored-client-secret-value"
		minted      = "minted-graph-token"
	)

	store := newControllerSecretStore(t)
	require.NoError(t, auth.NewSecretStoreCredentialStore(store).StoreConfig(cfgmsTenant, &auth.OAuth2Config{
		ClientID: clientID, ClientSecret: secretValue, TenantID: m365Tenant, UseClientCredentials: true,
	}))

	// Token endpoint: asserts the stored client_id / client_secret arrive.
	var tokenMu sync.Mutex
	var gotID, gotSecretMatches, gotPath string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tokenMu.Lock()
		gotID = r.PostForm.Get("client_id")
		if r.PostForm.Get("client_secret") == secretValue {
			gotSecretMatches = "yes"
		}
		gotPath = r.URL.Path
		tokenMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": minted, "token_type": "Bearer", "expires_in": 3600})
	}))
	defer tokenSrv.Close()
	tokenURL, err := url.Parse(tokenSrv.URL)
	require.NoError(t, err)

	issuer := workflow.NewM365CredentialIssuer(store)
	require.NotNil(t, issuer)
	issuer.SetHTTPClient(&http.Client{Transport: rewriteTransport{target: tokenURL}})
	authToken, err := issuer.Issue(context.Background(), "m365-entra-user", cfgmsTenant)
	require.NoError(t, err)
	tokenMu.Lock()
	assert.Equal(t, clientID, gotID)
	assert.Equal(t, "yes", gotSecretMatches, "token endpoint must receive the stored client_secret")
	assert.Contains(t, gotPath, m365Tenant)
	tokenMu.Unlock()
	assert.NotContains(t, authToken, secretValue)
	assert.NotContains(t, authToken, clientID)

	// Graph server: records the bearer token it receives.
	var graphMu sync.Mutex
	var authHeaders []string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		graphMu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		graphMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/licenseDetails") {
			_, _ = w.Write([]byte(`{"value":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"user-id-1","userPrincipalName":"someone@example.com","displayName":"Some One","accountEnabled":true}`))
	}))
	defer graphSrv.Close()

	// Serve the real entra_user module on a real contract socket.
	dir, err := os.MkdirTemp("/tmp", "cfgms-ms-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	lis, err := contract.Listen(filepath.Join(dir, "m.sock"))
	require.NoError(t, err)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- moduleserver.Serve(lis, "m365-entra-user", entrauser.New,
			graph.NewHTTPClient(graph.WithBaseURL(graphSrv.URL)), false)
	}()

	conn, err := grpc.NewClient("unix://"+filepath.Join(dir, "m.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := proto.NewWorkflowModuleServiceClient(conn)
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = client.Shutdown(sctx, &proto.ShutdownRequest{})
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// No call is served before the handshake binds a tenant.
	_, err = client.Get(ctx, &proto.GetRequest{ResourceId: m365Tenant + ":someone@example.com"})
	require.Error(t, err)

	_, err = client.Handshake(ctx, &proto.WorkflowHandshakeRequest{
		ModuleName: "m365-entra-user", TenantId: cfgmsTenant, AuthToken: authToken,
	})
	require.NoError(t, err)

	resp, err := client.Get(ctx, &proto.GetRequest{ResourceId: m365Tenant + ":someone@example.com"})
	require.NoError(t, err)
	assert.Contains(t, resp.ConfigData, "someone@example.com")

	graphMu.Lock()
	require.NotEmpty(t, authHeaders)
	for _, h := range authHeaders {
		assert.Equal(t, "Bearer "+minted, h)
	}
	graphMu.Unlock()

	// The session cannot be rebound to another tenant.
	_, err = client.Handshake(ctx, &proto.WorkflowHandshakeRequest{TenantId: "other-tenant", AuthToken: authToken})
	require.Error(t, err)
}

func TestModuleServer_HandshakeWithoutTokenFailsGet(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "cfgms-ms-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "m.sock")
	lis, err := contract.Listen(sock)
	require.NoError(t, err)
	go func() {
		_ = moduleserver.Serve(lis, "m365-entra-user", entrauser.New, graph.NewHTTPClient(graph.WithBaseURL("http://127.0.0.1:1")), false)
	}()
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := proto.NewWorkflowModuleServiceClient(conn)
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = client.Shutdown(sctx, &proto.ShutdownRequest{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = client.Handshake(ctx, &proto.WorkflowHandshakeRequest{TenantId: "client-1"})
	require.NoError(t, err)
	_, err = client.Get(ctx, &proto.GetRequest{ResourceId: "m365:someone@example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "No M365 credential was delivered")
	assert.Contains(t, err.Error(), "client-1")
}
