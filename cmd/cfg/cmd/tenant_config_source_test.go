// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const configSourceCLIToken = "ghp_cli-token-Zk3-7714"

func newConfigSourceTestController(t *testing.T) (*httptest.Server, func() []recordedReq) {
	t.Helper()
	var mu sync.Mutex
	var reqs []recordedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, recordedReq{r.Method, r.URL.Path, r.Header.Clone(), b})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/tenants/client-1/config-source/credential" {
			_, _ = w.Write([]byte(`{"data":{"credential_ref":"client-1/config-source-git","bound_repository_url":"https://git.example.com/org/configs"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"TENANT_NOT_FOUND","message":"tenant not found"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recordedReq {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedReq(nil), reqs...)
	}
}

func setupConfigSourceCmd(t *testing.T, url, stdin, repoURL string) {
	t.Helper()
	setupCrossingCmd(t, url)
	origStdin, origURL := configSourceStdin, configSourceURL
	t.Cleanup(func() { configSourceStdin, configSourceURL = origStdin, origURL })
	configSourceStdin = strings.NewReader(stdin)
	configSourceURL = repoURL
}

func TestTenantConfigSourceSetCredential(t *testing.T) {
	t.Run("reads the token from stdin, sends it in the body and prints the ref", func(t *testing.T) {
		srv, requests := newConfigSourceTestController(t)
		setupConfigSourceCmd(t, srv.URL, configSourceCLIToken+"\n", "https://git.example.com/org/configs.git")
		args := []string{"client-1"}
		out := captureStdout(t, func() {
			require.NoError(t, runTenantConfigSourceSetCredential(tenantConfigSourceSetCredentialCmd, args))
		})
		reqs := requests()
		require.Len(t, reqs, 1)
		assert.Equal(t, http.MethodPut, reqs[0].Method)
		var body map[string]string
		require.NoError(t, json.Unmarshal(reqs[0].Body, &body))
		assert.Equal(t, map[string]string{"url": "https://git.example.com/org/configs.git", "token": configSourceCLIToken}, body)
		assert.Contains(t, out, "client-1/config-source-git")
		assert.NotContains(t, out, configSourceCLIToken)
		assert.NotContains(t, strings.Join(args, " "), configSourceCLIToken)
	})

	t.Run("the token has no flag", func(t *testing.T) {
		assert.Nil(t, tenantConfigSourceSetCredentialCmd.Flags().Lookup("token"))
		for _, name := range []string{"url", "json"} {
			assert.NotNil(t, tenantConfigSourceSetCredentialCmd.Flags().Lookup(name))
		}
	})

	t.Run("a missing --url is an error and nothing is sent", func(t *testing.T) {
		srv, requests := newConfigSourceTestController(t)
		setupConfigSourceCmd(t, srv.URL, configSourceCLIToken+"\n", "")
		err := runTenantConfigSourceSetCredential(tenantConfigSourceSetCredentialCmd, []string{"client-1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--url")
		assert.Empty(t, requests())

		// The flag is also required at the cobra layer.
		f := tenantConfigSourceSetCredentialCmd.Flags().Lookup("url")
		assert.Contains(t, f.Annotations, "cobra_annotation_bash_completion_one_required_flag")
	})

	t.Run("an empty stdin is an error and nothing is sent", func(t *testing.T) {
		srv, requests := newConfigSourceTestController(t)
		setupConfigSourceCmd(t, srv.URL, "\n", "https://git.example.com/org/configs")
		require.Error(t, runTenantConfigSourceSetCredential(tenantConfigSourceSetCredentialCmd, []string{"client-1"}))
		assert.Empty(t, requests())
	})

	t.Run("a server refusal surfaces without the token", func(t *testing.T) {
		srv, _ := newConfigSourceTestController(t)
		setupConfigSourceCmd(t, srv.URL, configSourceCLIToken+"\n", "https://git.example.com/org/configs")
		err := runTenantConfigSourceSetCredential(tenantConfigSourceSetCredentialCmd, []string{"ghost"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TENANT_NOT_FOUND")
		assert.NotContains(t, err.Error(), configSourceCLIToken)
	})
}
