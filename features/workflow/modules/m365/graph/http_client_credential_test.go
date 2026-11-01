// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
)

func credentialTestClient(t *testing.T, status int, response string) (*HTTPClient, *http.Request, *[]byte) {
	t.Helper()
	var got http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		got = *r.Clone(context.Background())
		body = raw
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, werr := w.Write([]byte(response))
		assert.NoError(t, werr)
	}))
	t.Cleanup(srv.Close)
	return NewHTTPClient(WithBaseURL(srv.URL), WithHTTPClient(srv.Client())), &got, &body
}

func TestHTTPClient_ApplicationCredentialMethods(t *testing.T) {
	token := &auth.AccessToken{Token: "t", TokenType: "Bearer"}
	ctx := context.Background()
	cases := []struct {
		name   string
		path   string
		status int
		resp   string
		call   func(c *HTTPClient) error
		check  func(t *testing.T, body []byte)
	}{
		{"addPassword", "/applications/app-1/addPassword", 200, `{"keyId":"k1"}`,
			func(c *HTTPClient) error {
				_, err := c.AddApplicationPassword(ctx, token, "app-1", &AddApplicationPasswordRequest{
					PasswordCredential: ApplicationPasswordCredentialInput{DisplayName: "secret"}})
				return err
			},
			func(t *testing.T, body []byte) {
				var m map[string]map[string]interface{}
				require.NoError(t, json.Unmarshal(body, &m))
				assert.Equal(t, "secret", m["passwordCredential"]["displayName"])
				assert.NotContains(t, m["passwordCredential"], "secretText")
			}},
		{"removePassword", "/applications/app-1/removePassword", 204, ``,
			func(c *HTTPClient) error { return c.RemoveApplicationPassword(ctx, token, "app-1", "k1") },
			func(t *testing.T, body []byte) { assert.JSONEq(t, `{"keyId":"k1"}`, string(body)) }},
		{"addKey", "/applications/app-1/addKey", 200, `{"keyId":"k2"}`,
			func(c *HTTPClient) error {
				_, err := c.AddApplicationKey(ctx, token, "app-1", &AddApplicationKeyRequest{
					KeyCredential: ApplicationKeyCredentialInput{DisplayName: "cert", Type: "AsymmetricX509Cert", Usage: "Verify", Key: []byte{1, 2, 3}}})
				return err
			},
			func(t *testing.T, body []byte) {
				var m map[string]map[string]interface{}
				require.NoError(t, json.Unmarshal(body, &m))
				assert.Equal(t, "AQID", m["keyCredential"]["key"])
				assert.Equal(t, "Verify", m["keyCredential"]["usage"])
			}},
		{"removeKey", "/applications/app-1/removeKey", 204, ``,
			func(c *HTTPClient) error { return c.RemoveApplicationKey(ctx, token, "app-1", "k2") },
			func(t *testing.T, body []byte) { assert.JSONEq(t, `{"keyId":"k2"}`, string(body)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, req, body := credentialTestClient(t, tc.status, tc.resp)
			require.NoError(t, tc.call(c))
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, tc.path, req.URL.Path)
			tc.check(t, *body)
		})
		t.Run(tc.name+" non-2xx", func(t *testing.T) {
			c, _, _ := credentialTestClient(t, 403, `{"error":{"code":"Forbidden","message":"denied"}}`)
			assert.Error(t, tc.call(c))
		})
	}
}
