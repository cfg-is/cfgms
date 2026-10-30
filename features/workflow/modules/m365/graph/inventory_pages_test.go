// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package graph

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
)

func TestInventoryPages_FollowNextLinkWithoutCap(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("$skiptoken") {
		case "":
			fmt.Fprintf(w, `{"value":[{"id":"u1"},{"id":"u2"}],"@odata.nextLink":"%s%s?$skiptoken=2"}`, srv.URL, r.URL.Path)
		default:
			_, _ = w.Write([]byte(`{"value":[{"id":"u3"}]}`))
		}
	}))
	defer srv.Close()
	c := NewHTTPClient(WithBaseURL(srv.URL))
	tok := &auth.AccessToken{Token: "t", TokenType: "Bearer"}

	page, next, err := c.ListUsersPage(context.Background(), tok, "", 2)
	require.NoError(t, err)
	assert.Len(t, page, 2)
	require.NotEmpty(t, next)
	page, next, err = c.ListUsersPage(context.Background(), tok, next, 2)
	require.NoError(t, err)
	assert.Len(t, page, 1)
	assert.Empty(t, next)

	groups, _, err := c.ListGroupsPage(context.Background(), tok, "", 0)
	require.NoError(t, err)
	assert.NotEmpty(t, groups)
}

func TestInventoryPages_ForeignNextLinkIsAnErrorNotTheEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(WithBaseURL(srv.URL))
	tok := &auth.AccessToken{Token: "t", TokenType: "Bearer"}

	_, _, err := c.ListUsersPage(context.Background(), tok, "https://elsewhere.example/users?$skiptoken=1", 10)
	require.Error(t, err)
	_, _, err = c.ListGroupMembersPage(context.Background(), tok, "g1", "https://elsewhere.example/x", 10)
	require.Error(t, err)
}

func TestListGroupMembersPage_ReturnsEveryObjectTypeWithODataType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/groups/g1/members", r.URL.Path)
		assert.Equal(t, "999", r.URL.Query().Get("$top"))
		_, _ = w.Write([]byte(`{"value":[
			{"@odata.type":"#microsoft.graph.user","id":"u1","displayName":"U","userPrincipalName":"u@x"},
			{"@odata.type":"#microsoft.graph.device","id":"d1","displayName":"D"}]}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(WithBaseURL(srv.URL))

	got, next, err := c.ListGroupMembersPage(context.Background(), &auth.AccessToken{Token: "t", TokenType: "Bearer"}, "g1", "", 5000)
	require.NoError(t, err)
	assert.Empty(t, next)
	require.Len(t, got, 2)
	assert.Equal(t, "#microsoft.graph.device", got[1].ODataType)
	assert.Equal(t, "D", got[1].DisplayName)
}
