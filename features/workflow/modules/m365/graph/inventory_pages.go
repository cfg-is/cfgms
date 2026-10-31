// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package graph

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
)

// MaxInventoryPageSize is Graph's ceiling for $top on users, groups and group members.
const MaxInventoryPageSize = 999

const inventoryUserFields = "id,userPrincipalName,displayName,mailNickname,accountEnabled,mail,mobilePhone,officeLocation,jobTitle,department,companyName"

// DirectoryObject is one member of a group as Graph returns it. ODataType is the
// "@odata.type" discriminator ("#microsoft.graph.user", "#microsoft.graph.device").
type DirectoryObject struct {
	ID                string `json:"id"`
	ODataType         string `json:"@odata.type"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// InventoryClient reads whole directories one Graph page at a time. A page link
// is the opaque "@odata.nextLink" of the previous page; the empty link starts the
// enumeration, and an empty returned link ends it. Unlike ListUsers it has no
// result cap, so a caller that walks every page sees every object.
type InventoryClient interface {
	ListUsersPage(ctx context.Context, token *auth.AccessToken, pageLink string, pageSize int) ([]User, string, error)
	ListGroupsPage(ctx context.Context, token *auth.AccessToken, pageLink string, pageSize int) ([]Group, string, error)
	ListGroupMembersPage(ctx context.Context, token *auth.AccessToken, groupID, pageLink string, pageSize int) ([]DirectoryObject, string, error)
}

var _ InventoryClient = (*HTTPClient)(nil)

func clampPageSize(n int) int {
	if n <= 0 || n > MaxInventoryPageSize {
		return MaxInventoryPageSize
	}
	return n
}

// pageEndpoint resolves the request path for a page. A next link that does not
// point at this client's base URL is an error rather than the end of the list:
// treating it as the end would silently truncate an inventory.
func (c *HTTPClient) pageEndpoint(first, pageLink string) (string, error) {
	if pageLink == "" {
		return first, nil
	}
	if !strings.HasPrefix(pageLink, c.baseURL+"/") {
		return "", fmt.Errorf("graph next link does not belong to the configured Graph endpoint")
	}
	return pageLink[len(c.baseURL):], nil
}

// ListUsersPage returns one page of users.
func (c *HTTPClient) ListUsersPage(ctx context.Context, token *auth.AccessToken, pageLink string, pageSize int) ([]User, string, error) {
	endpoint, err := c.pageEndpoint(fmt.Sprintf("/users?$select=%s&$top=%d", inventoryUserFields, clampPageSize(pageSize)), pageLink)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list users: %w", err)
	}
	var resp struct {
		Value    []User `json:"value"`
		NextLink string `json:"@odata.nextLink"`
	}
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &resp); err != nil {
		return nil, "", fmt.Errorf("failed to list users: %w", err)
	}
	return resp.Value, resp.NextLink, nil
}

// ListGroupsPage returns one page of groups.
func (c *HTTPClient) ListGroupsPage(ctx context.Context, token *auth.AccessToken, pageLink string, pageSize int) ([]Group, string, error) {
	endpoint, err := c.pageEndpoint(fmt.Sprintf("/groups?$top=%d", clampPageSize(pageSize)), pageLink)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list groups: %w", err)
	}
	var resp struct {
		Value    []Group `json:"value"`
		NextLink string  `json:"@odata.nextLink"`
	}
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &resp); err != nil {
		return nil, "", fmt.Errorf("failed to list groups: %w", err)
	}
	return resp.Value, resp.NextLink, nil
}

// ListGroupMembersPage returns one page of a group's direct members, of every
// directory object type.
func (c *HTTPClient) ListGroupMembersPage(ctx context.Context, token *auth.AccessToken, groupID, pageLink string, pageSize int) ([]DirectoryObject, string, error) {
	first := fmt.Sprintf("/groups/%s/members?$select=id,displayName,userPrincipalName&$top=%d", url.PathEscape(groupID), clampPageSize(pageSize))
	endpoint, err := c.pageEndpoint(first, pageLink)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list group members: %w", err)
	}
	var resp struct {
		Value    []DirectoryObject `json:"value"`
		NextLink string            `json:"@odata.nextLink"`
	}
	if err := c.makeRequest(ctx, token, "GET", endpoint, nil, &resp); err != nil {
		return nil, "", fmt.Errorf("failed to list group members: %w", err)
	}
	return resp.Value, resp.NextLink, nil
}
