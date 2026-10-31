// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package m365

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

var _ interfaces.InventoryReader = (*EntraIDDirectoryProvider)(nil)

// inventoryClient returns the paged Graph client, or an error when the
// configured Graph client cannot page.
func (p *EntraIDDirectoryProvider) inventoryClient() (graph.InventoryClient, error) {
	c, ok := p.graphClient.(graph.InventoryClient)
	if !ok {
		return nil, fmt.Errorf("the configured Graph client does not support paged inventory")
	}
	return c, nil
}

// ListUsersPage implements interfaces.InventoryReader.
func (p *EntraIDDirectoryProvider) ListUsersPage(ctx context.Context, cursor string, pageSize int) ([]interfaces.DirectoryUser, string, error) {
	ic, err := p.inventoryClient()
	if err != nil {
		return nil, "", err
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, "", err
	}
	users, next, err := ic.ListUsersPage(ctx, tok, cursor, pageSize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list users in Entra ID: %w", err)
	}
	out := make([]interfaces.DirectoryUser, 0, len(users))
	for i := range users {
		out = append(out, *p.userFromGraph(&users[i]))
	}
	return out, next, nil
}

// ListGroupsPage implements interfaces.InventoryReader.
func (p *EntraIDDirectoryProvider) ListGroupsPage(ctx context.Context, cursor string, pageSize int) ([]interfaces.DirectoryGroup, string, error) {
	ic, err := p.inventoryClient()
	if err != nil {
		return nil, "", err
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, "", err
	}
	groups, next, err := ic.ListGroupsPage(ctx, tok, cursor, pageSize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to list groups in Entra ID: %w", err)
	}
	out := make([]interfaces.DirectoryGroup, 0, len(groups))
	for i := range groups {
		out = append(out, *p.groupFromGraph(&groups[i]))
	}
	return out, next, nil
}

// ListGroupMembersPage implements interfaces.InventoryReader.
func (p *EntraIDDirectoryProvider) ListGroupMembersPage(ctx context.Context, groupID, cursor string, pageSize int) ([]interfaces.GroupMemberRef, string, error) {
	ic, err := p.inventoryClient()
	if err != nil {
		return nil, "", err
	}
	tok, err := p.token(ctx)
	if err != nil {
		return nil, "", err
	}
	objs, next, err := ic.ListGroupMembersPage(ctx, tok, groupID, cursor, pageSize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get group members from Entra ID: %w", err)
	}
	out := make([]interfaces.GroupMemberRef, 0, len(objs))
	for _, o := range objs {
		out = append(out, interfaces.GroupMemberRef{ID: o.ID, Type: memberTypeOf(o.ODataType), DisplayName: o.DisplayName})
	}
	return out, next, nil
}

// memberTypeOf maps a Graph "@odata.type" to a member type name.
func memberTypeOf(odataType string) string {
	switch strings.ToLower(strings.TrimPrefix(odataType, "#microsoft.graph.")) {
	case "user":
		return "user"
	case "group":
		return "group"
	case "device":
		return "device"
	case "serviceprincipal":
		return "service_principal"
	case "orgcontact":
		return "contact"
	}
	return "other"
}
