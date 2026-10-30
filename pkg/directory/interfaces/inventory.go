// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces

import "context"

// GroupMemberRef is one direct member of a group as the directory reports it.
// Type is the provider's classification of the member object ("user", "group",
// "device", "service_principal", "contact" or "other"); it is empty only when the
// provider does not say.
type GroupMemberRef struct {
	ID          string
	Type        string
	DisplayName string
}

// InventoryReader is implemented by providers that can walk a whole directory
// one page at a time, for scheduled inventory. A cursor is opaque to the caller:
// the empty cursor starts the enumeration and an empty returned cursor ends it.
// Unlike ListUsers/ListGroups, which serve interactive callers and are bounded,
// walking every page returns every object. Callers reach it through
// DirectoryProviderManager.ExecuteProviderOp.
type InventoryReader interface {
	ListUsersPage(ctx context.Context, cursor string, pageSize int) (users []DirectoryUser, next string, err error)
	ListGroupsPage(ctx context.Context, cursor string, pageSize int) (groups []DirectoryGroup, next string, err error)
	// ListGroupMembersPage returns one page of the group's direct members of every
	// object type, with one Graph call per page.
	ListGroupMembersPage(ctx context.Context, groupID, cursor string, pageSize int) (members []GroupMemberRef, next string, err error)
}
