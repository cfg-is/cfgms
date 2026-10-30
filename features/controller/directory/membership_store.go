// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package directory holds the controller's durable directory membership state:
// who is a direct member of which group (Active Directory and Microsoft 365), and
// the change log of every membership add and remove. Membership is the member_of
// attribute of user and group fragments, not graph edges.
package directory

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Config-store layout. Every name is flat (a hash plus a suffix) so it passes the
// providers' key validation, which rejects path separators; the real ids live in
// each entry's value.
const (
	// NamespaceMembership holds the per-group member shards: <h>-<NN>.
	NamespaceMembership = "directory-membership"
	// NamespaceMembershipByMember holds each member's direct groups.
	NamespaceMembershipByMember = "directory-membership-by-member"
	// NamespaceMembershipLog holds change-log entries: <h>-<sequence>.
	NamespaceMembershipLog = "directory-membership-log"
	// NamespaceMembershipSeq holds the per-group log sequence counter.
	NamespaceMembershipSeq = "directory-membership-seq"
	// NamespaceMembershipPeer holds each peer's last verified authority.
	NamespaceMembershipPeer = "directory-membership-peer"

	// peerTenantID is the tenant segment of the per-peer entries: a peer's
	// last-known authority is exactly what survives the peer changing tenant, so it
	// cannot live under either tenant. Config stores reject an empty tenant.
	peerTenantID = "_global"

	// membershipShards is the fixed number of store-internal shards per group.
	membershipShards = 64

	defaultPageLimit = 100
	maxPageLimit     = 1000
	hashHexLen       = 32
)

// Reasons a call is refused. None carries an id, tenant or domain.
var (
	// ErrInvalidCursor is returned for a cursor that is malformed or was issued for
	// a different tenant, subject or listing.
	ErrInvalidCursor = errors.New("directory membership: invalid cursor")
	// ErrUnknownDomainOwner is returned when the domain registry names no owner for
	// an authority; nothing is written.
	ErrUnknownDomainOwner = errors.New("directory membership: authority has no registered owning tenant")
	// ErrInvalidArgument is returned for an empty or malformed tenant, authority or id.
	ErrInvalidArgument = errors.New("directory membership: invalid argument")
)

// MemberType classifies a group member.
type MemberType string

// Member types. User and group members come from user and group fragments;
// the rest are reported by the group itself (other_members) and are never managed
// objects.
const (
	MemberTypeUser                     MemberType = "user"
	MemberTypeGroup                    MemberType = "group"
	MemberTypeComputer                 MemberType = "computer"
	MemberTypeContact                  MemberType = "contact"
	MemberTypeForeignSecurityPrincipal MemberType = "foreign_security_principal"
	MemberTypeDevice                   MemberType = "device"
	MemberTypeServicePrincipal         MemberType = "service_principal"
	MemberTypeOther                    MemberType = "other"
)

// normalizeMemberType maps an unknown or empty type to MemberTypeOther.
func normalizeMemberType(t string) MemberType {
	switch mt := MemberType(strings.ToLower(strings.TrimSpace(t))); mt {
	case MemberTypeUser, MemberTypeGroup, MemberTypeComputer, MemberTypeContact,
		MemberTypeForeignSecurityPrincipal, MemberTypeDevice, MemberTypeServicePrincipal:
		return mt
	}
	return MemberTypeOther
}

// Member is one direct member of a group.
type Member struct {
	ID          string     `json:"id"`
	Type        MemberType `json:"type"`
	DisplayName string     `json:"display_name,omitempty"`
}

// MemberPage is one page of ListMembers. NextCursor is empty on the last page.
type MemberPage struct {
	Members    []Member `json:"members"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

// GroupsPage is one page of ListGroupsOf: ids of the groups the member is a direct
// member of. Truncated is true when the source object reported member_of as cut
// off, so the list may be incomplete.
type GroupsPage struct {
	GroupIDs   []string `json:"group_ids"`
	Truncated  bool     `json:"truncated,omitempty"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

// ChangeQuery selects change-log events of one group. Authority and GroupID are
// required; Since and Until bound RecordedAt (zero means unbounded). Baseline
// events (the first observation of a group) are excluded unless IncludeBaseline.
type ChangeQuery struct {
	Authority       string
	GroupID         string
	MemberID        string
	IncludeBaseline bool
	Since           time.Time
	Until           time.Time
	Cursor          string
	Limit           int
}

// ChangePage is one page of ListChanges, oldest first.
type ChangePage struct {
	Events     []ChangeEvent `json:"events"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// MembershipStore is the read side of the membership state. Every call is scoped
// to the owning tenant of the group entity the caller already authorised.
type MembershipStore interface {
	// ListMembers pages the direct members of a group.
	ListMembers(ctx context.Context, tenant, authority, groupID, cursor string, limit int) (MemberPage, error)
	// ListGroupsOf pages the groups a member is a direct member of.
	ListGroupsOf(ctx context.Context, tenant, authority, memberID, cursor string, limit int) (GroupsPage, error)
	// ListChanges pages the change log of one group.
	ListChanges(ctx context.Context, tenant string, q ChangeQuery) (ChangePage, error)
}

// shardValue is the value of one membership shard entry.
type shardValue struct {
	Authority string                `json:"authority"`
	GroupID   string                `json:"group_id"`
	Shard     int                   `json:"shard"`
	Members   map[string]shardEntry `json:"members"`
}

type shardEntry struct {
	Type MemberType `json:"type"`
	Name string     `json:"name,omitempty"`
}

// byMemberValue is the value of one by-member entry: the member's direct groups,
// plus what the member's own fragment reported about itself.
type byMemberValue struct {
	Authority    string        `json:"authority"`
	MemberID     string        `json:"member_id"`
	Type         MemberType    `json:"type,omitempty"`
	Name         string        `json:"name,omitempty"`
	Groups       []string      `json:"groups"`
	Truncated    bool          `json:"member_of_truncated,omitempty"`
	OtherMembers []otherMember `json:"other_members,omitempty"`
}

// otherMember is a non-user, non-group member reported by a group fragment.
type otherMember struct {
	ID   string     `json:"id"`
	Type MemberType `json:"type"`
	Name string     `json:"name,omitempty"`
}

func hashHex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:hashHexLen]
}

func groupHash(authority, group string) string { return hashHex(authority, group) }

func shardIndex(memberID string) int {
	sum := sha256.Sum256([]byte(memberID))
	return int(binary.BigEndian.Uint32(sum[:4]) % membershipShards)
}

func shardName(h string, idx int) string { return fmt.Sprintf("%s-%02d", h, idx) }

func shardKey(tenant, authority, group string, idx int) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenant, Namespace: NamespaceMembership, Name: shardName(groupHash(authority, group), idx)}
}

func byMemberKey(tenant, authority, member string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: tenant, Namespace: NamespaceMembershipByMember, Name: hashHex(authority, member)}
}

func peerKey(peerID string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: peerTenantID, Namespace: NamespaceMembershipPeer, Name: hashHex(peerID)}
}

// objectEID renders the entity id of a directory or m365 object.
func objectEID(authority string, t MemberType, id string) string {
	return authority + "/" + string(t) + ":" + id
}

func newEntry(key *cfgconfig.ConfigKey, v any, tags []string, now time.Time) (*cfgconfig.ConfigEntry, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode directory membership entry: %w", err)
	}
	return &cfgconfig.ConfigEntry{
		Key: key, Data: data, Format: cfgconfig.ConfigFormatJSON,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "directory-membership", UpdatedBy: "directory-membership",
		Source: "cfgms-controller", Tags: tags,
	}, nil
}

// getValue reads key into v and reports whether the entry exists.
func getValue(ctx context.Context, store cfgconfig.ConfigStore, key *cfgconfig.ConfigKey, v any) (bool, error) {
	e, err := store.GetConfig(ctx, key)
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("read directory membership entry: %w", err)
	}
	if err := json.Unmarshal(e.Data, v); err != nil {
		return false, fmt.Errorf("decode directory membership entry: %w", err)
	}
	return true, nil
}

// cursor is the opaque position in a listing. It is bound to the tenant, the
// listing kind and the subject it was issued for.
type cursor struct {
	Tenant  string `json:"t"`
	Kind    string `json:"k"`
	Subject string `json:"s"`
	After   string `json:"a,omitempty"`
	Shard   int    `json:"h,omitempty"`
	Seq     uint64 `json:"q,omitempty"`
	Index   int    `json:"i,omitempty"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c) // a flat struct of strings and ints cannot fail to encode
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s, tenant, kind, subject string) (cursor, error) {
	var c cursor
	if s == "" {
		return c, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &c) != nil {
		return cursor{}, ErrInvalidCursor
	}
	if c.Tenant != tenant || c.Kind != kind || c.Subject != subject || c.Shard < 0 || c.Shard >= membershipShards {
		return cursor{}, ErrInvalidCursor
	}
	return c, nil
}

func pageLimit(n int) int {
	switch {
	case n <= 0:
		return defaultPageLimit
	case n > maxPageLimit:
		return maxPageLimit
	}
	return n
}

func validScope(tenant, authority, id string) error {
	if tenant == "" || authority == "" || !validRawID(id) {
		return ErrInvalidArgument
	}
	return nil
}

// ListMembers implements MembershipStore. Members are ordered by shard, then id, so
// the order is stable across calls and a cursor resumes exactly.
func (m *Membership) ListMembers(ctx context.Context, tenant, authority, groupID, cur string, limit int) (MemberPage, error) {
	if err := validScope(tenant, authority, groupID); err != nil {
		return MemberPage{}, err
	}
	subject := groupHash(authority, groupID)
	c, err := decodeCursor(cur, tenant, "members", subject)
	if err != nil {
		return MemberPage{}, err
	}
	limit = pageLimit(limit)
	var page MemberPage
	for s := c.Shard; s < membershipShards; s++ {
		var sv shardValue
		ok, err := getValue(ctx, m.store, shardKey(tenant, authority, groupID, s), &sv)
		if err != nil {
			return MemberPage{}, err
		}
		if !ok {
			continue
		}
		ids := make([]string, 0, len(sv.Members))
		for id := range sv.Members {
			if s == c.Shard && c.After != "" && id <= c.After {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if len(page.Members) == limit {
				last := page.Members[len(page.Members)-1]
				page.NextCursor = encodeCursor(cursor{Tenant: tenant, Kind: "members", Subject: subject, After: last.ID, Shard: shardIndex(last.ID)})
				return page, nil
			}
			e := sv.Members[id]
			page.Members = append(page.Members, Member{ID: id, Type: e.Type, DisplayName: e.Name})
		}
	}
	return page, nil
}

// ListGroupsOf implements MembershipStore.
func (m *Membership) ListGroupsOf(ctx context.Context, tenant, authority, memberID, cur string, limit int) (GroupsPage, error) {
	if err := validScope(tenant, authority, memberID); err != nil {
		return GroupsPage{}, err
	}
	subject := hashHex(authority, memberID)
	c, err := decodeCursor(cur, tenant, "groups", subject)
	if err != nil {
		return GroupsPage{}, err
	}
	limit = pageLimit(limit)
	var bm byMemberValue
	if _, err := getValue(ctx, m.store, byMemberKey(tenant, authority, memberID), &bm); err != nil {
		return GroupsPage{}, err
	}
	groups := append([]string(nil), bm.Groups...)
	sort.Strings(groups)
	page := GroupsPage{Truncated: bm.Truncated}
	for _, g := range groups {
		if c.After != "" && g <= c.After {
			continue
		}
		if len(page.GroupIDs) == limit {
			page.NextCursor = encodeCursor(cursor{Tenant: tenant, Kind: "groups", Subject: subject, After: page.GroupIDs[len(page.GroupIDs)-1]})
			return page, nil
		}
		page.GroupIDs = append(page.GroupIDs, g)
	}
	return page, nil
}
