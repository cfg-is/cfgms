// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/directory"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Directory read API (Issue #5557). Every handler here reads stored state only:
// entities come from the entity graph through queryEntitiesInReadScope / the
// tenant-cut GetEntity, membership comes from the durable membership store. None
// of them can reach a steward or Microsoft Graph.

const (
	directoryDefaultLimit = 100
	directoryMaxLimit     = 500
	directoryMaxQueryLen  = 256
	directoryMaxTokenLen  = 2048
	directoryMaxObjectID  = 64
	directoryMaxMemberID  = 256
	// directoryInlineGroups bounds the groups list embedded in a user object.
	directoryInlineGroups = 100
	// directoryScanPageSize and directoryMaxScanPages bound the work one request
	// does when a filter has to read attributes row by row, or when a by-id lookup
	// has to find an object by id alone.
	directoryScanPageSize = 100
	directoryMaxScanPages = 50
	// directoryMaxChangeScan bounds the change events one request reads to order
	// them newest first.
	directoryMaxChangeScan = 100000

	directoryKindUser  = "user"
	directoryKindGroup = "group"
)

// directorySourceAuthority maps the API source name to the entity-graph authority type.
var directorySourceAuthority = map[string]string{"ad": "directory", "m365": "m365"}

// directoryObject is one user or group as the API returns it. It is built field by
// field from a fixed set of stored attributes, so nothing else on the entity (a
// distinguished name, a SID, anything credential-shaped) can leak into a response.
type directoryObject struct {
	Source            string              `json:"source"`
	Kind              string              `json:"kind"`
	ID                string              `json:"id"`
	Authority         string              `json:"authority"`
	DisplayName       string              `json:"display_name,omitempty"`
	SamAccountName    string              `json:"sam_account_name,omitempty"`
	UserPrincipalName string              `json:"user_principal_name,omitempty"`
	Mail              string              `json:"mail,omitempty"`
	Description       string              `json:"description,omitempty"`
	Enabled           *bool               `json:"enabled,omitempty"`
	Managed           bool                `json:"managed"`
	LastObserved      time.Time           `json:"last_observed"`
	Stale             bool                `json:"stale"`
	Groups            []directoryGroupRef `json:"groups,omitempty"`
	GroupsTruncated   bool                `json:"groups_truncated,omitempty"`
}

// directoryGroupRef is a group a user belongs to.
type directoryGroupRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
}

type directoryMember struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
}

type directoryChange struct {
	Group      string    `json:"group"`
	Member     string    `json:"member"`
	MemberType string    `json:"member_type"`
	Op         string    `json:"op"`
	ObservedAt time.Time `json:"observed_at"`
	RecordedAt time.Time `json:"recorded_at"`
	Source     string    `json:"source"`
	Baseline   bool      `json:"baseline"`
}

// directoryRoute is the per-request context of a directory route.
type directoryRoute struct {
	route string
	kind  string
}

func validDirectoryObjectID(id string) bool {
	if id == "" || len(id) > directoryMaxObjectID {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// validDirectoryAuthority accepts an AD domain name or a tenant GUID: letters,
// digits, '.', '-' and '_', at most 253 characters.
func validDirectoryAuthority(a string) bool {
	if a == "" || len(a) > egtypes.MaxDirectoryDomainLen {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// validDirectoryQuery accepts at most 256 characters of letters, digits, spaces and
// a short list of punctuation that appears in names, logins and mail addresses.
func validDirectoryQuery(q string) bool {
	if len(q) > directoryMaxQueryLen || !utf8.ValidString(q) {
		return false
	}
	for _, r := range q {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || strings.ContainsRune("-_.@'+,#&()", r) {
			continue
		}
		return false
	}
	return true
}

func validDirectoryMemberID(id string) bool {
	if id == "" || len(id) > directoryMaxMemberID || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func parseDirectoryLimit(q url.Values) (int, bool) {
	raw := q.Get("limit")
	if raw == "" {
		return directoryDefaultLimit, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > directoryMaxLimit {
		return 0, false
	}
	return n, true
}

// parseDirectoryBool parses an optional true/false filter. set is false when absent.
func parseDirectoryBool(q url.Values, name string) (val, set, ok bool) {
	raw := q.Get(name)
	if raw == "" {
		return false, false, true
	}
	switch raw {
	case "true":
		return true, true, true
	case "false":
		return false, true, true
	}
	return false, false, false
}

func (s *Server) directoryBadRequest(w http.ResponseWriter, msg string) {
	s.writeErrorResponse(w, http.StatusBadRequest, msg, "INVALID_REQUEST")
}

func (s *Server) directoryNotFound(w http.ResponseWriter) {
	s.writeErrorResponse(w, http.StatusNotFound, "not found", "NOT_FOUND")
}

func (s *Server) directoryInternalError(w http.ResponseWriter, what string, err error) {
	s.logger.Error("directory read failed",
		"operation", what,
		"error", logging.SanitizeLogValue(err.Error()),
	)
	s.writeErrorResponse(w, http.StatusInternalServerError, "directory read failed", "INTERNAL_ERROR")
}

// directoryMembershipStore returns the wired membership store, or nil.
func (s *Server) directoryMembershipStore() directory.MembershipStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.directoryMembership
}

// ---- opaque list cursor ----

// directoryCursor is the list page_token: the entity-graph position, bound to the
// caller's tenant cut and to the filters it was issued for.
type directoryCursor struct {
	Tenant string `json:"t"`
	Filter string `json:"f"`
	Pos    string `json:"p,omitempty"`
	Skip   int    `json:"k,omitempty"`
	Before int    `json:"b,omitempty"`
}

func encodeDirectoryCursor(c directoryCursor) string {
	b, _ := json.Marshal(c) // a flat struct of strings and ints cannot fail to encode
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeDirectoryCursor(tok, tenant, filter string) (directoryCursor, bool) {
	if tok == "" {
		return directoryCursor{}, true
	}
	if len(tok) > directoryMaxTokenLen {
		return directoryCursor{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	var c directoryCursor
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return directoryCursor{}, false
	}
	if c.Tenant != tenant || c.Filter != filter || c.Before < 0 || c.Skip < 0 {
		return directoryCursor{}, false
	}
	if c.Pos != "" {
		if n, err := strconv.Atoi(c.Pos); err != nil || n < 0 {
			return directoryCursor{}, false
		}
	}
	return c, true
}

func directoryFilterKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:8])
}

// ---- entity access ----

func directoryAttrString(attrs map[string]interface{}, key string) string {
	v, _ := attrs[key].(string)
	return v
}

func directoryAttrBool(attrs map[string]interface{}, key string) (val, present bool) {
	v, ok := attrs[key].(bool)
	return v, ok
}

// directorySourceName is the API source name for an EID's authority type.
func directorySourceName(eid egtypes.EID) string {
	if eid.AuthorityType() == "m365" {
		return "m365"
	}
	return "ad"
}

// directoryLocalID returns the object id of eid when it is a kind object, or "".
func directoryLocalID(eid egtypes.EID, kind string) string {
	local := eid.LocalID()
	prefix := kind + ":"
	if !strings.HasPrefix(local, prefix) {
		return ""
	}
	return strings.TrimPrefix(local, prefix)
}

// buildDirectoryObject projects a stored entity onto the response shape.
func buildDirectoryObject(view *egtypes.EntityView, kind string) *directoryObject {
	eid := view.Entity.EID
	attrs := view.Entity.Attributes
	obj := &directoryObject{
		Source:            directorySourceName(eid),
		Kind:              kind,
		ID:                directoryLocalID(eid, kind),
		Authority:         eid.AuthorityName(),
		DisplayName:       directoryAttrString(attrs, "display_name"),
		SamAccountName:    directoryAttrString(attrs, "sam_account_name"),
		UserPrincipalName: directoryAttrString(attrs, "user_principal_name"),
		Mail:              directoryAttrString(attrs, "mail"),
		Description:       directoryAttrString(attrs, "description"),
		LastObserved:      view.Freshness.ObservedAt,
		Stale:             view.Freshness.Stale,
	}
	obj.Managed, _ = directoryAttrBool(attrs, "managed")
	if kind == directoryKindUser {
		en, ok := directoryAttrBool(attrs, "enabled")
		if !ok {
			en, ok = directoryAttrBool(attrs, "account_enabled")
		}
		if !ok {
			en = true
		}
		obj.Enabled = &en
	}
	obj.GroupsTruncated, _ = directoryAttrBool(attrs, "member_of_truncated")
	return obj
}

func directoryMatchesQuery(obj *directoryObject, needle string) bool {
	for _, f := range []string{obj.DisplayName, obj.SamAccountName, obj.UserPrincipalName, obj.Mail, obj.ID} {
		if strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

// loadDirectoryViews reads the stored entity for every eid in one pass, each inside
// the cut of the tenant that owns it. Entities that no longer exist are omitted.
// The entity-graph read interface exposes no multi-entity read, so this is the
// single place a page's display fields are loaded; callers never read per row.
func (s *Server) loadDirectoryViews(r *http.Request, owners []string, eids []egtypes.EID) (map[string]*egtypes.EntityView, error) {
	out := make(map[string]*egtypes.EntityView, len(eids))
	for i, eid := range eids {
		view, err := s.egProvider.GetEntity(r.Context(), eid, eginterfaces.GetEntityOpts{TenantFilter: owners[i]})
		if err != nil {
			if isEntityNotFound(err) {
				continue
			}
			return nil, err
		}
		if view != nil && view.Entity != nil {
			out[eid.String()] = view
		}
	}
	return out, nil
}

// ---- list ----

func (s *Server) handleListDirectoryUsers(w http.ResponseWriter, r *http.Request) {
	s.listDirectory(w, r, directoryRoute{route: "GET /api/v1/directory/users", kind: directoryKindUser})
}

func (s *Server) handleListDirectoryGroups(w http.ResponseWriter, r *http.Request) {
	s.listDirectory(w, r, directoryRoute{route: "GET /api/v1/directory/groups", kind: directoryKindGroup})
}

// listDirectory serves GET /api/v1/directory/{users,groups}. Rows are returned
// without any membership: only the show and membership routes read it.
func (s *Server) listDirectory(w http.ResponseWriter, r *http.Request, dr directoryRoute) {
	if s.egProvider == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "entity graph unavailable", "SERVICE_UNAVAILABLE")
		return
	}
	q := r.URL.Query()

	limit, ok := parseDirectoryLimit(q)
	if !ok {
		s.directoryBadRequest(w, "limit must be an integer between 1 and 500")
		return
	}
	text := q.Get("q")
	if !validDirectoryQuery(text) {
		s.directoryBadRequest(w, "q must be at most 256 characters of letters, digits, spaces and - _ . @ ' + , # & ( )")
		return
	}
	source := q.Get("source")
	authorityTypes := []string{"directory", "m365"}
	if source != "" {
		at, known := directorySourceAuthority[source]
		if !known {
			s.directoryBadRequest(w, "source must be ad or m365")
			return
		}
		authorityTypes = []string{at}
	}
	enabled, enabledSet, ok := parseDirectoryBool(q, "enabled")
	if !ok {
		s.directoryBadRequest(w, "enabled must be true or false")
		return
	}
	if enabledSet && dr.kind != directoryKindUser {
		s.directoryBadRequest(w, "enabled applies to users only")
		return
	}
	managed, managedSet, ok := parseDirectoryBool(q, "managed")
	if !ok {
		s.directoryBadRequest(w, "managed must be true or false")
		return
	}

	tenant, ids := s.entityCut(r)
	filterKey := directoryFilterKey(dr.kind, source, strings.ToLower(text),
		strconv.FormatBool(enabledSet)+strconv.FormatBool(enabled),
		strconv.FormatBool(managedSet)+strconv.FormatBool(managed),
		strconv.Itoa(limit))
	cur, ok := decodeDirectoryCursor(q.Get("page_token"), tenant, filterKey)
	if !ok {
		s.directoryBadRequest(w, "invalid page_token")
		return
	}

	// Directory entities are told apart by the kind in their id (user:/group:), not
	// by a stored entity kind, so an entity-graph page can hold both and is filtered
	// here. The token is the entity-graph position plus the rows of that page
	// already returned, so a page holds exactly limit rows and none repeats.
	pageSize := limit
	if pageSize > directoryScanPageSize {
		pageSize = directoryScanPageSize
	}
	needle := strings.ToLower(text)
	filter := eginterfaces.EntityFilter{
		TenantFilter:     tenant,
		TenantSubtreeIDs: ids,
		AuthorityTypes:   authorityTypes,
	}

	items := make([]*directoryObject, 0, limit)
	pos, skip := cur.Pos, cur.Skip
	var next *directoryCursor
scan:
	for scanned := 0; ; scanned++ {
		page, err := s.queryEntitiesInReadScope(r, dr.route, filter, eginterfaces.PageToken{Token: pos, PageSize: pageSize})
		if err != nil {
			s.directoryInternalError(w, "query", err)
			return
		}
		eids := make([]egtypes.EID, 0, len(page.Entities))
		owners := make([]string, 0, len(page.Entities))
		for _, v := range page.Entities {
			if v == nil || v.Entity == nil || directoryLocalID(v.Entity.EID, dr.kind) == "" {
				continue
			}
			eids = append(eids, v.Entity.EID)
			owners = append(owners, v.Entity.OwningTenant)
		}
		if skip > len(eids) {
			skip = len(eids)
		}
		views, err := s.loadDirectoryViews(r, owners[skip:], eids[skip:])
		if err != nil {
			s.directoryInternalError(w, "load", err)
			return
		}
		for i := skip; i < len(eids); i++ {
			view := views[eids[i].String()]
			if view == nil {
				continue
			}
			obj := buildDirectoryObject(view, dr.kind)
			if enabledSet && (obj.Enabled == nil || *obj.Enabled != enabled) {
				continue
			}
			if managedSet && obj.Managed != managed {
				continue
			}
			if needle != "" && !directoryMatchesQuery(obj, needle) {
				continue
			}
			if len(items) == limit {
				// The token names this row: the first one not yet returned.
				next = &directoryCursor{Tenant: tenant, Filter: filterKey, Pos: pos, Skip: i}
				break scan
			}
			items = append(items, obj)
		}
		pos, skip = page.NextToken, 0
		if pos == "" {
			break
		}
		if scanned+1 >= directoryMaxScanPages {
			// The scan budget is spent: return what was found with a token to go on.
			next = &directoryCursor{Tenant: tenant, Filter: filterKey, Pos: pos}
			break
		}
	}

	resp := map[string]interface{}{"items": items}
	if next != nil {
		resp["next_page_token"] = encodeDirectoryCursor(*next)
	}
	writeEntityJSON(w, resp)
}

// ---- by-id ----

// findDirectoryEID resolves {source}/{id} to an entity id. With an authority
// (domain or tenant GUID) it is exact; without, the caller's read scope is searched
// for the object id. found is false when nothing matches inside that scope.
func (s *Server) findDirectoryEID(w http.ResponseWriter, r *http.Request, dr directoryRoute, source, id, authority string) (egtypes.EID, bool) {
	at := directorySourceAuthority[source]
	if authority != "" {
		eid, err := egtypes.NewEID(at, authority, dr.kind+":"+id)
		if err != nil {
			s.directoryNotFound(w)
			return egtypes.EID{}, false
		}
		return eid, true
	}
	tenant, ids := s.entityCut(r)
	filter := eginterfaces.EntityFilter{TenantFilter: tenant, TenantSubtreeIDs: ids, AuthorityTypes: []string{at}}
	var matches []egtypes.EID
	pos := ""
	for scanned := 0; scanned < directoryMaxScanPages*10; scanned++ {
		page, err := s.queryEntitiesInReadScope(r, dr.route, filter, eginterfaces.PageToken{Token: pos, PageSize: directoryMaxLimit})
		if err != nil {
			s.directoryInternalError(w, "find", err)
			return egtypes.EID{}, false
		}
		for _, v := range page.Entities {
			if v != nil && v.Entity != nil && directoryLocalID(v.Entity.EID, dr.kind) == id {
				matches = append(matches, v.Entity.EID)
			}
		}
		pos = page.NextToken
		if pos == "" {
			break
		}
	}
	switch len(matches) {
	case 0:
		s.directoryNotFound(w)
		return egtypes.EID{}, false
	case 1:
		return matches[0], true
	}
	s.writeErrorResponse(w, http.StatusConflict, "id exists in more than one domain; pass authority", "AMBIGUOUS_ID")
	return egtypes.EID{}, false
}

// loadDirectoryObject validates the path, finds the object and puts it through the
// entity read path: it must exist inside the caller's tenant cut and its owning
// tenant must pass the read-scope decision. A refusal is written and false returned;
// another tenant's object is a plain 404.
func (s *Server) loadDirectoryObject(w http.ResponseWriter, r *http.Request, dr directoryRoute) (*egtypes.EntityView, bool) {
	if s.egProvider == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "entity graph unavailable", "SERVICE_UNAVAILABLE")
		return nil, false
	}
	vars := mux.Vars(r)
	source, id := vars["source"], vars["id"]
	if _, known := directorySourceAuthority[source]; !known {
		s.directoryBadRequest(w, "source must be ad or m365")
		return nil, false
	}
	if !validDirectoryObjectID(id) {
		s.directoryBadRequest(w, "invalid id")
		return nil, false
	}
	authority := r.URL.Query().Get("authority")
	if authority != "" && !validDirectoryAuthority(authority) {
		s.directoryBadRequest(w, "invalid authority")
		return nil, false
	}
	eid, ok := s.findDirectoryEID(w, r, dr, source, id, authority)
	if !ok {
		return nil, false
	}
	tenant, ids := s.entityCut(r)
	view, err := s.egProvider.GetEntity(r.Context(), eid, eginterfaces.GetEntityOpts{TenantFilter: tenant, TenantSubtreeIDs: ids})
	if err != nil {
		if isEntityNotFound(err) {
			s.directoryNotFound(w)
			return nil, false
		}
		s.directoryInternalError(w, "get", err)
		return nil, false
	}
	if view == nil || view.Entity == nil || directoryLocalID(view.Entity.EID, dr.kind) == "" {
		s.directoryNotFound(w)
		return nil, false
	}
	if !s.authorizeRecordRead(w, r, view.Entity.OwningTenant, dr.route, func() { s.directoryNotFound(w) }) {
		return nil, false
	}
	return view, true
}

func directoryMembershipAuthority(eid egtypes.EID) string { return eid.AuthoritySegment() }

func (s *Server) handleGetDirectoryUser(w http.ResponseWriter, r *http.Request) {
	dr := directoryRoute{route: "GET /api/v1/directory/users/{source}/{id}", kind: directoryKindUser}
	view, ok := s.loadDirectoryObject(w, r, dr)
	if !ok {
		return
	}
	obj := buildDirectoryObject(view, dr.kind)
	if store := s.directoryMembershipStore(); store != nil {
		page, err := store.ListGroupsOf(r.Context(), view.Entity.OwningTenant, directoryMembershipAuthority(view.Entity.EID), obj.ID, "", directoryInlineGroups)
		if err != nil {
			s.directoryInternalError(w, "groups-of", err)
			return
		}
		refs, err := s.directoryGroupRefs(r, view, page.GroupIDs)
		if err != nil {
			s.directoryInternalError(w, "group-names", err)
			return
		}
		obj.Groups = refs
		if page.Truncated || page.NextCursor != "" {
			obj.GroupsTruncated = true
		}
	} else {
		// Without the membership store the group list cannot be answered, so it is
		// reported as unavailable rather than as empty.
		obj.GroupsTruncated = true
	}
	writeEntityJSON(w, obj)
}

func (s *Server) handleGetDirectoryGroup(w http.ResponseWriter, r *http.Request) {
	dr := directoryRoute{route: "GET /api/v1/directory/groups/{source}/{id}", kind: directoryKindGroup}
	view, ok := s.loadDirectoryObject(w, r, dr)
	if !ok {
		return
	}
	writeEntityJSON(w, buildDirectoryObject(view, dr.kind))
}

// directoryGroupRefs resolves group ids to display names with one batched load,
// inside the owning tenant of the user the ids came from.
func (s *Server) directoryGroupRefs(r *http.Request, user *egtypes.EntityView, groupIDs []string) ([]directoryGroupRef, error) {
	eids := make([]egtypes.EID, 0, len(groupIDs))
	owners := make([]string, 0, len(groupIDs))
	valid := make([]string, 0, len(groupIDs))
	eid := user.Entity.EID
	for _, g := range groupIDs {
		ge, err := egtypes.NewEID(eid.AuthorityType(), eid.AuthorityName(), directoryKindGroup+":"+g)
		if err != nil {
			continue
		}
		eids = append(eids, ge)
		owners = append(owners, user.Entity.OwningTenant)
		valid = append(valid, g)
	}
	views, err := s.loadDirectoryViews(r, owners, eids)
	if err != nil {
		return nil, err
	}
	refs := make([]directoryGroupRef, 0, len(groupIDs))
	for i, g := range valid {
		ref := directoryGroupRef{ID: g}
		if v := views[eids[i].String()]; v != nil {
			ref.DisplayName = directoryAttrString(v.Entity.Attributes, "display_name")
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// ---- membership ----

// requireDirectoryMembership returns the membership store or writes a 503.
func (s *Server) requireDirectoryMembership(w http.ResponseWriter) (directory.MembershipStore, bool) {
	store := s.directoryMembershipStore()
	if store == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "directory membership unavailable", "SERVICE_UNAVAILABLE")
		return nil, false
	}
	return store, true
}

// directoryStoreError maps a membership store refusal onto a response.
func (s *Server) directoryStoreError(w http.ResponseWriter, op string, err error) {
	if errors.Is(err, directory.ErrInvalidCursor) {
		s.directoryBadRequest(w, "invalid page_token")
		return
	}
	if errors.Is(err, directory.ErrInvalidArgument) {
		s.directoryNotFound(w)
		return
	}
	s.directoryInternalError(w, op, err)
}

func (s *Server) handleListDirectoryGroupMembers(w http.ResponseWriter, r *http.Request) {
	dr := directoryRoute{route: "GET /api/v1/directory/groups/{source}/{id}/members", kind: directoryKindGroup}
	q := r.URL.Query()
	limit, ok := parseDirectoryLimit(q)
	if !ok {
		s.directoryBadRequest(w, "limit must be an integer between 1 and 500")
		return
	}
	token := q.Get("page_token")
	if len(token) > directoryMaxTokenLen {
		s.directoryBadRequest(w, "invalid page_token")
		return
	}
	store, ok := s.requireDirectoryMembership(w)
	if !ok {
		return
	}
	view, ok := s.loadDirectoryObject(w, r, dr)
	if !ok {
		return
	}
	id := directoryLocalID(view.Entity.EID, dr.kind)
	page, err := store.ListMembers(r.Context(), view.Entity.OwningTenant, directoryMembershipAuthority(view.Entity.EID), id, token, limit)
	if err != nil {
		s.directoryStoreError(w, "members", err)
		return
	}
	members := make([]directoryMember, 0, len(page.Members))
	for _, m := range page.Members {
		members = append(members, directoryMember{ID: m.ID, Type: string(m.Type), DisplayName: m.DisplayName})
	}
	resp := map[string]interface{}{"members": members}
	if page.NextCursor != "" {
		resp["next_page_token"] = page.NextCursor
	}
	writeEntityJSON(w, resp)
}

func (s *Server) handleListDirectoryUserGroups(w http.ResponseWriter, r *http.Request) {
	dr := directoryRoute{route: "GET /api/v1/directory/users/{source}/{id}/groups", kind: directoryKindUser}
	q := r.URL.Query()
	limit, ok := parseDirectoryLimit(q)
	if !ok {
		s.directoryBadRequest(w, "limit must be an integer between 1 and 500")
		return
	}
	token := q.Get("page_token")
	if len(token) > directoryMaxTokenLen {
		s.directoryBadRequest(w, "invalid page_token")
		return
	}
	store, ok := s.requireDirectoryMembership(w)
	if !ok {
		return
	}
	view, ok := s.loadDirectoryObject(w, r, dr)
	if !ok {
		return
	}
	id := directoryLocalID(view.Entity.EID, dr.kind)
	page, err := store.ListGroupsOf(r.Context(), view.Entity.OwningTenant, directoryMembershipAuthority(view.Entity.EID), id, token, limit)
	if err != nil {
		s.directoryStoreError(w, "groups-of", err)
		return
	}
	refs, err := s.directoryGroupRefs(r, view, page.GroupIDs)
	if err != nil {
		s.directoryInternalError(w, "group-names", err)
		return
	}
	truncated, _ := directoryAttrBool(view.Entity.Attributes, "member_of_truncated")
	resp := map[string]interface{}{
		"groups":           refs,
		"groups_truncated": truncated || page.Truncated,
	}
	if page.NextCursor != "" {
		resp["next_page_token"] = page.NextCursor
	}
	writeEntityJSON(w, resp)
}

func (s *Server) handleListDirectoryMembershipChanges(w http.ResponseWriter, r *http.Request) {
	dr := directoryRoute{route: "GET /api/v1/directory/groups/{source}/{id}/membership-changes", kind: directoryKindGroup}
	q := r.URL.Query()
	limit, ok := parseDirectoryLimit(q)
	if !ok {
		s.directoryBadRequest(w, "limit must be an integer between 1 and 500")
		return
	}
	var since, until time.Time
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"since", &since}, {"until", &until}} {
		if raw := q.Get(p.name); raw != "" {
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				s.directoryBadRequest(w, p.name+" must be RFC 3339 (e.g. 2006-01-02T15:04:05Z)")
				return
			}
			*p.dst = t
		}
	}
	if !since.IsZero() && !until.IsZero() && until.Before(since) {
		s.directoryBadRequest(w, "until must not be before since")
		return
	}
	member := q.Get("member")
	if member != "" && !validDirectoryMemberID(member) {
		s.directoryBadRequest(w, "invalid member")
		return
	}
	baseline, _, ok := parseDirectoryBool(q, "include_baseline")
	if !ok {
		s.directoryBadRequest(w, "include_baseline must be true or false")
		return
	}
	store, ok := s.requireDirectoryMembership(w)
	if !ok {
		return
	}
	view, ok := s.loadDirectoryObject(w, r, dr)
	if !ok {
		return
	}
	owner := view.Entity.OwningTenant
	groupEID := view.Entity.EID
	filterKey := directoryFilterKey(groupEID.String(), owner, member, strconv.FormatBool(baseline),
		since.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano), strconv.Itoa(limit))
	cur, ok := decodeDirectoryCursor(q.Get("page_token"), owner, filterKey)
	if !ok {
		s.directoryBadRequest(w, "invalid page_token")
		return
	}

	// The store lists oldest first. Reading the matching events and walking them
	// backwards gives newest first; the cursor is the count of events older than the
	// ones already returned, so events recorded meanwhile never shift a page.
	query := directory.ChangeQuery{
		Authority: directoryMembershipAuthority(groupEID), GroupID: directoryLocalID(groupEID, dr.kind),
		MemberID: member, IncludeBaseline: baseline, Since: since, Until: until, Limit: 1000,
	}
	var all []directory.ChangeEvent
	for {
		page, err := store.ListChanges(r.Context(), owner, query)
		if err != nil {
			s.directoryStoreError(w, "changes", err)
			return
		}
		all = append(all, page.Events...)
		if len(all) > directoryMaxChangeScan {
			s.directoryBadRequest(w, "too many membership changes in range; narrow it with since and until")
			return
		}
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
	}
	before := len(all)
	if cur.Before > 0 && cur.Before < before {
		before = cur.Before
	}
	start := before - limit
	if start < 0 {
		start = 0
	}
	events := make([]directoryChange, 0, before-start)
	for i := before - 1; i >= start; i-- {
		ev := all[i]
		events = append(events, directoryChange{
			Group: ev.GroupEID, Member: ev.MemberEID, MemberType: string(ev.MemberType), Op: ev.Op,
			ObservedAt: ev.ObservedAt, RecordedAt: ev.RecordedAt, Source: ev.Source, Baseline: ev.Baseline,
		})
	}
	resp := map[string]interface{}{"events": events}
	if start > 0 {
		resp["next_page_token"] = encodeDirectoryCursor(directoryCursor{Tenant: owner, Filter: filterKey, Before: start})
	}
	writeEntityJSON(w, resp)
}
