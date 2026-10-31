// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Declared resource types. The executor passes a declared resource to Get and
// Set as "<type>:<name>" (module reference activedirectory.<type>).
const (
	resourceUser   = "user"
	resourceGroup  = "group"
	resourceDomain = "domain"

	// credentialKindUser is the credential kind of a new user's initial
	// password, as the controller's credential service expects it.
	credentialKindUser = "activedirectory.user"
)

// Write operations, as named in module.yaml (supported_operations.write and
// security.audit_operations) and accepted by write.ps1.
const (
	opCreateUser        = "create_user"
	opSetUserEnabled    = "set_user_enabled"
	opSetUserAttributes = "set_user_attributes"
	opCreateGroup       = "create_group"
	opAddGroupMember    = "add_group_member"
	opRemoveGroupMember = "remove_group_member"
)

// writeOperations is every write the module implements.
var writeOperations = []string{
	opCreateUser, opSetUserEnabled, opSetUserAttributes,
	opCreateGroup, opAddGroupMember, opRemoveGroupMember,
}

const (
	maxUserSamLength   = 20
	maxGroupSamLength  = 64
	maxNameLength      = 256
	maxMembersPerList  = 1000
	defaultGroupScope  = "Global"
	defaultGroupCateg  = "Security"
	maxOUComponentSize = 64
)

// namePattern is the character set of every name a declared resource carries
// (sAMAccountName, userPrincipalName, displayName, mail, member names). A
// name may not start with "-", so it can never be read as a parameter.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9._@][A-Za-z0-9._@ -]*$`)

// ouPattern is a distinguished name built only from OU, CN and DC components
// with plain values: no escapes, no quoting, no leading or trailing spaces.
var ouPattern = regexp.MustCompile(`(?i)^(?:(?:OU|CN)=[A-Za-z0-9._-](?:[A-Za-z0-9._ -]{0,62}[A-Za-z0-9._-])?,)*(?:DC=[A-Za-z0-9-]{1,63},)*DC=[A-Za-z0-9-]{1,63}$`)

var groupScopes = map[string]string{"domainlocal": "DomainLocal", "global": "Global", "universal": "Universal"}
var groupCategories = map[string]string{"security": "Security", "distribution": "Distribution"}

// splitResourceID splits a declared resource ID into its type and name.
func splitResourceID(resourceID string) (kind, name string, ok bool) {
	kind, name, found := strings.Cut(resourceID, ":")
	if !found || name == "" {
		return "", "", false
	}
	switch kind {
	case resourceUser, resourceGroup, resourceDomain:
		return kind, name, true
	}
	return "", "", false
}

func resourceIDFor(kind, name string) string { return kind + ":" + name }

// isReservedName reports whether name is one of the inventory IDs.
func isReservedName(name string) bool {
	n := strings.ToLower(name)
	return n == kindDirectoryUser || n == kindDirectoryGroup
}

// Validate checks a declared resource before it is used: the resource name may
// not be one of the inventory IDs (directory_user, directory_group), so
// inventory Get IDs and declared IDs cannot be confused, and the configuration
// of an activedirectory.user, .group or .domain resource must parse.
func (m *activeDirectoryModule) Validate(resourceID string, config modules.ConfigState) error {
	name := resourceID
	kind, typedName, typed := splitResourceID(resourceID)
	if typed {
		name = typedName
	}
	if isReservedName(name) {
		return fmt.Errorf("resource name %q is reserved for directory inventory and cannot be declared", name)
	}
	if !typed {
		return nil
	}
	if config == nil {
		return fmt.Errorf("activedirectory: %s resource %q has no configuration", kind, name)
	}
	_, err := parseConfig(kind, config.AsMap())
	return err
}

// ---- configuration ----------------------------------------------------------

type userConfig struct {
	SamAccountName    string
	UserPrincipalName string
	DisplayName       string
	Mail              string
	OU                string
	Enabled           bool
	Adopt             bool

	hasDisplayName bool
	hasMail        bool
	hasEnabled     bool
}

type groupConfig struct {
	SamAccountName string
	OU             string
	GroupScope     string
	GroupCategory  string
	MembersPresent []string
	MembersAbsent  []string
	Adopt          bool
}

type domainConfig struct {
	Domain string
}

type parsedConfig struct {
	user   *userConfig
	group  *groupConfig
	domain *domainConfig
}

func parseConfig(kind string, raw map[string]interface{}) (parsedConfig, error) {
	var p parsedConfig
	var err error
	switch kind {
	case resourceUser:
		p.user, err = parseUserConfig(raw)
	case resourceGroup:
		p.group, err = parseGroupConfig(raw)
	case resourceDomain:
		p.domain, err = parseDomainConfig(raw)
	default:
		err = fmt.Errorf("activedirectory: unknown resource type %q", kind)
	}
	return p, err
}

// configReader reads typed fields from a raw configuration map and rejects
// fields it does not know.
type configReader struct {
	raw     map[string]interface{}
	allowed map[string]bool
	err     error
}

func newConfigReader(raw map[string]interface{}, fields ...string) *configReader {
	r := &configReader{raw: raw, allowed: map[string]bool{}}
	for _, f := range fields {
		r.allowed[f] = true
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !r.allowed[k] {
			r.err = fmt.Errorf("activedirectory: unknown field %q", logging.SanitizeLogValue(k))
			break
		}
	}
	return r
}

func (r *configReader) str(field string) (string, bool) {
	v, ok := r.raw[field]
	if !ok || r.err != nil {
		return "", false
	}
	s, isStr := v.(string)
	if !isStr {
		r.err = fmt.Errorf("activedirectory: %s must be a string", field)
		return "", false
	}
	return s, true
}

func (r *configReader) boolean(field string) (bool, bool) {
	v, ok := r.raw[field]
	if !ok || r.err != nil {
		return false, false
	}
	b, isBool := v.(bool)
	if !isBool {
		r.err = fmt.Errorf("activedirectory: %s must be true or false", field)
		return false, false
	}
	return b, true
}

func (r *configReader) list(field string) []string {
	v, ok := r.raw[field]
	if !ok || r.err != nil {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case []string:
		out = append(out, t...)
	case []interface{}:
		for _, e := range t {
			s, isStr := e.(string)
			if !isStr {
				r.err = fmt.Errorf("activedirectory: %s must be a list of names", field)
				return nil
			}
			out = append(out, s)
		}
	default:
		r.err = fmt.Errorf("activedirectory: %s must be a list of names", field)
		return nil
	}
	return out
}

// checkName validates one name against namePattern and maxLen.
func checkName(field, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("activedirectory: %s is longer than %d characters", field, maxLen)
	}
	if !namePattern.MatchString(value) {
		return fmt.Errorf("activedirectory: %s may contain only letters, digits, '.', '_', '@', '-' and spaces, and may not start with '-' or a space", field)
	}
	return nil
}

func checkOU(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxNameLength*2 || !ouPattern.MatchString(value) {
		return fmt.Errorf("activedirectory: ou must be a distinguished name of plain OU, CN and DC components")
	}
	return nil
}

func parseUserConfig(raw map[string]interface{}) (*userConfig, error) {
	r := newConfigReader(raw, "sam_account_name", "user_principal_name", "display_name", "mail", "ou", "enabled", "adopt")
	c := &userConfig{Enabled: true}
	c.SamAccountName, _ = r.str("sam_account_name")
	c.UserPrincipalName, _ = r.str("user_principal_name")
	c.DisplayName, c.hasDisplayName = r.str("display_name")
	c.Mail, c.hasMail = r.str("mail")
	c.OU, _ = r.str("ou")
	if v, ok := r.boolean("enabled"); ok {
		c.Enabled, c.hasEnabled = v, true
	}
	c.Adopt, _ = r.boolean("adopt")
	if r.err != nil {
		return nil, r.err
	}
	if c.SamAccountName == "" {
		return nil, fmt.Errorf("activedirectory: sam_account_name is required")
	}
	if err := checkName("sam_account_name", c.SamAccountName, maxUserSamLength); err != nil {
		return nil, err
	}
	for field, value := range map[string]string{"user_principal_name": c.UserPrincipalName, "display_name": c.DisplayName, "mail": c.Mail} {
		if value == "" {
			continue
		}
		if err := checkName(field, value, maxNameLength); err != nil {
			return nil, err
		}
	}
	if err := checkOU(c.OU); err != nil {
		return nil, err
	}
	return c, nil
}

func parseGroupConfig(raw map[string]interface{}) (*groupConfig, error) {
	r := newConfigReader(raw, "sam_account_name", "ou", "group_scope", "group_category", "members_present", "members_absent", "adopt")
	c := &groupConfig{GroupScope: defaultGroupScope, GroupCategory: defaultGroupCateg}
	c.SamAccountName, _ = r.str("sam_account_name")
	c.OU, _ = r.str("ou")
	scope, hasScope := r.str("group_scope")
	category, hasCategory := r.str("group_category")
	c.MembersPresent = r.list("members_present")
	c.MembersAbsent = r.list("members_absent")
	c.Adopt, _ = r.boolean("adopt")
	if r.err != nil {
		return nil, r.err
	}
	if c.SamAccountName == "" {
		return nil, fmt.Errorf("activedirectory: sam_account_name is required")
	}
	if err := checkName("sam_account_name", c.SamAccountName, maxGroupSamLength); err != nil {
		return nil, err
	}
	if err := checkOU(c.OU); err != nil {
		return nil, err
	}
	if hasScope {
		v, ok := groupScopes[strings.ToLower(scope)]
		if !ok {
			return nil, fmt.Errorf("activedirectory: group_scope must be DomainLocal, Global or Universal")
		}
		c.GroupScope = v
	}
	if hasCategory {
		v, ok := groupCategories[strings.ToLower(category)]
		if !ok {
			return nil, fmt.Errorf("activedirectory: group_category must be Security or Distribution")
		}
		c.GroupCategory = v
	}
	if len(c.MembersPresent) > maxMembersPerList || len(c.MembersAbsent) > maxMembersPerList {
		return nil, fmt.Errorf("activedirectory: a member list may hold at most %d names", maxMembersPerList)
	}
	seen := map[string]string{}
	for _, list := range []struct {
		field string
		names []string
	}{{"members_present", c.MembersPresent}, {"members_absent", c.MembersAbsent}} {
		for _, n := range list.names {
			if err := checkName(list.field, n, maxGroupSamLength); err != nil {
				return nil, err
			}
			key := strings.ToLower(n)
			if prev, dup := seen[key]; dup {
				if prev != list.field {
					return nil, fmt.Errorf("activedirectory: member %q is listed in both members_present and members_absent", n)
				}
				return nil, fmt.Errorf("activedirectory: member %q is listed twice in %s", n, list.field)
			}
			seen[key] = list.field
		}
	}
	return c, nil
}

func parseDomainConfig(raw map[string]interface{}) (*domainConfig, error) {
	r := newConfigReader(raw, "domain")
	domain, _ := r.str("domain")
	if r.err != nil {
		return nil, r.err
	}
	d, ok := egtypes.NormalizeDirectoryDomain(domain)
	if !ok {
		return nil, fmt.Errorf("activedirectory: domain must be a DNS name")
	}
	return &domainConfig{Domain: d}, nil
}

// domainDN returns the distinguished name of a DNS domain.
func domainDN(domain string) string {
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, "DC="+l)
	}
	return strings.Join(parts, ",")
}

// ouInDomain reports whether ou is the domain's own DN or below it.
func ouInDomain(ou, domain string) bool {
	if ou == "" {
		return true
	}
	o, d := strings.ToLower(ou), strings.ToLower(domainDN(domain))
	return o == d || strings.HasSuffix(o, ","+d)
}

// ---- state --------------------------------------------------------------------

// resourceState is the state Get reports for a declared resource. It carries
// only the fields the declaration names.
type resourceState struct {
	fields map[string]interface{}
}

func (s *resourceState) AsMap() map[string]interface{} {
	out := make(map[string]interface{}, len(s.fields))
	for k, v := range s.fields {
		out[k] = v
	}
	return out
}

func (s *resourceState) ToYAML() ([]byte, error) { return yaml.Marshal(s.fields) }

func (s *resourceState) FromYAML([]byte) error {
	return fmt.Errorf("activedirectory resource state is read-only")
}

func (s *resourceState) Validate() error { return nil }

func (s *resourceState) GetManagedFields() []string {
	keys := make([]string, 0, len(s.fields))
	for k := range s.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SetDeclared implements modules.DeclaredResourceAware.
func (m *activeDirectoryModule) SetDeclared(resources []modules.DeclaredResource) {
	m.declared.replace(resources)
}

// declaredResource returns the declared, parsed resource for resourceID.
func (m *activeDirectoryModule) declaredResource(resourceID string) (declaredResource, error) {
	dr, ok := m.declared.get(resourceID)
	if !ok {
		return declaredResource{}, fmt.Errorf("activedirectory: resource %q is not declared in this steward's configuration", logging.SanitizeLogValue(resourceID))
	}
	if dr.err != nil {
		return declaredResource{}, dr.err
	}
	return dr, nil
}

// getDeclared reports the state of a declared resource. A resource that is
// not bound to an object, or whose bound object is missing or no longer owns
// its name, reports an empty state, so it shows as drift and Set decides.
// Fields set only at creation (names, ou, scope, category) and adopt are
// reported as declared once the bound object is found; enabled, display_name,
// mail and membership are reported as read.
func (m *activeDirectoryModule) getDeclared(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	dr, err := m.declaredResource(resourceID)
	if err != nil {
		return nil, err
	}
	state := &resourceState{fields: map[string]interface{}{}}
	echo := func(fields ...string) {
		for _, f := range fields {
			if v, ok := dr.raw[f]; ok {
				state.fields[f] = v
			}
		}
	}

	switch dr.kind {
	case resourceDomain:
		info, err := m.getDomainInfo(ctx)
		if err != nil {
			return nil, err
		}
		actual, _ := egtypes.NormalizeDirectoryDomain(info.Domain)
		if actual == dr.domain.Domain {
			echo("domain")
		} else {
			state.fields["domain"] = actual
		}
		return state, nil

	case resourceUser:
		target, err := m.boundObject(ctx, resourceID, resourceUser, dr.user.SamAccountName, nil)
		if err != nil || target == nil {
			return state, err
		}
		echo("sam_account_name", "user_principal_name", "ou", "adopt")
		if _, ok := dr.raw["display_name"]; ok {
			state.fields["display_name"] = target.object.DisplayName
		}
		if _, ok := dr.raw["mail"]; ok {
			state.fields["mail"] = target.object.Mail
		}
		if _, ok := dr.raw["enabled"]; ok {
			state.fields["enabled"] = target.object.Enabled
		}
		return state, nil

	default: // resourceGroup
		members := append(append([]string{}, dr.group.MembersPresent...), dr.group.MembersAbsent...)
		target, err := m.boundObject(ctx, resourceID, resourceGroup, dr.group.SamAccountName, members)
		if err != nil || target == nil {
			return state, err
		}
		echo("sam_account_name", "ou", "group_scope", "group_category", "adopt")
		if _, ok := dr.raw["members_present"]; ok {
			present := make([]interface{}, 0, len(dr.group.MembersPresent))
			all := true
			for i, n := range dr.group.MembersPresent {
				if mr := target.members[i]; mr != nil && mr.Found && mr.IsMember && !mr.Uncertain {
					present = append(present, n)
				} else {
					all = false
				}
			}
			if all {
				echo("members_present")
			} else {
				state.fields["members_present"] = present
			}
		}
		if _, ok := dr.raw["members_absent"]; ok {
			absent := make([]interface{}, 0, len(dr.group.MembersAbsent))
			all := true
			offset := len(dr.group.MembersPresent)
			for i, n := range dr.group.MembersAbsent {
				if mr := target.members[offset+i]; mr != nil && (!mr.Found || (!mr.IsMember && !mr.Uncertain)) {
					absent = append(absent, n)
				} else {
					all = false
				}
			}
			if all {
				echo("members_absent")
			} else {
				state.fields["members_absent"] = absent
			}
		}
		return state, nil
	}
}

// lookup is the result of finding a declared resource's object.
type lookup struct {
	byID    *readRecord
	byName  *readRecord
	members map[int]*readRecord // group member records by request index
}

// boundTarget is the object a bound resource converges.
type boundTarget struct {
	object  *readRecord
	members map[int]*readRecord
}

// find reads the object bound by guid (when set) and the object named sam.
func (m *activeDirectoryModule) find(ctx context.Context, kind, guid, sam string, members []string) (*lookup, error) {
	operation := "find_user"
	if kind == resourceGroup {
		operation = "find_group"
	}
	res := &lookup{members: map[int]*readRecord{}}
	err := m.runReadRequest(ctx, readRequest{Operation: operation, ID: guid, SamAccountName: sam, Members: members}, func(rec *readRecord) error {
		switch {
		case rec.Type == kind && rec.Match == "id":
			res.byID = rec
		case rec.Type == kind && rec.Match == "name":
			res.byName = rec
		case rec.Type == "member" && kind == resourceGroup && rec.Index >= 0 && rec.Index < len(members):
			res.members[rec.Index] = rec
		default:
			return fmt.Errorf("activedirectory: unexpected %q record in the %s read", rec.Type, operation)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, r := range []*readRecord{res.byID, res.byName} {
		if r != nil && !objectGUIDPattern.MatchString(r.ID) {
			return nil, fmt.Errorf("activedirectory: the %s read returned a malformed objectGUID", operation)
		}
	}
	return res, nil
}

// boundObject returns the object resourceID is bound to, or nil when the
// resource is unbound, its object is missing, or its name now belongs to a
// different object.
func (m *activeDirectoryModule) boundObject(ctx context.Context, resourceID, kind, sam string, members []string) (*boundTarget, error) {
	if m.bindings == nil {
		return nil, fmt.Errorf("activedirectory: no binding store")
	}
	guid, bound, err := m.bindings.get(resourceID)
	if err != nil || !bound {
		return nil, err
	}
	res, err := m.find(ctx, kind, guid, sam, members)
	if err != nil {
		return nil, err
	}
	if res.byID == nil || res.byID.ID != guid || (res.byName != nil && res.byName.ID != guid) {
		return nil, nil
	}
	return &boundTarget{object: res.byID, members: res.members}, nil
}

// setDeclared converges a declared resource. It writes only the object bound
// to (or, for a new resource, created for or adopted by) this resource, never
// deletes anything, and changes nothing when the resource's object cannot be
// identified unambiguously.
func (m *activeDirectoryModule) setDeclared(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if err := m.Validate(resourceID, config); err != nil {
		return err
	}
	dr, err := m.declaredResource(resourceID)
	if err != nil {
		return err
	}
	desired, err := parseConfig(dr.kind, config.AsMap())
	if err != nil {
		return err
	}
	if m.bindings == nil && dr.kind != resourceDomain {
		return fmt.Errorf("activedirectory: no binding store")
	}

	info, err := m.getDomainInfo(ctx)
	if err != nil {
		return err
	}
	domain, ok := egtypes.NormalizeDirectoryDomain(info.Domain)
	if !ok {
		return fmt.Errorf("activedirectory: the machine's domain could not be read")
	}

	switch dr.kind {
	case resourceDomain:
		if desired.domain.Domain != domain {
			return fmt.Errorf("activedirectory: declared domain %q is not this machine's domain", desired.domain.Domain)
		}
		return nil
	case resourceUser:
		if !ouInDomain(desired.user.OU, domain) {
			return fmt.Errorf("activedirectory: ou is not inside the machine's domain")
		}
		return m.setUser(ctx, resourceID, dr.name, desired.user)
	default:
		if !ouInDomain(desired.group.OU, domain) {
			return fmt.Errorf("activedirectory: ou is not inside the machine's domain")
		}
		return m.setGroup(ctx, resourceID, desired.group)
	}
}

// resolveTarget applies the bind and adopt rules. It returns the object to
// converge, or nil when no object with the name exists and the resource is
// unbound (the caller creates one).
func (m *activeDirectoryModule) resolveTarget(resourceID, sam string, adopt bool, res *lookup) (*readRecord, error) {
	guid, bound, err := m.bindings.get(resourceID)
	if err != nil {
		return nil, err
	}
	if bound {
		if res.byID == nil || res.byID.ID != guid {
			return nil, fmt.Errorf("activedirectory: the object bound to %q no longer exists; nothing was changed", logging.SanitizeLogValue(resourceID))
		}
		if res.byName != nil && res.byName.ID != guid {
			return nil, fmt.Errorf("activedirectory: %q now names a different object than the one bound to %q; nothing was changed", sam, logging.SanitizeLogValue(resourceID))
		}
		return res.byID, nil
	}
	if res.byName == nil {
		return nil, nil
	}
	if !adopt {
		return nil, fmt.Errorf("activedirectory: an object named %q already exists and is not managed by %q; nothing was changed (set adopt: true to manage it)", sam, logging.SanitizeLogValue(resourceID))
	}
	if err := m.bindings.put(resourceID, res.byName.ID); err != nil {
		return nil, err
	}
	m.logger.Info("Adopted existing AD object", "resource_id", logging.SanitizeLogValue(resourceID), "object_guid", res.byName.ID)
	return res.byName, nil
}

func (m *activeDirectoryModule) setUser(ctx context.Context, resourceID, name string, c *userConfig) error {
	guid, _, err := m.bindings.get(resourceID)
	if err != nil {
		return err
	}
	res, err := m.find(ctx, resourceUser, guid, c.SamAccountName, nil)
	if err != nil {
		return err
	}
	target, err := m.resolveTarget(resourceID, c.SamAccountName, c.Adopt, res)
	if err != nil {
		return err
	}
	if target == nil {
		return m.createUser(ctx, resourceID, name, c)
	}

	attrs := writeRequest{Operation: opSetUserAttributes, ID: target.ID}
	changed := false
	if c.hasDisplayName && target.DisplayName != c.DisplayName {
		attrs.DisplayName = stringPtr(c.DisplayName)
		changed = true
	}
	if c.hasMail && target.Mail != c.Mail {
		attrs.Mail = stringPtr(c.Mail)
		changed = true
	}
	if changed {
		if _, err := m.runWrite(ctx, attrs, nil); err != nil {
			return err
		}
	}
	if c.hasEnabled && target.Enabled != c.Enabled {
		if _, err := m.runWrite(ctx, writeRequest{Operation: opSetUserEnabled, ID: target.ID, Enabled: boolPtr(c.Enabled)}, nil); err != nil {
			return err
		}
	}
	return nil
}

// createUser creates the user with a controller-issued one-time password and
// "must change at next logon", then binds the resource to the new object. The
// password is held only in memory, goes to the write script on stdin, and is
// cleared after the call. Without a password no account is created.
func (m *activeDirectoryModule) createUser(ctx context.Context, resourceID, name string, c *userConfig) error {
	client, ok := m.GetCredentialClient()
	if !ok {
		return fmt.Errorf("activedirectory: no credential client; no account was created for %q", logging.SanitizeLogValue(resourceID))
	}
	password, err := client.IssueInitialCredential(ctx, name, credentialKindUser)
	if err != nil || password == "" {
		return fmt.Errorf("activedirectory: the controller did not issue an initial password; no account was created for %q", logging.SanitizeLogValue(resourceID))
	}
	secret := []byte(password)
	defer clear(secret)

	req := writeRequest{
		Operation:         opCreateUser,
		SamAccountName:    c.SamAccountName,
		UserPrincipalName: c.UserPrincipalName,
		DisplayName:       stringPtr(c.DisplayName),
		Mail:              stringPtr(c.Mail),
		OU:                c.OU,
		Enabled:           boolPtr(c.Enabled),
	}
	id, err := m.runWrite(ctx, req, secret)
	if err != nil {
		return err
	}
	if err := m.bindings.put(resourceID, id); err != nil {
		return fmt.Errorf("activedirectory: account created but its binding could not be recorded: %w", err)
	}
	m.logger.Info("Created AD user", "resource_id", logging.SanitizeLogValue(resourceID), "object_guid", id)
	return nil
}

func (m *activeDirectoryModule) setGroup(ctx context.Context, resourceID string, c *groupConfig) error {
	members := append(append([]string{}, c.MembersPresent...), c.MembersAbsent...)
	guid, _, err := m.bindings.get(resourceID)
	if err != nil {
		return err
	}
	res, err := m.find(ctx, resourceGroup, guid, c.SamAccountName, members)
	if err != nil {
		return err
	}
	target, err := m.resolveTarget(resourceID, c.SamAccountName, c.Adopt, res)
	if err != nil {
		return err
	}
	if target == nil {
		id, err := m.runWrite(ctx, writeRequest{
			Operation:      opCreateGroup,
			SamAccountName: c.SamAccountName,
			OU:             c.OU,
			GroupScope:     c.GroupScope,
			GroupCategory:  c.GroupCategory,
		}, nil)
		if err != nil {
			return err
		}
		if err := m.bindings.put(resourceID, id); err != nil {
			return fmt.Errorf("activedirectory: group created but its binding could not be recorded: %w", err)
		}
		m.logger.Info("Created AD group", "resource_id", logging.SanitizeLogValue(resourceID), "object_guid", id)
		if len(members) == 0 {
			return nil
		}
		// Read the members again against the new group.
		if res, err = m.find(ctx, resourceGroup, id, c.SamAccountName, members); err != nil {
			return err
		}
		if res.byID == nil {
			return fmt.Errorf("activedirectory: the new group could not be read back")
		}
		target = res.byID
	}

	for i, n := range c.MembersPresent {
		mr := res.members[i]
		switch {
		case mr == nil || !mr.Found:
			return fmt.Errorf("activedirectory: member %q of members_present was not found", n)
		case mr.Uncertain:
			return fmt.Errorf("activedirectory: the membership of %q cannot be verified; nothing was changed for it", n)
		case mr.IsMember:
			continue
		}
		if !objectGUIDPattern.MatchString(mr.ID) {
			return fmt.Errorf("activedirectory: member %q has a malformed objectGUID", n)
		}
		if _, err := m.runWrite(ctx, writeRequest{Operation: opAddGroupMember, ID: target.ID, MemberID: mr.ID}, nil); err != nil {
			return err
		}
	}
	offset := len(c.MembersPresent)
	for i, n := range c.MembersAbsent {
		mr := res.members[offset+i]
		switch {
		case mr == nil:
			return fmt.Errorf("activedirectory: the membership of %q was not read", n)
		case !mr.Found:
			continue
		case mr.Uncertain:
			return fmt.Errorf("activedirectory: the membership of %q cannot be verified; nothing was changed for it", n)
		case !mr.IsMember:
			continue
		}
		if !objectGUIDPattern.MatchString(mr.ID) {
			return fmt.Errorf("activedirectory: member %q has a malformed objectGUID", n)
		}
		if _, err := m.runWrite(ctx, writeRequest{Operation: opRemoveGroupMember, ID: target.ID, MemberID: mr.ID}, nil); err != nil {
			return err
		}
	}
	return nil
}

// ---- write script ---------------------------------------------------------------

// writeRequest is the request document write.ps1 validates. A new user's
// password is never part of it: it follows the request line on stdin.
type writeRequest struct {
	Operation         string  `json:"operation"`
	ID                string  `json:"id,omitempty"`
	MemberID          string  `json:"member_id,omitempty"`
	SamAccountName    string  `json:"sam_account_name,omitempty"`
	UserPrincipalName string  `json:"user_principal_name,omitempty"`
	DisplayName       *string `json:"display_name,omitempty"`
	Mail              *string `json:"mail,omitempty"`
	OU                string  `json:"ou,omitempty"`
	Enabled           *bool   `json:"enabled,omitempty"`
	GroupScope        string  `json:"group_scope,omitempty"`
	GroupCategory     string  `json:"group_category,omitempty"`
}

func stringPtr(s string) *string { return &s }
func boolPtr(b bool) *bool       { return &b }

// runWrite runs one write operation and returns the objectGUID the script
// reports. stdin is the request line, then, for create_user only, the
// password. The stdin buffer is cleared after the run.
func (m *activeDirectoryModule) runWrite(ctx context.Context, req writeRequest, password []byte) (string, error) {
	if m.writer == nil {
		return "", fmt.Errorf("activedirectory: no write script runner")
	}
	line, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("activedirectory: encode write request: %w", err)
	}
	stdin := make([]byte, 0, len(line)+1+len(password))
	stdin = append(stdin, line...)
	stdin = append(stdin, '\n')
	stdin = append(stdin, password...)
	defer clear(stdin)

	m.updateStats(true)
	var id string
	err = m.writer.Run(ctx, stdin, func(out []byte) error {
		var rec readRecord
		if err := json.Unmarshal(out, &rec); err != nil {
			return fmt.Errorf("activedirectory: decode write script output: %w", err)
		}
		switch rec.Type {
		case "error":
			return fmt.Errorf("activedirectory: %s failed: write script reported %s (%s)", req.Operation, rec.Code, rec.Detail)
		case "done":
			id = strings.ToLower(rec.ID)
			return nil
		}
		return fmt.Errorf("activedirectory: unexpected %q record from the write script", rec.Type)
	})
	if err != nil {
		m.updateStats(false)
		return "", err
	}
	if !objectGUIDPattern.MatchString(id) {
		return "", fmt.Errorf("activedirectory: %s did not report the object's objectGUID", req.Operation)
	}
	m.logger.Info("AD write applied", "operation", req.Operation, "object_guid", id)
	return id, nil
}
