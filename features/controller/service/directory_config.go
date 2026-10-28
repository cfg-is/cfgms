// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"fmt"
	"sort"
	"strings"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/config"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// Declaration shape of a directory domain, the single producer other stories cite:
//
//	resources:
//	  - name: corp-domain
//	    module: activedirectory.domain
//	    config:
//	      domain: corp.example.com   # DNS name; stored lowercase, no trailing dot
//
// Directory resources (activedirectory.*) are declared only in the DC steward's own
// device-level cfg. The same declaration is what the controller's DirectoryAuthority
// verifier later looks for in that steward's effective cfg.
const (
	// DirectoryModulePrefix is the module namespace of directory resources.
	DirectoryModulePrefix = "activedirectory."
	// DirectoryDomainModule is the module that declares a domain.
	DirectoryDomainModule = "activedirectory.domain"
	// m365EntraModulePrefix is the module namespace of Entra resources, which share
	// the no-credentials-in-cfg rule.
	m365EntraModulePrefix = "m365-entra-"
)

// Config validation error codes for directory declarations.
const (
	CodeDirectoryNonDeviceLevel  = "DIRECTORY_RESOURCE_NON_DEVICE_LEVEL"
	CodeDirectoryInvalidDomain   = "DIRECTORY_DOMAIN_INVALID"
	CodeDirectoryDomainConflict  = "DIRECTORY_DOMAIN_CONFLICT"
	CodeDirectoryForbiddenField  = "DIRECTORY_FORBIDDEN_FIELD"
	CodeDirectoryReservedName    = "DIRECTORY_RESERVED_RESOURCE_NAME"
	CodeDirectoryRegistryFailure = "DIRECTORY_REGISTRY_ERROR"
)

// forbiddenDirectoryFields are credential fields no declared directory or Entra
// resource may carry: a cfg is stored and delivered in cleartext, so a password in
// it would be a cleartext secret on disk and on the wire.
var forbiddenDirectoryFields = map[string]struct{}{
	"password":         {},
	"password_profile": {},
	"initial_password": {},
}

func isDirectoryResource(r stewardtypes.ResourceConfig) bool {
	return strings.HasPrefix(r.Module, DirectoryModulePrefix)
}

// isReservedResourceName reports whether name collides with a per-object directory
// fragment kind. Those kinds are produced by the directory module itself; a
// declared resource of the same name would shadow them.
func isReservedResourceName(name string) bool {
	n := strings.ToLower(name)
	return n == egtypes.KindDirectoryUser || n == egtypes.KindDirectoryGroup
}

// CheckDirectoryDeclarations is the one static check every config save path runs
// (SetConfiguration, BatchSetConfigurations, ValidateConfig and, through
// SetConfiguration, the config push handler). It is pure: it never reads or writes
// the domain registry. Errors name the offending field and never name another tenant.
//
// level is the hierarchy level the document is saved at. activedirectory.*
// resources are only valid at config.LevelDevice: a tenant-level or cluster/role
// declaration would be inherited by every steward below it, which would make
// "this steward declares the domain" meaningless as an authority signal.
func CheckDirectoryDeclarations(level config.InheritanceLevel, cfg *stewardtypes.StewardConfig) []config.ValidationError {
	if cfg == nil {
		return nil
	}
	var errs []config.ValidationError
	add := func(field, msg, code string) {
		errs = append(errs, config.ValidationError{Field: field, Message: msg, Code: code, Level: "error"})
	}
	for i, r := range cfg.Resources {
		base := fmt.Sprintf("resources[%d]", i)
		if isReservedResourceName(r.Name) {
			add(base+".name", fmt.Sprintf("resource name %q is reserved", r.Name), CodeDirectoryReservedName)
		}
		dir := isDirectoryResource(r)
		if dir && level != config.LevelDevice {
			add(base+".module", "activedirectory resources may only be declared in a steward's own device-level configuration", CodeDirectoryNonDeviceLevel)
		}
		if dir || strings.HasPrefix(r.Module, m365EntraModulePrefix) {
			for _, path := range forbiddenFieldPaths(r.Config, base+".config") {
				add(path, "credential fields are not allowed in a declared directory resource", CodeDirectoryForbiddenField)
			}
		}
		if r.Module == DirectoryDomainModule {
			raw, _ := r.Config["domain"].(string)
			if _, ok := egtypes.NormalizeDirectoryDomain(raw); !ok {
				add(base+".config.domain", "domain must be a DNS name", CodeDirectoryInvalidDomain)
			}
		}
	}
	return errs
}

// forbiddenFieldPaths returns the path of every forbidden credential key found in m,
// recursing through nested maps and lists, in a deterministic order.
func forbiddenFieldPaths(m map[string]interface{}, prefix string) []string {
	var out []string
	for _, k := range sortedKeys(m) {
		path := prefix + "." + k
		if _, bad := forbiddenDirectoryFields[strings.ToLower(k)]; bad {
			out = append(out, path)
			continue
		}
		out = append(out, forbiddenFieldPathsValue(m[k], path)...)
	}
	return out
}

func forbiddenFieldPathsValue(v interface{}, path string) []string {
	switch t := v.(type) {
	case map[string]interface{}:
		return forbiddenFieldPaths(t, path)
	case map[interface{}]interface{}:
		conv := make(map[string]interface{}, len(t))
		for k, val := range t {
			conv[fmt.Sprint(k)] = val
		}
		return forbiddenFieldPaths(conv, path)
	case []interface{}:
		var out []string
		for i, e := range t {
			out = append(out, forbiddenFieldPathsValue(e, fmt.Sprintf("%s[%d]", path, i))...)
		}
		return out
	}
	return nil
}

// DeclaredDirectoryDomains returns the normalized, de-duplicated domains cfg
// declares through activedirectory.domain resources, in declaration order. Resources
// whose domain is malformed are skipped (CheckDirectoryDeclarations rejects them).
func DeclaredDirectoryDomains(cfg *stewardtypes.StewardConfig) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, r := range cfg.Resources {
		if r.Module != DirectoryDomainModule {
			continue
		}
		raw, _ := r.Config["domain"].(string)
		d, ok := egtypes.NormalizeDirectoryDomain(raw)
		if !ok {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
