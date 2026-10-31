// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package activedirectory

import (
	"strings"
	"sync"

	"github.com/cfgis/cfgms/features/modules"
)

// DeclaredSet holds the activedirectory resources declared in the steward's
// configuration. The steward factory creates one holder and gives it to every
// activedirectory module instance: the executor's instance receives the
// declared set through SetDeclared, and the observe sweep's instance, a
// different object, reads it to mark the objects it reports as managed.
type DeclaredSet struct {
	mu        sync.RWMutex
	resources map[string]declaredResource
}

// declaredResource is one declared resource, parsed.
type declaredResource struct {
	name   string
	kind   string // resourceUser, resourceGroup or resourceDomain
	raw    map[string]interface{}
	user   *userConfig
	group  *groupConfig
	domain *domainConfig
	err    error // a config that does not parse; Get and Set report it
}

// NewDeclaredSet returns an empty holder.
func NewDeclaredSet() *DeclaredSet {
	return &DeclaredSet{resources: map[string]declaredResource{}}
}

// replace swaps the whole declared set for resources. Resources of other
// modules and the untyped activedirectory resources are ignored.
func (d *DeclaredSet) replace(resources []modules.DeclaredResource) {
	next := make(map[string]declaredResource, len(resources))
	for _, r := range resources {
		kind, name, ok := splitResourceID(r.ResourceID)
		if !ok || name != r.Name {
			continue
		}
		dr := declaredResource{name: name, kind: kind, raw: r.Config}
		switch kind {
		case resourceUser:
			dr.user, dr.err = parseUserConfig(r.Config)
		case resourceGroup:
			dr.group, dr.err = parseGroupConfig(r.Config)
		case resourceDomain:
			dr.domain, dr.err = parseDomainConfig(r.Config)
		}
		next[r.ResourceID] = dr
	}
	d.mu.Lock()
	d.resources = next
	d.mu.Unlock()
}

// get returns the declared resource with the given module-internal ID.
func (d *DeclaredSet) get(resourceID string) (declaredResource, bool) {
	if d == nil {
		return declaredResource{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.resources[resourceID]
	return r, ok
}

// ofKind returns every parsed resource of kind, keyed by resource name.
func (d *DeclaredSet) ofKind(kind string) map[string]declaredResource {
	out := map[string]declaredResource{}
	if d == nil {
		return out
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, r := range d.resources {
		if r.kind == kind && r.err == nil {
			out[r.name] = r
		}
	}
	return out
}

// managedMatcher decides whether an observed object of one kind is managed:
// bound to a declared resource by objectGUID, or, for a declared resource not
// yet bound, matching its sAMAccountName.
type managedMatcher struct {
	guids map[string]bool
	names map[string]bool
}

func (m managedMatcher) managed(id, samAccountName string) bool {
	return m.guids[id] || (samAccountName != "" && m.names[strings.ToLower(samAccountName)])
}

// matcher builds the managedMatcher for kind from the declared set and the
// bindings.
func (d *DeclaredSet) matcher(kind string, bindings BindingStore) managedMatcher {
	m := managedMatcher{guids: map[string]bool{}, names: map[string]bool{}}
	declared := d.ofKind(kind)
	if len(declared) == 0 {
		return m
	}
	bound := map[string]string{}
	if bindings != nil {
		if all, err := bindings.all(); err == nil {
			bound = all
		}
	}
	for _, r := range declared {
		if guid, ok := bound[resourceIDFor(kind, r.name)]; ok {
			m.guids[guid] = true
			continue
		}
		var sam string
		switch kind {
		case resourceUser:
			sam = r.user.SamAccountName
		case resourceGroup:
			sam = r.group.SamAccountName
		}
		if sam != "" {
			m.names[strings.ToLower(sam)] = true
		}
	}
	return m
}
