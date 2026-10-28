// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package types

import (
	"strings"
	"unicode/utf8"
)

// Directory-authority vocabulary shared by the DNA-sync writer, the controller's
// directory verifier and config validation, so all three read one definition.
const (
	// KindDirectoryUser and KindDirectoryGroup are the fragment kinds a directory
	// module emits per object. They resolve to directory:<domain>/user:<local> and
	// directory:<domain>/group:<local>.
	KindDirectoryUser  = "directory_user"
	KindDirectoryGroup = "directory_group"

	// PayloadDirectoryDomain is the fragment payload key naming the domain an
	// object belongs to. It is a steward claim; it reaches an EID only after the
	// DirectoryAuthority verifier accepts it.
	PayloadDirectoryDomain = "directory_domain"

	// DirectoryDomainsNamespace is the config-store namespace of the domain
	// registry: ConfigKey{TenantID: DirectoryDomainsTenantID, Namespace:
	// DirectoryDomainsNamespace, Name: <normalized domain>}.
	DirectoryDomainsNamespace = "directory-domains"

	// DirectoryDomainsTenantID is the tenant segment of the registry key. The
	// registry is global (it exists to span tenants), but every config store
	// rejects an empty tenant segment, so a reserved non-tenant value stands in for
	// the empty one.
	DirectoryDomainsTenantID = "_global"

	// MaxDirectoryDomainLen is the DNS name limit.
	MaxDirectoryDomainLen = 253
)

// NormalizeDirectoryDomain lowercases a DNS domain name and strips one trailing
// dot, then reports whether the result is a storable domain: non-empty, at most
// MaxDirectoryDomainLen bytes, made of dot-separated labels of 1-63 characters
// drawn from [a-z0-9_-], none beginning or ending with '-'. Anything else
// (a '/', a control character, an empty label, non-ASCII) is malformed.
func NormalizeDirectoryDomain(domain string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == "" || len(d) > MaxDirectoryDomainLen || !utf8.ValidString(d) {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return "", false
			}
		}
	}
	return d, true
}
