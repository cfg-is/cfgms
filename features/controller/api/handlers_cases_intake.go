// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Bounds applied to technician-supplied identity claims before they reach the
// entity graph provider.
const (
	// maxIntakeMACClaims bounds the MACAddrs slice. Each accepted MAC expands, in
	// both entity-index providers, into four bound parameters and three
	// leading-wildcard (therefore unindexable) LIKE predicates. The structured-body
	// cap is 10 MiB (validation_middleware.go), which admits tens of thousands of
	// entries, so the slice needs its own bound.
	maxIntakeMACClaims = 32

	maxIntakeHostnameLen = 253 // RFC 1123 FQDN limit
	maxIntakeSIDLen      = 128 // a Windows SID string tops out well under this
	maxIntakeGUIDLen     = 68  // braced, hyphenated GUID
	maxIntakeSerialLen   = 128
	maxIntakeCloudIDLen  = 256
)

// validateIntakeClaims bounds and character-checks technician-supplied identity
// claims before they are handed to ResolveIdentity.
//
// The entity-index providers interpolate MAC claims into SQL LIKE patterns
// (pkg/entitygraph/providers/{sqlite,database}/entity_reads.go) and escape
// neither '%' nor '_'. Values are bound, so this is not SQL injection, but an
// unescaped wildcard turns a lookup into bulk intra-tenant eid enumeration
// (CWE-155) — `{"MACAddrs":["%"]}` otherwise matches every indexed multi-NIC
// host. The per-field charsets below therefore exclude both LIKE
// metacharacters, and no identity claim has a legitimate use for either.
func validateIntakeClaims(c eginterfaces.IdentityClaims) error {
	if err := validateClaimValue("hostname", c.Hostname, maxIntakeHostnameLen, "-."); err != nil {
		return err
	}
	if err := validateClaimValue("machine_sid", c.MachineSID, maxIntakeSIDLen, "-"); err != nil {
		return err
	}
	if err := validateClaimValue("directory_object_guid", c.DirectoryObjectGUID, maxIntakeGUIDLen, "-{}"); err != nil {
		return err
	}
	if err := validateClaimValue("serial_number", c.SerialNumber, maxIntakeSerialLen, "-./+ "); err != nil {
		return err
	}
	if err := validateClaimValue("cloud_object_id", c.CloudObjectID, maxIntakeCloudIDLen, "-.:/@{}"); err != nil {
		return err
	}

	if len(c.MACAddrs) > maxIntakeMACClaims {
		return fmt.Errorf("at most %d mac_addrs claims are accepted", maxIntakeMACClaims)
	}
	for _, mac := range c.MACAddrs {
		// Empty entries are absent, not invalid: claimsEmpty and both providers
		// skip them.
		if mac == "" {
			continue
		}
		if !isMACAddress(mac) {
			return fmt.Errorf("mac_addrs entries must be MAC addresses")
		}
	}
	return nil
}

// validateClaimValue rejects an over-long claim value, or one carrying a
// character outside [A-Za-z0-9] plus the field-specific extra set. An empty
// value is absent, not invalid. No extra set contains '%' or '_'.
func validateClaimValue(field, value string, maxLen int, extra string) error {
	if value == "" {
		return nil
	}
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds %d characters", field, maxLen)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			continue
		case strings.ContainsRune(extra, r):
			continue
		default:
			return fmt.Errorf("%s contains an unsupported character", field)
		}
	}
	return nil
}

// isMACAddress reports whether s is a syntactically valid MAC address in one of
// the notations the entity index stores: colon-, hyphen- or dot-delimited (all
// handled by net.ParseMAC), or bare 12 hex characters. Every accepted form is
// hex digits plus delimiters, so no LIKE metacharacter can pass.
//
// The value is validated, never rewritten: the providers match the stored text
// exactly, so normalizing here would stop matching entities whose reporter used
// a different notation.
func isMACAddress(s string) bool {
	if _, err := net.ParseMAC(s); err == nil {
		return true
	}
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// claimsEmpty reports whether all device identity fields in c are blank or absent.
// MACAddrs entries that are empty strings are treated as absent (matching the
// provider's own skip logic).
func claimsEmpty(c eginterfaces.IdentityClaims) bool {
	if c.Hostname != "" || c.MachineSID != "" || c.DirectoryObjectGUID != "" ||
		c.SerialNumber != "" || c.CloudObjectID != "" {
		return false
	}
	for _, mac := range c.MACAddrs {
		if mac != "" {
			return false
		}
	}
	return true
}

// handleCasesIntakeAssist handles POST /api/v1/cases/intake-assist.
// Resolves technician-supplied device claims to tenant-filtered candidate eids.
// Eids resolved outside the caller's tenant subtree are silently dropped (ADR-022 §7).
func (s *Server) handleCasesIntakeAssist(w http.ResponseWriter, r *http.Request) {
	if s.egProvider == nil {
		http.Error(w, "entity graph unavailable", http.StatusServiceUnavailable)
		return
	}

	var claims eginterfaces.IdentityClaims
	if err := json.NewDecoder(r.Body).Decode(&claims); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if claimsEmpty(claims) {
		http.Error(w, "at least one identity claim is required", http.StatusBadRequest)
		return
	}

	if err := validateIntakeClaims(claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	eids, err := s.egProvider.ResolveIdentity(r.Context(), claims)
	if err != nil {
		s.logger.Error("handleCasesIntakeAssist: resolve failed",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "resolve failed", http.StatusInternalServerError)
		return
	}

	callerTenant := callerTenantSubtree(r)
	candidates := make([]eginterfaces.EIDRef, 0, len(eids))
	for _, eid := range eids {
		ok, accessErr := s.verifyEntityAccess(r.Context(), eid, callerTenant)
		if accessErr != nil {
			s.logger.Error("handleCasesIntakeAssist: entity access check failed",
				"error", logging.SanitizeLogValue(accessErr.Error()),
			)
			http.Error(w, "resolve failed", http.StatusInternalServerError)
			return
		}
		if ok {
			candidates = append(candidates, eid)
		}
		// Cross-tenant eid: silently drop, not surfaced as an error (ADR-022 §7).
	}

	writeEntityJSON(w, candidates)
}
