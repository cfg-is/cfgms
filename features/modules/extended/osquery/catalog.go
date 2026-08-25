// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package osquery: catalog.go defines the bundle-embedded query registry for
// the ad-hoc osquery RPC path (Issue #3566, Epic #2855).
//
// # Governance
//
// The catalog is an in-code, compiled registry shipped inside the signed osquery
// module bundle. It is not runtime-configurable: adding a query requires a code
// change, a publisher re-sign of the bundle, and a controller-side approval
// workflow — the same governance path that governs every other module capability.
//
// # Parameter types
//
// Each parameter in a catalog entry declares one of the following types:
//
//   - ParamTypeEnum: the value must exactly match one of a closed set of literals.
//     No SQL metacharacter check is needed; the value never reaches string
//     substitution unless it is already a known literal.
//   - ParamTypeCharset: the value is a charset-restricted string (path, username,
//     etc.). SQL metacharacters (', --, ;, UNION) are always rejected, and the
//     value must additionally match the declared character whitelist pattern.
//
// Enum is always preferred when the use case allows a closed set of literals.
// Charset is used only when a genuinely open-ended string (a filesystem path, a
// username) is required, with the narrowest allowable character set.
package osquery

import (
	"fmt"
	"regexp"
	"strings"
)

// ParamType enumerates the validation strategies for catalog query parameters.
type ParamType int

const (
	// ParamTypeEnum requires the value to match exactly one entry in an explicit
	// closed set. SQL metacharacter checking is unnecessary — non-literal values
	// are rejected by the set membership check before reaching query construction.
	ParamTypeEnum ParamType = iota

	// ParamTypeCharset allows any value that matches the declared character
	// whitelist AND does not contain SQL metacharacters. Use only when a closed
	// enum is not feasible (e.g. arbitrary filesystem paths, arbitrary usernames).
	ParamTypeCharset
)

// ParamSchema describes the validation rule for one catalog query parameter.
type ParamSchema struct {
	// Type selects the validation strategy (enum or charset).
	Type ParamType

	// AllowedValues is the closed set of accepted literal values for ParamTypeEnum.
	// Ignored for ParamTypeCharset.
	AllowedValues []string

	// CharsetPattern is a compiled regexp that accepted values must fully match for
	// ParamTypeCharset. Nil means no charset restriction beyond the SQL metacharacter
	// block. Ignored for ParamTypeEnum.
	CharsetPattern *regexp.Regexp
}

// CatalogEntry is one named entry in the bundle-embedded catalog registry.
// SQL text is derived here at build time, never accepted from the wire.
type CatalogEntry struct {
	// ID is the stable, human-readable name used in OsqueryQueryRequest.catalog_id.
	ID string

	// query is the SQL template delivered to runQuery via stdin after parameter
	// substitution. It is not exported: callers obtain the final query text only
	// after admission validation succeeds, via CatalogEntry.BuildQuery.
	// Parameter placeholders use the form {{param_name}}.
	query string

	// Params maps each parameter name to its validation schema.
	Params map[string]ParamSchema
}

// sqlMetacharacters is the set of SQL metacharacter fragments that are always
// rejected in ParamTypeCharset parameter values. These never appear in legitimate
// path or username values and are the root cause of SQL injection in template
// substitution paths.
var sqlMetacharacters = []string{"'", "--", ";", "UNION"}

// Validate checks that values satisfies the schema for the named parameter.
// Returns a non-nil error if the value is rejected; the error message is safe
// to include in a log entry after wrapping with logging.SanitizeLogValue.
func (s ParamSchema) Validate(name, value string) error {
	switch s.Type {
	case ParamTypeEnum:
		for _, allowed := range s.AllowedValues {
			if value == allowed {
				return nil
			}
		}
		return fmt.Errorf("parameter %q: value is not in the allowed set", name)

	case ParamTypeCharset:
		// SQL metacharacter check always applies to charset parameters.
		upperValue := strings.ToUpper(value)
		for _, meta := range sqlMetacharacters {
			if strings.Contains(upperValue, strings.ToUpper(meta)) {
				return fmt.Errorf("parameter %q: value contains SQL metacharacter %q", name, meta)
			}
		}
		// Charset pattern check (if declared).
		if s.CharsetPattern != nil && !s.CharsetPattern.MatchString(value) {
			return fmt.Errorf("parameter %q: value does not match allowed character set", name)
		}
		return nil

	default:
		return fmt.Errorf("parameter %q: unknown param type %d", name, s.Type)
	}
}

// BuildQuery substitutes validated parameters into the query template and
// returns the final SQL string for delivery to runQuery via stdin.
//
// BuildQuery must only be called after all parameters have been validated via
// Validate — it performs no validation itself. Callers (the RPC handler's
// admission step) enforce this sequencing contract.
func (e *CatalogEntry) BuildQuery(params map[string]string) string {
	q := e.query
	for k, v := range params {
		q = strings.ReplaceAll(q, "{{"+k+"}}", v)
	}
	return q
}

// catalogRegistry is the fixed, bundle-embedded set of named osquery queries.
// To add a new query: add an entry here, update the bundle, and obtain a new
// publisher signature — the same governance path as any other module capability
// change.
//
// The closed set documented here ships with pinnedVersion (5.13.1). host_info,
// process_list, listening_ports, and file_info query cross-platform osquery
// tables present since v4.x. installed_packages queries Linux-only tables
// (deb_packages, rpm_packages) and must only be dispatched to Linux stewards.
var catalogRegistry = map[string]*CatalogEntry{
	// host_info: point-in-time OS and hardware identity facts. No parameters.
	// Used by the controller to refresh host:os and host:bios DNA fragments
	// without waiting for the next convergence cycle.
	"host_info": {
		ID:    "host_info",
		query: "SELECT hostname, os_name, platform, platform_like, version, build, kernel_version, arch FROM os_version LIMIT 1",
	},

	// process_list: running processes visible to osquery. Requires a name_prefix
	// enum parameter to limit output to a declared set of process name prefixes.
	// The caller must always supply name_prefix; callers that need all processes
	// should use separate catalog entries per prefix.
	"process_list": {
		ID: "process_list",
		query: "SELECT pid, name, path, cmdline, uid, state, resident_size " +
			"FROM processes WHERE name LIKE '{{name_prefix}}%' ORDER BY name LIMIT 500",
		Params: map[string]ParamSchema{
			"name_prefix": {
				Type: ParamTypeEnum,
				AllowedValues: []string{
					"cfgms",
					"osquery",
					"steward",
					"controller",
				},
			},
		},
	},

	// listening_ports: network ports currently open for inbound connections.
	// Requires a protocol_num enum parameter: "6" for TCP, "17" for UDP.
	// The caller must always supply protocol_num; osquery stores protocol as an
	// IANA protocol number (RFC 790), not a name string.
	"listening_ports": {
		ID: "listening_ports",
		query: "SELECT pid, port, protocol, family, address, net_namespace " +
			"FROM listening_ports WHERE protocol = {{protocol_num}} ORDER BY port LIMIT 1000",
		Params: map[string]ParamSchema{
			// osquery listening_ports.protocol is numeric: 6=TCP, 17=UDP (RFC 790).
			"protocol_num": {
				Type:          ParamTypeEnum,
				AllowedValues: []string{"6", "17"},
			},
		},
	},

	// installed_packages: installed software packages (Linux only — queries
	// deb_packages and rpm_packages, which are absent on macOS and Windows).
	// Callers must only dispatch this catalog ID to Linux stewards.
	// No parameters; returns all known packages up to the 5000-row limit.
	"installed_packages": {
		ID:    "installed_packages",
		query: "SELECT name, version, source, arch FROM deb_packages UNION SELECT name, version, source, arch FROM rpm_packages ORDER BY name LIMIT 5000",
	},

	// file_info: metadata for a specific absolute file path. The path parameter
	// is charset-restricted to safe filesystem characters; SQL metacharacters are
	// always rejected. Use only for declared monitoring paths, not user-supplied.
	"file_info": {
		ID: "file_info",
		// path is a parameter declared in the WHERE clause, not appended to the
		// query string via concatenation — the substituted value is the predicate.
		query: "SELECT path, filename, size, type, mode, uid, gid, mtime, sha256 FROM file WHERE path = '{{path}}' LIMIT 1",
		Params: map[string]ParamSchema{
			"path": {
				Type: ParamTypeCharset,
				// Absolute POSIX/Windows paths: slash, backslash, colon, dot,
				// dash, alphanumeric, underscore. No quotes, semicolons, or spaces.
				CharsetPattern: regexp.MustCompile(`^[a-zA-Z0-9/_\\.:\-]+$`),
			},
		},
	},
}

// LookupCatalogEntry returns the CatalogEntry for the given id, or an error
// if the id is not registered. This is the first gate in the front-door
// admission check — it must be called before any parameter validation.
func LookupCatalogEntry(id string) (*CatalogEntry, error) {
	entry, ok := catalogRegistry[id]
	if !ok {
		return nil, fmt.Errorf("catalog: unknown query id %q", id)
	}
	return entry, nil
}

// ValidateParams checks that every key in params is declared in entry.Params
// and that every value satisfies its declared schema. It also rejects params
// that are present in the request but not declared in the catalog entry (no
// silent extra parameters). Returns on the first validation failure.
//
// ValidateParams must be called as part of the same admission step as
// LookupCatalogEntry — never after the entry's query text has been accessed.
func ValidateParams(entry *CatalogEntry, params map[string]string) error {
	// Reject undeclared parameters — defense in depth against parameter injection
	// via names not in the schema.
	for name := range params {
		if _, ok := entry.Params[name]; !ok {
			return fmt.Errorf("catalog: parameter %q is not declared for query %q", name, entry.ID)
		}
	}
	// Validate each declared parameter that has a provided value.
	for name, schema := range entry.Params {
		value, provided := params[name]
		if !provided {
			// Missing declared parameter — the template will contain an unreplaced
			// placeholder. Reject to prevent partial substitution.
			return fmt.Errorf("catalog: required parameter %q not provided for query %q", name, entry.ID)
		}
		if err := schema.Validate(name, value); err != nil {
			return err
		}
	}
	return nil
}
