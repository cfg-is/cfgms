// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package selector

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/controller/fleet"
)

// Parse converts a filter expression string into a fleet.Filter.
// The second return value is the normalized tenant path if the expression
// carried a leading <tenant-path><sep> prefix; it is empty when no prefix
// was present. The caller is responsible for enforcing the authz boundary
// between the parsed tenant path and the authenticated principal's scope.
//
// Tenant prefix: an optional leading "<path><sep>" where sep is '/' or '\'
// (both accepted and normalized to '/'). The path may have multiple segments
// separated by '/' or '\'. Example: "msp-a/client-1/name:web*" parses to
// tenant path "msp-a/client-1" and selector "name:web*".
//
// The expression is a space-separated list of key:value terms. Values may be
// double-quoted to include spaces. Supported keys:
//
//	id:<steward-id>    — exact steward ID match; comma-separated for OR (id:a,b)
//	name:<hostname>    — hostname match; trailing * enables prefix-glob
//	os:<value>         — exact OS match
//	platform:<value>   — exact platform match
//	arch:<value>       — exact architecture match
//	tag:<value>        — tag must be present (repeatable)
//	dna.<key>:<value>  — arbitrary DNA attribute exact match (repeatable)
//
// The special keyword "all" matches all stewards. An empty expression is
// rejected — fail-closed so a fat-fingered command cannot fan out fleet-wide.
// Unknown keys are parse errors.
func Parse(expr string) (fleet.Filter, string, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fleet.Filter{}, "", fmt.Errorf("empty selector: use 'all' to match all stewards")
	}

	tenantPath, rest := extractTenantPrefix(expr)
	rest = strings.TrimSpace(rest)

	if rest == "" {
		return fleet.Filter{}, tenantPath, fmt.Errorf("empty selector: use 'all' to match all stewards")
	}
	if rest == "all" {
		return fleet.Filter{}, tenantPath, nil
	}

	terms, err := tokenize(rest)
	if err != nil {
		return fleet.Filter{}, tenantPath, err
	}

	var f fleet.Filter
	for _, t := range terms {
		if err := applyTerm(&f, t); err != nil {
			return fleet.Filter{}, tenantPath, err
		}
	}
	return f, tenantPath, nil
}

// extractTenantPrefix detects and strips a leading <tenant-path><sep> prefix
// from expr, where sep is '/' or '\'. Returns the normalized tenant path (with
// '/' separators) and the remaining selector expression. The tenant path is the
// rightmost prefix such that everything to the left of the final separator
// contains no ':' and no whitespace (valid path segments only). If no such
// prefix exists, returns ("", expr).
func extractTenantPrefix(expr string) (tenantPath, rest string) {
	splitAt := -1
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if ch == '/' || ch == '\\' {
			left := expr[:i]
			if left != "" && !strings.ContainsAny(left, ": \t") {
				splitAt = i
			}
		}
	}
	if splitAt < 0 {
		return "", expr
	}
	raw := expr[:splitAt]
	normalized := strings.ReplaceAll(raw, "\\", "/")
	return normalized, expr[splitAt+1:]
}

type term struct {
	key   string
	value string
}

// tokenize splits the expression into key:value pairs. The first colon in each
// token is the key separator; unquoted values extend to the next space;
// double-quoted values may contain spaces. A token with no colon before its
// next space (or end of string) is a bare token and maps to an implicit
// name:<value> term, enabling bare hostname targeting without a key prefix.
func tokenize(expr string) ([]term, error) {
	var terms []term
	i := 0
	for i < len(expr) {
		// Skip whitespace between terms.
		for i < len(expr) && expr[i] == ' ' {
			i++
		}
		if i >= len(expr) {
			break
		}

		rest := expr[i:]
		colonRel := strings.IndexByte(rest, ':')
		spaceRel := strings.IndexByte(rest, ' ')

		// Bare token: no colon found, or colon appears after the next space.
		// The whole token becomes an implicit name: value.
		if colonRel < 0 || (spaceRel >= 0 && spaceRel < colonRel) {
			end := len(expr)
			if spaceRel >= 0 {
				end = i + spaceRel
			}
			terms = append(terms, term{key: "name", value: expr[i:end]})
			i = end
			continue
		}

		// key:value term — colon appears before the next space.
		colonIdx := i + colonRel
		key := expr[i:colonIdx]
		if key == "" {
			return nil, fmt.Errorf("empty key in selector near position %d", i)
		}
		if strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("invalid selector key %q: keys must not contain spaces", key)
		}

		i = colonIdx + 1 // advance past the colon

		// Parse the value — quoted or unquoted.
		var value string
		if i < len(expr) && expr[i] == '"' {
			i++ // skip opening quote
			start := i
			for i < len(expr) && expr[i] != '"' {
				i++
			}
			if i >= len(expr) {
				return nil, fmt.Errorf("unterminated quoted value for key %q", key)
			}
			value = expr[start:i]
			i++ // skip closing quote
		} else {
			start := i
			for i < len(expr) && expr[i] != ' ' {
				i++
			}
			value = expr[start:i]
		}

		if value == "" {
			return nil, fmt.Errorf("empty value for key %q", key)
		}

		terms = append(terms, term{key: key, value: value})
	}

	return terms, nil
}

// applyTerm merges a parsed key:value term into the filter.
func applyTerm(f *fleet.Filter, t term) error {
	switch {
	case t.key == "id":
		f.IDs = append(f.IDs, strings.Split(t.value, ",")...)
	case t.key == "name":
		f.Name = t.value
	case t.key == "os":
		f.OS = t.value
	case t.key == "platform":
		f.Platform = t.value
	case t.key == "arch":
		f.Architecture = t.value
	case t.key == "tag":
		f.Tags = append(f.Tags, t.value)
	case strings.HasPrefix(t.key, "dna."):
		attr := strings.TrimPrefix(t.key, "dna.")
		if attr == "" {
			return fmt.Errorf("empty DNA attribute key in selector (write dna.<key>:value)")
		}
		if f.DNAAttributes == nil {
			f.DNAAttributes = make(map[string]string)
		}
		f.DNAAttributes[attr] = t.value
	default:
		return fmt.Errorf("unknown selector key %q: valid keys are id, name, os, platform, arch, tag, dna.<key>", t.key)
	}
	return nil
}
