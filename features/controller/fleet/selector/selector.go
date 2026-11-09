// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package selector

import (
	"fmt"
	"regexp"
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

// stewardIDPattern matches both generated steward ID formats:
// steward-<32 hex> and steward-<unixnano>-<16 hex>. It is applied only to bare
// tokens so `cfg steward list` output can be pasted into any selector.
var stewardIDPattern = regexp.MustCompile(`^steward-[0-9a-f]+(-[0-9a-f]+)?$`)

type term struct {
	key   string
	value string
}

// tokenize splits the expression into key:value pairs. The first colon in each
// token is the key separator; unquoted values extend to the next space;
// double-quoted values may contain spaces. A token with no colon before its
// next space (or end of string) is a bare token and maps to an implicit
// name:<value> term, enabling bare hostname targeting without a key prefix.
// A bare token shaped like a steward ID is an id:<value> term instead; use
// name:<value> to force a hostname match.
func tokenize(expr string) ([]term, error) {
	var terms []term
	i := 0
	for i < len(expr) {
		i = skipSpaces(expr, i)
		if i >= len(expr) {
			break
		}

		t, next, err := nextTerm(expr, i)
		if err != nil {
			return nil, err
		}
		terms = append(terms, t)
		i = next
	}

	return terms, nil
}

// skipSpaces returns the index of the first non-space byte at or after i.
func skipSpaces(expr string, i int) int {
	for i < len(expr) && expr[i] == ' ' {
		i++
	}
	return i
}

// nextTerm parses the single term starting at expr[i] (which is not a space)
// and returns it with the index just past it.
func nextTerm(expr string, i int) (term, int, error) {
	rest := expr[i:]
	colonRel := strings.IndexByte(rest, ':')
	spaceRel := strings.IndexByte(rest, ' ')

	// Bare token: no colon found, or colon appears after the next space.
	// The whole token becomes an implicit name: value.
	if colonRel < 0 || (spaceRel >= 0 && spaceRel < colonRel) {
		return bareTerm(expr, i, spaceRel)
	}

	// key:value term — colon appears before the next space.
	return keyValueTerm(expr, i, i+colonRel)
}

// bareTerm parses a bare token starting at expr[i] as an implicit name or id
// term. spaceRel is the offset of the next space relative to i, or -1.
func bareTerm(expr string, i, spaceRel int) (term, int, error) {
	end := len(expr)
	if spaceRel >= 0 {
		end = i + spaceRel
	}
	tok := expr[i:end]
	key := "name"
	if stewardIDPattern.MatchString(tok) {
		key = "id"
	}
	return term{key: key, value: tok}, end, nil
}

// keyValueTerm parses a key:value term whose key starts at expr[i] and whose
// colon is at expr[colonIdx].
func keyValueTerm(expr string, i, colonIdx int) (term, int, error) {
	key := expr[i:colonIdx]
	if key == "" {
		return term{}, 0, fmt.Errorf("empty key in selector near position %d", i)
	}
	if strings.ContainsAny(key, " \t") {
		return term{}, 0, fmt.Errorf("invalid selector key %q: keys must not contain spaces", key)
	}

	value, next, err := scanValue(expr, colonIdx+1, key)
	if err != nil {
		return term{}, 0, err
	}
	if value == "" {
		return term{}, 0, fmt.Errorf("empty value for key %q", key)
	}
	return term{key: key, value: value}, next, nil
}

// scanValue reads a quoted or unquoted value starting at expr[i] and returns
// it with the index just past it. key is used only for error messages.
func scanValue(expr string, i int, key string) (string, int, error) {
	if i < len(expr) && expr[i] == '"' {
		i++ // skip opening quote
		start := i
		for i < len(expr) && expr[i] != '"' {
			i++
		}
		if i >= len(expr) {
			return "", 0, fmt.Errorf("unterminated quoted value for key %q", key)
		}
		return expr[start:i], i + 1, nil // skip closing quote
	}

	start := i
	for i < len(expr) && expr[i] != ' ' {
		i++
	}
	return expr[start:i], i, nil
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
