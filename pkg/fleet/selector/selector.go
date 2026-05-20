// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package selector

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/controller/fleet"
)

// Parse converts a filter expression string into a fleet.Filter.
//
// The expression is a space-separated list of key:value terms. Values may be
// double-quoted to include spaces. Supported keys:
//
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
func Parse(expr string) (fleet.Filter, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fleet.Filter{}, fmt.Errorf("empty selector: use 'all' to match all stewards")
	}
	if expr == "all" {
		return fleet.Filter{}, nil
	}

	terms, err := tokenize(expr)
	if err != nil {
		return fleet.Filter{}, err
	}

	var f fleet.Filter
	for _, t := range terms {
		if err := applyTerm(&f, t); err != nil {
			return fleet.Filter{}, err
		}
	}
	return f, nil
}

type term struct {
	key   string
	value string
}

// tokenize splits the expression into key:value pairs. The first colon in each
// token is the key separator; unquoted values extend to the next space;
// double-quoted values may contain spaces.
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

		// Find the colon separating key from value.
		rest := expr[i:]
		colonRel := strings.IndexByte(rest, ':')
		if colonRel < 0 {
			return nil, fmt.Errorf("invalid selector term %q: expected key:value format", rest)
		}
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
	case t.key == "name":
		f.Hostname = t.value
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
		return fmt.Errorf("unknown selector key %q: valid keys are name, os, platform, arch, tag, dna.<key>", t.key)
	}
	return nil
}
