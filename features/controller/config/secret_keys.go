// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// secretKeyKind selects which forms a secret-bearing key accepts.
type secretKeyKind int

const (
	// secretKeyReference accepts only a whole-scalar ${VAR} reference.
	secretKeyReference secretKeyKind = iota
	// secretKeyOptionalReference accepts a ${VAR} reference or an absent key.
	secretKeyOptionalReference
	// secretKeyDSN accepts a whole-value ${VAR}, a DSN whose password component
	// is exactly ${VAR}, or a DSN with no password component.
	secretKeyDSN
)

// secretKeySpec names one secret-bearing controller config key.
type secretKeySpec struct {
	Path []string
	Kind secretKeyKind
}

// SecretBearingKeys is the single definition of the controller config keys that
// carry secrets and so must never hold a literal value on disk (Issue #4664).
// LoadWithPath iterates it against the raw file before ${VAR} expansion.
var SecretBearingKeys = []secretKeySpec{
	{[]string{"storage", "cluster", "session_hmac_key"}, secretKeyReference},
	{[]string{"storage", "cluster", "s3", "access_key_id"}, secretKeyOptionalReference},
	{[]string{"storage", "cluster", "s3", "secret_access_key"}, secretKeyOptionalReference},
	{[]string{"audit", "worm", "access_key_id"}, secretKeyOptionalReference},
	{[]string{"audit", "worm", "secret_access_key"}, secretKeyOptionalReference},
	{[]string{"storage", "config", "password"}, secretKeyOptionalReference},
	{[]string{"storage", "cluster", "postgres_dsn"}, secretKeyDSN},
	{[]string{"storage", "config", "dsn"}, secretKeyDSN},
}

var wholeVarRef = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

func (k secretKeySpec) pathString() string { return strings.Join(k.Path, ".") }

func (k secretKeySpec) acceptedForms() string {
	switch k.Kind {
	case secretKeyOptionalReference:
		return "a ${VAR} reference or an absent key"
	case secretKeyDSN:
		return "a ${VAR} reference, a DSN whose password is a ${VAR} reference, or a DSN without a password"
	default:
		return "a ${VAR} reference"
	}
}

// validateNoLiteralSecrets parses the raw (unexpanded) config content and
// refuses a literal in any secret-bearing key. The error names the key and the
// accepted forms and never contains the value. Content that is not valid YAML
// is left to the normal parse step to report.
func validateNoLiteralSecrets(content string) error {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := resolveAlias(doc.Content[0])
	for _, spec := range SecretBearingKeys {
		node := lookupPath(root, spec.Path)
		if node == nil {
			continue
		}
		if !secretNodeAcceptable(node, spec.Kind) {
			return fmt.Errorf("literal secret refused in %s: accepted forms are %s (a literal would leave a cleartext secret on disk; %s is not accepted)",
				spec.pathString(), spec.acceptedForms(), "${VAR:-default}")
		}
	}
	return nil
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for depth := 0; n != nil && n.Kind == yaml.AliasNode && depth < 32; depth++ {
		n = n.Alias
	}
	return n
}

// lookupPath walks mapping keys, resolving aliases and YAML merge keys.
func lookupPath(n *yaml.Node, path []string) *yaml.Node {
	for _, key := range path {
		n = mappingValue(resolveAlias(n), key, 0)
		if n == nil {
			return nil
		}
	}
	return resolveAlias(n)
}

func mappingValue(m *yaml.Node, key string, depth int) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode || depth > 8 {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i].Tag != "!!merge" {
			return m.Content[i+1]
		}
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Tag != "!!merge" {
			continue
		}
		src := resolveAlias(m.Content[i+1])
		if src != nil && src.Kind == yaml.SequenceNode {
			for _, item := range src.Content {
				if v := mappingValue(resolveAlias(item), key, depth+1); v != nil {
					return v
				}
			}
		} else if v := mappingValue(src, key, depth+1); v != nil {
			return v
		}
	}
	return nil
}

func secretNodeAcceptable(n *yaml.Node, kind secretKeyKind) bool {
	if n.Kind != yaml.ScalarNode {
		return false // a map or list cannot be a reference
	}
	if n.Tag == "!!null" || n.Value == "" {
		return true // carries no secret
	}
	if wholeVarRef.MatchString(n.Value) {
		return true
	}
	if kind == secretKeyDSN {
		return dsnPasswordAcceptable(n.Value)
	}
	return false
}

// dsnPasswordAcceptable reports whether the DSN's password component is absent
// or exactly a ${VAR} reference.
func dsnPasswordAcceptable(dsn string) bool {
	trimmed := strings.TrimSpace(dsn)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return uriPasswordsAcceptable(trimmed)
	}
	return keywordPasswordAcceptable(trimmed)
}

func passwordValueOK(v string) bool { return v == "" || wholeVarRef.MatchString(v) }

// uriPasswordsAcceptable checks the userinfo password and any password= query
// parameter of a postgres:// URI. It parses by hand because ${VAR} is not a
// legal userinfo character for net/url.
func uriPasswordsAcceptable(uri string) bool {
	rest := uri[strings.Index(uri, "://")+3:]
	query := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		userinfo := rest[:at]
		if c := strings.IndexByte(userinfo, ':'); c >= 0 && !passwordValueOK(userinfo[c+1:]) {
			return false
		}
	}
	for _, pair := range strings.Split(query, "&") {
		if k, v, ok := strings.Cut(pair, "="); ok && strings.EqualFold(k, "password") && !passwordValueOK(v) {
			return false
		}
	}
	return true
}

// keywordPasswordAcceptable scans a libpq keyword/value string. A string that
// cannot be tokenised is refused (fail closed).
func keywordPasswordAcceptable(s string) bool {
	i, n := 0, len(s)
	for {
		for i < n && isDSNSpace(s[i]) {
			i++
		}
		if i >= n {
			return true
		}
		start := i
		for i < n && s[i] != '=' && !isDSNSpace(s[i]) {
			i++
		}
		key := s[start:i]
		for i < n && isDSNSpace(s[i]) {
			i++
		}
		if i >= n || s[i] != '=' || key == "" {
			return false
		}
		i++
		for i < n && isDSNSpace(s[i]) {
			i++
		}
		var val strings.Builder
		if i < n && s[i] == '\'' {
			i++
			closed := false
			for i < n {
				if s[i] == '\\' && i+1 < n {
					val.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '\'' {
					i++
					closed = true
					break
				}
				val.WriteByte(s[i])
				i++
			}
			if !closed {
				return false
			}
		} else {
			for i < n && !isDSNSpace(s[i]) {
				if s[i] == '\\' && i+1 < n {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
		}
		if strings.EqualFold(key, "password") && !passwordValueOK(val.String()) {
			return false
		}
	}
}

func isDSNSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
