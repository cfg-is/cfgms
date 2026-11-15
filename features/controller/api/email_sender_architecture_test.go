// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emailSenderAllowedFiles are the only non-test files in this package that may
// touch the controller-wide notifier directly: the resolver (the one accessor)
// and handlers_notifications.go (which builds, initialises and rebuilds it).
// The Server struct field declaration in server.go is not a selector expression,
// so it needs no entry.
var emailSenderAllowedFiles = map[string]bool{
	"email_sender_resolver.go":  true,
	"handlers_notifications.go": true,
}

// checkEmailSenderAccess parses one source file and returns "file:line" for every
// use of platformEmailNotifier (called or taken as a method value) and every
// selector of the emailNotifier field, outside the allow-list. A send path must
// obtain its notifier from resolveEmailSender with an explicit rule.
func checkEmailSenderAccess(path string, src []byte) []string {
	if emailSenderAllowedFiles[filepath.Base(path)] {
		return nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{fmt.Sprintf("%s: does not parse: %v", filepath.ToSlash(path), err)}
	}
	var findings []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "platformEmailNotifier", "emailNotifier":
			findings = append(findings, fmt.Sprintf("%s:%d uses %s", filepath.ToSlash(path), fset.Position(sel.Pos()).Line, sel.Sel.Name))
		}
		return true
	})
	return findings
}

func TestEmailSenderArchitecture_RealPackageHasNoFindings(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		checked++
		assert.Empty(t, checkEmailSenderAccess(name, src), "%s must obtain its notifier through resolveEmailSender", name)
	}
	assert.Greater(t, checked, 10, "the walk must actually see the package's source files")
}

func TestEmailSenderArchitecture_DetectsViolations(t *testing.T) {
	t.Run("calling platformEmailNotifier from a handler", func(t *testing.T) {
		src := []byte(`package api
func (s *Server) handleSomething() {
	n := s.platformEmailNotifier()
	_ = n
}
`)
		assert.NotEmpty(t, checkEmailSenderAccess("handlers_something.go", src))
	})
	t.Run("reading the emailNotifier field from a handler", func(t *testing.T) {
		src := []byte(`package api
func (s *Server) handleSomething() {
	s.emailMu.RLock()
	n := s.emailNotifier
	s.emailMu.RUnlock()
	_ = n
}
`)
		findings := checkEmailSenderAccess("handlers_something.go", src)
		require.Len(t, findings, 1)
		assert.Contains(t, findings[0], "handlers_something.go:4")
	})
	t.Run("taking platformEmailNotifier as a method value", func(t *testing.T) {
		src := []byte(`package api
func (s *Server) handleSomething() {
	f := s.platformEmailNotifier
	_ = f
}
`)
		assert.NotEmpty(t, checkEmailSenderAccess("handlers_something.go", src))
	})
	t.Run("the resolver and the owner of build/init/rebuild are allowed", func(t *testing.T) {
		src := []byte(`package api
func (s *Server) f() { _ = s.platformEmailNotifier(); s.emailNotifier = nil }
`)
		assert.Empty(t, checkEmailSenderAccess("email_sender_resolver.go", src))
		assert.Empty(t, checkEmailSenderAccess("handlers_notifications.go", src))
	})
	t.Run("a struct field declaration is not a use", func(t *testing.T) {
		src := []byte(`package api
type Server struct {
	emailNotifier Notifier
}
`)
		assert.Empty(t, checkEmailSenderAccess("server.go", src))
	})
	t.Run("resolveEmailSender is the sanctioned route", func(t *testing.T) {
		src := []byte(`package api
func (s *Server) handleSomething() {
	n, src := s.resolveEmailSender(ctx, emailRulePlatformOnly, "")
	_, _ = n, src
}
`)
		assert.Empty(t, checkEmailSenderAccess("handlers_something.go", src))
	})
}
