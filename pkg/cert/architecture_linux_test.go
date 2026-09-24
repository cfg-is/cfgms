//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetAdminMarker_Architecture enforces the restricted-caller rule for SetAdminMarker.
// Any production file outside the allow-list that calls cert.SetAdminMarker fails this test.
// Test files (_test.go) are excluded — they are test infrastructure, not production code paths.
func TestSetAdminMarker_Architecture(t *testing.T) {
	allowList := map[string]bool{
		// Story B: admin cert issuance during controller initialization
		"features/controller/initialization/initialization.go": true,
		// Story D: admin bundle packaging
		"features/controller/initialization/admin_bundle.go": true,
		// Issue #3719: credential-request collect signs the marker set recorded at
		// approval (#3718), which may include the admin marker.
		"features/controller/api/handlers_credential_requests_collect.go": true,
	}

	repoRoot := findRepoRoot(t)

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip agent dispatch worktrees — they contain nested repo copies
			// from /dispatch agents and are not part of this checkout's source.
			// Skip the in-tree module cache — GOMODCACHE is set to .cache/go-mod
			// inside the working tree, and third-party code there is not first-party.
			if d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path) // #nosec G304 -- repo scan reads controlled source files
		if err != nil {
			return nil
		}
		if bytes.Contains(content, []byte("cert.SetAdminMarker")) {
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if !allowList[rel] {
				violations = append(violations, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, violations,
		"unauthorized production callers of cert.SetAdminMarker; "+
			"add to allow-list or move to an allowed file: %v", violations)
}

// TestSetRootScopeMarker_Architecture enforces the restricted-caller rule for
// SetRootScopeMarker (ADR-025 Amendment 1 A1.3, founder decision 2026-08-09, PR #3215).
// Any production file outside the allow-list that calls cert.SetRootScopeMarker fails
// this test. Test files (_test.go) are excluded — they are test infrastructure, not
// production code paths.
//
// The risk this guards is INVERTED relative to TestSetAdminMarker_Architecture above.
// SetAdminMarker grants privilege, so an unauthorized caller is a privilege-escalation
// risk. SetRootScopeMarker instead RESTRICTS privilege: a marked cert becomes subject to
// ADR-025 Decision 1's root<->MSP boundary, denied every strict descendant of "root"
// without an active grant or break-glass crossing. So the hazard an unauthorized caller
// represents here is not escalation but accidental stamping — an operator issuing what
// they believe is an ordinary unrestricted admin bundle instead silently locking
// themselves out below "root". Conversely, the security property this marker exists to
// provide (a SaaS operator's credential reliably identifiable as root-scoped) depends on
// issuance being deliberate and auditable, not incidental — which is exactly what a
// closed allow-list plus IssueAdminBundle's audit-on-issue (admin_bundle.go) gives it.
//
// Deliberately does NOT allow-list initialization.go: the first-boot / --regenerate
// system admin bundle (issueAdminBundle, initialization.go) must never carry this marker
// — see that function's doc comment for why (it is the deployment's only admin
// credential on single-root/on-prem installs; marking it would be a lockout).
func TestSetRootScopeMarker_Architecture(t *testing.T) {
	allowList := map[string]bool{
		// Founder-directed root-scoped issuance opt-in (bootstrap-admin --root-scoped)
		"features/controller/initialization/admin_bundle.go": true,
		// Issue #3719: credential-request collect signs the marker set recorded at
		// approval (#3718) — the root-scope marker is only ever in that set because
		// principalHasCertifiedRootScope already required the approver to present
		// their own certified, non-revoked root-scope-marked certificate. Collect
		// enacts that decision verbatim; it performs no root-scope authority check
		// of its own.
		"features/controller/api/handlers_credential_requests_collect.go": true,
	}

	repoRoot := findRepoRoot(t)

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path) // #nosec G304 -- repo scan reads controlled source files
		if err != nil {
			return nil
		}
		if bytes.Contains(content, []byte("cert.SetRootScopeMarker")) {
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if !allowList[rel] {
				violations = append(violations, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, violations,
		"unauthorized production callers of cert.SetRootScopeMarker; "+
			"add to allow-list or move to an allowed file: %v", violations)
}

// TestSetPayloadSigningMarker_Architecture enforces the restricted-caller rule for
// SetPayloadSigningMarker. Any production file outside the allow-list that calls
// cert.SetPayloadSigningMarker fails this test. Test files (_test.go) are excluded —
// they are test infrastructure, not production code paths.
//
// The allow-list is currently empty: this story (#3692) adds the primitive without
// wiring in a caller — Story S10's CSR issuance handler is the intended sole
// production caller and must add itself here when it lands.
func TestSetPayloadSigningMarker_Architecture(t *testing.T) {
	allowList := map[string]bool{
		// Issue #3693: CSR-based payload-signing certificate issuance handler —
		// the sole production caller of cert.SetPayloadSigningMarker.
		"features/controller/api/handlers_signing_credential.go": true,
		// Issue #3719: credential-request collect signs the marker set recorded at
		// approval (#3718), which may include the payload-signing marker.
		"features/controller/api/handlers_credential_requests_collect.go": true,
	}

	repoRoot := findRepoRoot(t)

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, err := os.ReadFile(path) // #nosec G304 -- repo scan reads controlled source files
		if err != nil {
			return nil
		}
		if bytes.Contains(content, []byte("cert.SetPayloadSigningMarker")) {
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if !allowList[rel] {
				violations = append(violations, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, violations,
		"unauthorized production callers of cert.SetPayloadSigningMarker; "+
			"add to allow-list or move to an allowed file: %v", violations)
}

// findRepoRoot walks up from the working directory to find the repository root (go.mod presence).
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod not found)")
		}
		dir = parent
	}
}

// TestNoGetCertificatesByTypeOutsideCertPackage enforces that GetCertificatesByType
// is never called outside pkg/cert. The method is package-private on FileStore and
// removed from Manager's public API. Callers outside pkg/cert must use
// GetCurrentCertForPurpose or GetAllValidCertificatesForPurpose instead.
func TestNoGetCertificatesByTypeOutsideCertPackage(t *testing.T) {
	repoRoot := findRepoRoot(t)
	certPkgPath := filepath.Join(repoRoot, "pkg", "cert")

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// pkg/cert internals use the private getCertificatesByType — skip the whole directory
		if rel, relErr := filepath.Rel(certPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "GetCertificatesByType" {
				pos := fset.Position(sel.Pos())
				rel, relErr := filepath.Rel(repoRoot, pos.Filename)
				if relErr != nil {
					rel = pos.Filename
				}
				violations = append(violations, fmt.Sprintf("%s:%d", filepath.ToSlash(rel), pos.Line))
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, violations,
		"external callers of GetCertificatesByType found outside pkg/cert; "+
			"use GetCurrentCertForPurpose or GetAllValidCertificatesForPurpose: %v", violations)
}

// TestNoCertSliceIndex0InNonTest enforces that cert-collection variables are never
// blindly indexed at position 0 outside pkg/cert. Selecting [0] from a cert slice
// races with rotation: the newest cert may be invalid during a rotation overlap
// window. Use GetCurrentCertForPurpose instead to get a single valid certificate.
func TestNoCertSliceIndex0InNonTest(t *testing.T) {
	repoRoot := findRepoRoot(t)
	certPkgPath := filepath.Join(repoRoot, "pkg", "cert")

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// pkg/cert internals are exempt (e.g., clientCerts[0] in GetClientCertificate)
		if rel, relErr := filepath.Rel(certPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			indexExpr, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			lit, isLit := indexExpr.Index.(*ast.BasicLit)
			if !isLit || lit.Kind != token.INT || lit.Value != "0" {
				return true
			}
			ident, isIdent := indexExpr.X.(*ast.Ident)
			if !isIdent {
				return true
			}
			name := ident.Name
			if strings.Contains(name, "Certs") || strings.Contains(name, "certs") ||
				strings.Contains(name, "Certificates") || strings.Contains(name, "certificates") {
				pos := fset.Position(indexExpr.Pos())
				rel, relErr := filepath.Rel(repoRoot, pos.Filename)
				if relErr != nil {
					rel = pos.Filename
				}
				violations = append(violations, fmt.Sprintf("%s:%d (%s[0])", filepath.ToSlash(rel), pos.Line, name))
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, violations,
		"cert-slice [0] indexing found outside pkg/cert; "+
			"use GetCurrentCertForPurpose for single-cert access: %v", violations)
}
