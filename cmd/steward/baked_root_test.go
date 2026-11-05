// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setBaked(t *testing.T, v string) {
	t.Helper()
	old := ControllerRootFingerprints
	ControllerRootFingerprints = v
	t.Cleanup(func() { ControllerRootFingerprints = old })
}

func fpOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func makeCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c, key
}

func TestBakedRootFingerprints_Parsing(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("0123456789abcdef", 4)

	setBaked(t, "")
	_, err := bakedRootFingerprints()
	assert.ErrorIs(t, err, errNoBakedRoot)

	bad := map[string]string{
		"short":     strings.Repeat("a", 63),
		"long":      strings.Repeat("a", 65),
		"non-hex":   strings.Repeat("g", 64),
		"uppercase": strings.Repeat("A", 64),
		"colons":    strings.Repeat("aa:", 21) + "a",
		"too many":  strings.Join([]string{a, a, a, a, a}, ","),
		"empty ent": a + ",",
		"space":     a + ", " + b,
	}
	for name, v := range bad {
		t.Run(name, func(t *testing.T) {
			setBaked(t, v)
			_, err := bakedRootFingerprints()
			assert.ErrorIs(t, err, errBakedRootMalformed)
		})
	}

	setBaked(t, a+","+b)
	got, err := bakedRootFingerprints()
	require.NoError(t, err)
	assert.Equal(t, []string{a, b}, got)

	setBaked(t, strings.Join([]string{a, a, a, a}, ","))
	got, err = bakedRootFingerprints()
	require.NoError(t, err)
	assert.Len(t, got, 4)
}

func TestMatchesBakedRoot(t *testing.T) {
	root1, rootKey := makeCert(t, "root-1", true, nil, nil)
	root2, _ := makeCert(t, "root-2", true, nil, nil)
	other, _ := makeCert(t, "other", true, nil, nil)
	leaf, _ := makeCert(t, "leaf", false, root1, rootKey)
	inter, _ := makeCert(t, "inter", true, root1, rootKey)
	selfLeaf, _ := makeCert(t, "self-leaf", false, nil, nil)

	setBaked(t, fpOf(root1)+","+fpOf(root2))
	assert.True(t, matchesBakedRoot(root1), "first entry")
	assert.True(t, matchesBakedRoot(root2), "second entry")
	assert.False(t, matchesBakedRoot(other), "different CA")
	assert.False(t, matchesBakedRoot(nil))

	// Non-CA and intermediate certificates are rejected even when listed.
	setBaked(t, fpOf(selfLeaf)+","+fpOf(inter)+","+fpOf(leaf))
	assert.False(t, matchesBakedRoot(selfLeaf), "non-CA with listed fingerprint")
	assert.False(t, matchesBakedRoot(inter), "intermediate with listed fingerprint")
	assert.False(t, matchesBakedRoot(leaf))

	// One-bit-different fingerprint.
	raw, err := hex.DecodeString(fpOf(root1))
	require.NoError(t, err)
	raw[0] ^= 0x01
	setBaked(t, hex.EncodeToString(raw))
	assert.False(t, matchesBakedRoot(root1))

	// Malformed or empty baked value fails closed.
	setBaked(t, strings.ToUpper(fpOf(root1)))
	assert.False(t, matchesBakedRoot(root1))
	setBaked(t, "")
	assert.False(t, matchesBakedRoot(root1))
}

// TestBakedRootSourceReadsNothingExternal statically verifies baked_root.go
// has no environment, flag, config or file access.
func TestBakedRootSourceReadsNothingExternal(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "baked_root.go", nil, 0)
	require.NoError(t, err)

	banned := map[string]bool{"os": true, "flag": true, "io/ioutil": true, "io/fs": true,
		"bufio": true, "net/http": true, "syscall": true, "path/filepath": true, "encoding/json": true}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		require.NoError(t, err)
		assert.Falsef(t, banned[p], "baked_root.go must not import %s", p)
		assert.Falsef(t, strings.Contains(p, "config") || strings.Contains(p, "viper"), "baked_root.go must not import %s", p)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				assert.NotContainsf(t, []string{"os", "flag", "ioutil", "viper"}, id.Name, "unexpected use of %s.%s", id.Name, sel.Sel.Name)
			}
		}
		return true
	})
}

func buildStewardForStatus(t *testing.T, ldflags string) string {
	t.Helper()
	name := "steward-under-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	args := []string{"build", "-o", bin}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build: %s", out)
	return bin
}

func statusRootLine(t *testing.T, bin string) string {
	t.Helper()
	cmd := exec.Command(bin, "status")
	cmd.Env = []string{} // empty environment
	if runtime.GOOS == "windows" {
		// Windows processes cannot start without SystemRoot; it carries no baked-root input.
		cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot")}
	}
	out, runErr := cmd.CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "Root CA:") {
			return strings.TrimSpace(strings.SplitN(l, "Root CA:", 2)[1])
		}
	}
	t.Fatalf("no Root CA line in status output: %s (run error: %v)", out, runErr)
	return ""
}

func TestStatusPrintsBakedRootFingerprints(t *testing.T) {
	a := strings.Repeat("ab", 32)
	b := strings.Repeat("01", 32)

	stamped := buildStewardForStatus(t, "-X main.ControllerRootFingerprints="+a+","+b)
	assert.Equal(t, a+","+b, statusRootLine(t, stamped))

	plain := buildStewardForStatus(t, "")
	assert.Equal(t, "none", statusRootLine(t, plain))

	malformed := buildStewardForStatus(t, "-X main.ControllerRootFingerprints=NOTHEX")
	assert.Equal(t, "none", statusRootLine(t, malformed))
}
