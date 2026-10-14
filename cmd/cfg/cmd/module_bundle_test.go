// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cmd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// runCfg invokes the cobra root with args and stdin, resetting the package-level flag
// state first so tests do not leak into each other.
func runCfg(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	bundleBuildManifest, bundleBuildOut, bundleBuildSeedStdin, pubkeySeedStdin = "", "", false, false
	bundleBuildBinaries = nil
	moduleBundleBuildCmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
	modulePubkeyCmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetIn(nil)
	return out.String(), err
}

func writeManifest(t *testing.T, dir, publisher, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, "module.yaml")
	body := "name: " + name + "\nversion: \"" + version + "\"\npublisher: " + publisher + "\nexecutors: [steward]\n"
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func writeBin(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

var kvRE = func(key string) *regexp.Regexp { return regexp.MustCompile(`(?m)^` + key + `: (\S+)$`) }

func field(t *testing.T, out, key string) string {
	t.Helper()
	m := kvRE(key).FindStringSubmatch(out)
	require.NotNil(t, m, "missing %q in output %q", key, out)
	return m[1]
}

func keygen(t *testing.T) (seed, pub, fp string) {
	t.Helper()
	out, err := runCfg(t, "", "module", "keygen")
	require.NoError(t, err)
	return field(t, out, "seed"), field(t, out, "public key"), field(t, out, "fingerprint")
}

func TestModuleKeygenPubkeyRoundTrip(t *testing.T) {
	seed, pub, fp := keygen(t)

	t.Setenv(publisherSeedEnv, "")
	out, err := runCfg(t, seed+"\n", "module", "pubkey", "--seed-stdin")
	require.NoError(t, err)
	assert.Equal(t, pub, field(t, out, "public key"))
	assert.Equal(t, fp, field(t, out, "fingerprint"))
	assert.NotContains(t, out, seed)

	t.Setenv(publisherSeedEnv, seed)
	out, err = runCfg(t, "", "module", "pubkey")
	require.NoError(t, err)
	assert.Equal(t, pub, field(t, out, "public key"))
	assert.Equal(t, fp, field(t, out, "fingerprint"))
}

func TestModuleKeygenWritesNothing(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(wd) })
	_, _, _ = keygen(t)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestModuleBundleBuildTwoPlatformsVerifies(t *testing.T) {
	seed, pub, fp := keygen(t)
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "acme-corp", "widget", "1.2.3")
	lin := writeBin(t, dir, "lin", "linux-bytes")
	win := writeBin(t, dir, "win", "windows-bytes")
	root := filepath.Join(dir, "root")

	out, err := runCfg(t, seed, "module", "bundle", "build", "--seed-stdin",
		"--manifest", manifest, "--binary", "linux-amd64="+lin, "--binary", "windows-amd64="+win, "--out", root)
	require.NoError(t, err, out)
	assert.Equal(t, "acme-corp", field(t, out, "publisher"))
	assert.Equal(t, fp, field(t, out, "public key fingerprint"))

	b, err := bundle.ReadInstalledPayload(root, bundle.ReadOptions{})
	require.NoError(t, err)
	assert.Equal(t, field(t, out, "content hash"), b.ContentHash)
	assert.Len(t, b.BinaryDigests, 2)
	assert.Contains(t, b.BinaryDigests, "linux-amd64")
	assert.Contains(t, b.BinaryDigests, "windows-amd64")
	assert.Equal(t, "cfgms-module-widget.exe", b.Binaries["windows-amd64"])

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	require.NoError(t, err)
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{Name: "acme-corp", PublicKey: ed25519.PublicKey(pubBytes), Algorithm: "ed25519"}))
	require.Len(t, b.Signatures, 1)
	require.NoError(t, trust.VerifyBundleSignature(b, b.Signatures[0], store))

	sidecar, err := os.ReadFile(filepath.Join(root, "bundle.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(sidecar), "linux-amd64")
	assert.Contains(t, string(sidecar), "windows-amd64")
}

func TestModuleBundleBuildRefusesBadSeeds(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "acme-corp", "widget", "1.0.0")
	bin := writeBin(t, dir, "bin", "x")

	devSeed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := map[string]struct {
		stdin, env string
		useStdin   bool
		want       error
	}{
		"absent env":     {want: errSeedAbsent},
		"absent stdin":   {useStdin: true, want: errSeedAbsent},
		"malformed b64":  {env: "!!!notbase64", want: errSeedMalformed},
		"short seed":     {stdin: base64.StdEncoding.EncodeToString(make([]byte, 16)), useStdin: true, want: errSeedMalformed},
		"dev seed env":   {env: devSeed, want: errSeedDevKey},
		"dev seed stdin": {stdin: devSeed, useStdin: true, want: errSeedDevKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(publisherSeedEnv, tc.env)
			root := filepath.Join(t.TempDir(), "root")
			args := []string{"module", "bundle", "build", "--manifest", manifest, "--binary", "linux-amd64=" + bin, "--out", root}
			if tc.useStdin {
				args = append(args, "--seed-stdin")
			}
			_, err := runCfg(t, tc.stdin, args...)
			require.ErrorIs(t, err, tc.want)
			_, statErr := os.Stat(root)
			assert.True(t, os.IsNotExist(statErr), "nothing may be written")
		})
	}
}

func TestModuleBundleBuildRefusesUnsafeNames(t *testing.T) {
	seed, _, _ := keygen(t)
	for name, tc := range map[string]struct{ publisher, module string }{
		"publisher path":  {"../evil", "widget"},
		"publisher slash": {"a/b", "widget"},
		"name path":       {"acme-corp", "../widget"},
		"name backslash":  {"acme-corp", `a\b`},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			manifest := writeManifest(t, dir, tc.publisher, tc.module, "1.0.0")
			bin := writeBin(t, dir, "bin", "x")
			root := filepath.Join(dir, "root")
			_, err := runCfg(t, seed, "module", "bundle", "build", "--seed-stdin",
				"--manifest", manifest, "--binary", "linux-amd64="+bin, "--out", root)
			require.Error(t, err)
			_, statErr := os.Stat(root)
			assert.True(t, os.IsNotExist(statErr))
		})
	}
}

func TestModuleBundleBuildRefusesBadBinarySpecs(t *testing.T) {
	seed, _, _ := keygen(t)
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "acme-corp", "widget", "1.0.0")
	bin := writeBin(t, dir, "bin", "x")
	for name, spec := range map[string]string{
		"no equals":    "linux-amd64",
		"bad platform": "plan9-mips=" + bin,
		"missing file": "linux-amd64=" + filepath.Join(dir, "absent"),
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(dir, "root-"+strings.ReplaceAll(name, " ", "-"))
			_, err := runCfg(t, seed, "module", "bundle", "build", "--seed-stdin",
				"--manifest", manifest, "--binary", spec, "--out", root)
			require.Error(t, err)
			_, statErr := os.Stat(root)
			assert.True(t, os.IsNotExist(statErr))
		})
	}
}

func TestModuleBundleBuildRefusesExistingOut(t *testing.T) {
	seed, _, _ := keygen(t)
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "acme-corp", "widget", "1.0.0")
	bin := writeBin(t, dir, "bin", "x")
	_, err := runCfg(t, seed, "module", "bundle", "build", "--seed-stdin",
		"--manifest", manifest, "--binary", "linux-amd64="+bin, "--out", dir)
	require.ErrorIs(t, err, bundle.ErrRootExists)
}

func TestModuleBundleHasNoSeedOrKeyFileFlag(t *testing.T) {
	src, err := os.ReadFile("module_bundle.go")
	require.NoError(t, err)
	flags := regexp.MustCompile(`Flags\(\)\.\w+\(&?\w+, "([^"]+)"`).FindAllStringSubmatch(string(src), -1)
	var names []string
	for _, m := range flags {
		names = append(names, m[1])
	}
	assert.ElementsMatch(t, []string{"manifest", "binary", "out", "seed-stdin", "seed-stdin"}, names)
}
