// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

func TestParseConfigSource_Defaults(t *testing.T) {
	// Absent metadata should default to controller source with no error
	info, err := ParseConfigSource(nil)
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeController, info.Type)
	assert.Empty(t, info.URL)
	assert.Empty(t, info.Branch)
	assert.Empty(t, info.SubPath)
	assert.Empty(t, info.CredentialRef)
	assert.Equal(t, 5*time.Minute, info.PollInterval)

	// Empty map should also default
	info2, err2 := ParseConfigSource(map[string]string{})
	require.NoError(t, err2)
	assert.Equal(t, ConfigSourceTypeController, info2.Type)
	assert.Equal(t, 5*time.Minute, info2.PollInterval)
}

func TestParseConfigSource_GitSource(t *testing.T) {
	meta := map[string]string{
		MetaKeyConfigSourceType:         "git",
		MetaKeyConfigSourceURL:          "https://github.com/example/configs.git",
		MetaKeyConfigSourceBranch:       "main",
		MetaKeyConfigSourcePath:         "tenants/acme",
		MetaKeyConfigSourceCredential:   "acme-git-token",
		MetaKeyConfigSourcePollInterval: "10m",
	}

	info, err := ParseConfigSource(meta)
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeGit, info.Type)
	assert.Equal(t, "https://github.com/example/configs.git", info.URL)
	assert.Equal(t, "main", info.Branch)
	assert.Equal(t, "tenants/acme", info.SubPath)
	assert.Equal(t, "acme-git-token", info.CredentialRef)
	assert.Equal(t, 10*time.Minute, info.PollInterval)
}

func TestParseConfigSource_UnknownType(t *testing.T) {
	meta := map[string]string{
		MetaKeyConfigSourceType: "s3",
	}
	_, err := ParseConfigSource(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown config_source_type")
}

func TestParseConfigSource_MissingURL(t *testing.T) {
	meta := map[string]string{
		MetaKeyConfigSourceType: "git",
	}
	_, err := ParseConfigSource(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config_source_url")
}

func TestParseConfigSource_HTTPSOnly(t *testing.T) {
	// HTTP must be rejected
	meta := map[string]string{
		MetaKeyConfigSourceType: "git",
		MetaKeyConfigSourceURL:  "http://github.com/example/configs.git",
	}
	_, err := ParseConfigSource(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")

	// HTTPS must be accepted
	meta[MetaKeyConfigSourceURL] = "https://github.com/example/configs.git"
	_, err = ParseConfigSource(meta)
	require.NoError(t, err)
}

func TestParseConfigSource_RejectsSSH(t *testing.T) {
	// SCP-style git@ URL must be rejected with message about SSH not yet supported
	meta := map[string]string{
		MetaKeyConfigSourceType: "git",
		MetaKeyConfigSourceURL:  "git@github.com:example/configs.git",
	}
	_, err := ParseConfigSource(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSH")

	// ssh:// scheme also rejected
	meta[MetaKeyConfigSourceURL] = "ssh://git@github.com/example/configs.git"
	_, err = ParseConfigSource(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSH")
}

func TestParseConfigSource_RejectsUserinfoCredential(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"token-only userinfo", "https://token@github.com/example/configs.git"},
		{"user:pass userinfo", "https://user:pass@github.com/example/configs.git"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]string{
				MetaKeyConfigSourceType: "git",
				MetaKeyConfigSourceURL:  tc.url,
			}
			_, err := ParseConfigSource(meta)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "userinfo")
		})
	}
}

func TestParseConfigSource_RejectsRFC1918Host(t *testing.T) {
	privateHosts := []struct {
		name string
		url  string
	}{
		{"10.x.x.x", "https://10.0.0.1/repo.git"},
		{"172.16.x.x", "https://172.16.0.1/repo.git"},
		{"172.31.x.x", "https://172.31.255.255/repo.git"},
		{"192.168.x.x", "https://192.168.1.1/repo.git"},
		{"link-local IPv4", "https://169.254.0.1/repo.git"},
	}
	for _, tc := range privateHosts {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]string{
				MetaKeyConfigSourceType: "git",
				MetaKeyConfigSourceURL:  tc.url,
			}
			_, err := ParseConfigSource(meta)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SSRF")
		})
	}
}

func TestParseConfigSource_RejectsLoopback(t *testing.T) {
	loopbackHosts := []struct {
		name string
		url  string
	}{
		{"localhost IPv4", "https://127.0.0.1/repo.git"},
		{"127.x.x.x", "https://127.0.0.2/repo.git"},
		{"IPv6 loopback", "https://[::1]/repo.git"},
		{"IPv6 link-local", "https://[fe80::1]/repo.git"},
	}
	for _, tc := range loopbackHosts {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]string{
				MetaKeyConfigSourceType: "git",
				MetaKeyConfigSourceURL:  tc.url,
			}
			_, err := ParseConfigSource(meta)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SSRF")
		})
	}
}

func TestParseConfigSource_PollIntervalDefaults(t *testing.T) {
	// Unparseable poll interval should default to 5 minutes
	meta := map[string]string{
		MetaKeyConfigSourceType:         "git",
		MetaKeyConfigSourceURL:          "https://github.com/example/configs.git",
		MetaKeyConfigSourcePollInterval: "not-a-duration",
	}
	info, err := ParseConfigSource(meta)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, info.PollInterval)
}

func TestNormalizeRepositoryURL(t *testing.T) {
	const want = "https://github.com/acme/configs"
	for _, in := range []string{
		"https://github.com/acme/configs",
		"https://github.com/acme/configs.git",
		"https://github.com/acme/configs/",
		"https://github.com/acme/configs.git/",
		"HTTPS://GitHub.COM/acme/configs",
		"https://github.com:443/acme/configs",
	} {
		assert.Equal(t, want, NormalizeRepositoryURL(in), in)
	}
	assert.Equal(t, "https://github.com:8443/acme/configs", NormalizeRepositoryURL("https://github.com:8443/acme/configs.git"))
	assert.Equal(t, "https://github.com/Acme/Configs", NormalizeRepositoryURL("https://github.com/Acme/Configs"), "path case is preserved")
}

func TestCheckCredentialBinding(t *testing.T) {
	const tokenValue = "ghp_supersecrettokenvalue"
	bound := func(u string) *secretsiface.Secret {
		return &secretsiface.Secret{Value: tokenValue, Metadata: map[string]string{SecretMetaKeyBoundRepositoryURL: NormalizeRepositoryURL(u)}}
	}
	a := "https://github.com/acme/configs"

	for _, u := range []string{a, a + ".git", a + "/", "https://GITHUB.com:443/acme/configs.git/"} {
		assert.NoError(t, CheckCredentialBinding(bound(a), u), u)
	}

	failing := map[string]struct {
		secret *secretsiface.Secret
		url    string
	}{
		"different repo":    {bound(a), "https://github.com/acme/other"},
		"different host":    {bound(a), "https://gitlab.com/acme/configs"},
		"different port":    {bound(a), "https://github.com:8443/acme/configs"},
		"different scheme":  {bound(a), "http://github.com/acme/configs"},
		"url is prefix":     {bound(a + "-extra"), a},
		"binding is prefix": {bound(a), a + "-extra"},
		"url is subpath":    {bound("https://github.com/acme"), a},
		"binding subpath":   {bound(a), "https://github.com/acme"},
		"no metadata":       {&secretsiface.Secret{Value: tokenValue}, a},
		"empty binding":     {&secretsiface.Secret{Value: tokenValue, Metadata: map[string]string{SecretMetaKeyBoundRepositoryURL: ""}}, a},
		"nil secret":        {nil, a},
		"empty url":         {bound(a), ""},
	}
	for name, tc := range failing {
		err := CheckCredentialBinding(tc.secret, tc.url)
		require.Error(t, err, name)
		assert.NotContains(t, err.Error(), tokenValue, name)
	}
}

// fakeResolver is a network-free HostResolver for tests.
type fakeResolver struct {
	addrs []net.IPAddr
	err   error
	block bool
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.addrs, f.err
}

func ipAddrs(ips ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

// publicTestResolver answers a public documentation address for every name.
func publicTestResolver() HostResolver {
	return &fakeResolver{addrs: ipAddrs("203.0.113.10")}
}

func TestValidateSourceURLWithResolver_BlockedAnswers(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "169.254.169.254", "10.1.2.3", "::1",
		"100.100.100.200", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "255.255.255.255",
		"::ffff:127.0.0.1", "224.0.0.1", "ff02::1", "198.18.0.1", "192.0.0.8", "::7f00:1",
	}
	for _, ip := range blocked {
		t.Run(ip, func(t *testing.T) {
			err := ValidateSourceURLWithResolver(context.Background(), "https://git.acme-corp.example/r", &fakeResolver{addrs: ipAddrs(ip)})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), ip)
		})
	}
	t.Run("mixed public and blocked", func(t *testing.T) {
		err := ValidateSourceURLWithResolver(context.Background(), "https://git.acme-corp.example/r",
			&fakeResolver{addrs: ipAddrs("203.0.113.10", "169.254.169.254")})
		require.Error(t, err)
	})
}

func TestValidateSourceURLWithResolver_PublicAdmitted(t *testing.T) {
	for _, ip := range []string{"203.0.113.10", "2606:4700:4700::1111"} {
		require.NoError(t, ValidateSourceURLWithResolver(context.Background(), "https://git.acme-corp.example/r", &fakeResolver{addrs: ipAddrs(ip)}), ip)
	}
	require.NoError(t, ValidateSourceURLWithResolver(context.Background(), "https://cafe.example/r", publicTestResolver()))
}

func TestValidateSourceURLWithResolver_FailsClosed(t *testing.T) {
	const raw = "https://git.acme-corp.example/r"
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	cases := map[string]struct {
		ctx context.Context
		r   HostResolver
	}{
		"error":     {context.Background(), &fakeResolver{err: errors.New("lookup failed for 203.0.113.99")}},
		"empty":     {context.Background(), &fakeResolver{}},
		"timeout":   {deadline, &fakeResolver{block: true}},
		"cancelled": {cancelled, &fakeResolver{block: true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateSourceURLWithResolver(tc.ctx, raw, tc.r)
			require.Error(t, err)
			assert.False(t, strings.Contains(err.Error(), "203.0.113"), "no address in error: %v", err)
		})
	}
}

func TestValidateSourceURL_NonCanonicalNumericHosts(t *testing.T) {
	restore := UseHostResolverForTesting(publicTestResolver())
	defer restore()
	for _, h := range []string{"2130706433", "0177.0.0.1", "0x7f.1", "127.000.000.001", "0x7f.0x0.0x0.0x1"} {
		require.Error(t, ValidateSourceURL("https://"+h+"/r"), h)
		_, err := ParseConfigSource(map[string]string{MetaKeyConfigSourceType: "git", MetaKeyConfigSourceURL: "https://" + h + "/r"})
		require.Error(t, err, h)
	}
	require.Error(t, ValidateSourceURL("https://[::ffff:127.0.0.1]/r"))
}

func TestParseConfigSource_DoesNotResolve(t *testing.T) {
	restore := UseHostResolverForTesting(&fakeResolver{err: errors.New("must not be called")})
	defer restore()
	_, err := ParseConfigSource(map[string]string{MetaKeyConfigSourceType: "git", MetaKeyConfigSourceURL: "https://git.acme-corp.example/r"})
	require.NoError(t, err)
}
