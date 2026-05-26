// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
