// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package config provides mount-point metadata constants and config source parsing
package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Metadata key constants for config source routing on mount points.
const (
	MetaKeyConfigSourceType         = "config_source_type"
	MetaKeyConfigSourceURL          = "config_source_url"
	MetaKeyConfigSourceBranch       = "config_source_branch"
	MetaKeyConfigSourcePath         = "config_source_path"
	MetaKeyConfigSourceCredential   = "config_source_credential" // #nosec G101 -- metadata key name, not a credential
	MetaKeyConfigSourcePollInterval = "config_source_poll_interval"
)

// ConfigSourceType identifies how a mount point's configuration is fetched.
type ConfigSourceType string

const (
	// ConfigSourceTypeController means config is pushed/managed by the controller (default).
	ConfigSourceTypeController ConfigSourceType = "controller"
	// ConfigSourceTypeGit means config is pulled from an external HTTPS git repository.
	ConfigSourceTypeGit ConfigSourceType = "git"
)

// ConfigSourceInfo holds the parsed config source parameters for a mount point.
type ConfigSourceInfo struct {
	Type          ConfigSourceType
	URL           string
	Branch        string
	SubPath       string
	CredentialRef string
	PollInterval  time.Duration
}

const defaultPollInterval = 5 * time.Minute

// ParseConfigSource parses mount-point metadata into a ConfigSourceInfo.
// Absent metadata defaults to ConfigSourceTypeController with no error.
// URL validation order: scheme → userinfo absent → host not RFC1918/loopback/link-local.
func ParseConfigSource(metadata map[string]string) (*ConfigSourceInfo, error) {
	info := &ConfigSourceInfo{
		Type:         ConfigSourceTypeController,
		PollInterval: defaultPollInterval,
	}

	if len(metadata) == 0 {
		return info, nil
	}

	rawType, ok := metadata[MetaKeyConfigSourceType]
	if !ok || rawType == "" {
		rawType = string(ConfigSourceTypeController)
	}

	switch ConfigSourceType(rawType) {
	case ConfigSourceTypeController:
		info.Type = ConfigSourceTypeController
	case ConfigSourceTypeGit:
		info.Type = ConfigSourceTypeGit
	default:
		return nil, fmt.Errorf("unknown config_source_type %q: supported values are %q and %q",
			rawType, ConfigSourceTypeController, ConfigSourceTypeGit)
	}

	if info.Type == ConfigSourceTypeGit {
		rawURL := metadata[MetaKeyConfigSourceURL]
		if rawURL == "" {
			return nil, fmt.Errorf("config_source_url is required when config_source_type is %q", ConfigSourceTypeGit)
		}
		if err := validateSourceURL(rawURL); err != nil {
			return nil, err
		}
		info.URL = rawURL
		info.Branch = metadata[MetaKeyConfigSourceBranch]
		info.SubPath = metadata[MetaKeyConfigSourcePath]
		info.CredentialRef = metadata[MetaKeyConfigSourceCredential]
	}

	if raw := metadata[MetaKeyConfigSourcePollInterval]; raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			info.PollInterval = d
		}
		// unparseable value silently falls back to default
	}

	return info, nil
}

// validateSourceURL enforces Phase-1 URL security rules:
//   - SCP-style git@ addresses are rejected (SSH not yet supported)
//   - scheme must be https
//   - userinfo must be absent (credentials go in CredentialRef)
//   - host must not be an RFC 1918, loopback, link-local, or unspecified IP literal
//
// Error messages use parsed.Redacted() to avoid leaking embedded credentials.
func validateSourceURL(raw string) error {
	// Reject SCP-style git@ before url.Parse, which cannot handle them.
	if strings.HasPrefix(raw, "git@") {
		return fmt.Errorf("SSH URLs are not yet supported (got %q); use an HTTPS URL instead", raw)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid config_source_url: %w", err)
	}

	if parsed.Scheme == "ssh" {
		return fmt.Errorf("SSH URLs are not yet supported (scheme %q); use HTTPS instead", parsed.Scheme)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf("config_source_url must use the https scheme, got scheme %q (url: %s)", parsed.Scheme, parsed.Redacted())
	}

	if parsed.User != nil {
		return fmt.Errorf("userinfo credentials are not allowed in config_source_url (%s); supply credentials via %s",
			parsed.Redacted(), MetaKeyConfigSourceCredential)
	}

	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if err := checkSSRF(ip); err != nil {
			return fmt.Errorf("SSRF guard: config_source_url %q %w", parsed.Redacted(), err)
		}
	}

	return nil
}

// checkSSRF returns an error if ip falls within a disallowed range.
// Covers: RFC 1918, IPv6 ULA (fc00::/7), loopback, link-local, unspecified.
// NOTE: hostname-based bypasses (DNS resolving to private IPs) are not caught here;
// the consumer must re-validate the resolved address at dial time.
func checkSSRF(ip net.IP) error {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return fmt.Errorf("resolves to a private/loopback/link-local address")
	}
	// IsPrivate covers RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6 ULA (fc00::/7).
	if ip.IsPrivate() {
		return fmt.Errorf("resolves to a private/loopback/link-local address")
	}
	// Additional RFC 3927 link-local for IPv4 (169.254.0.0/16) — covered by IsLinkLocalUnicast
	// but checked explicitly for clarity.
	for _, block := range ssrfExtraBlocks {
		if block.Contains(ip) {
			return fmt.Errorf("resolves to a private/loopback/link-local address")
		}
	}
	return nil
}

// ssrfExtraBlocks catches ranges not covered by net.IP helper methods above.
var ssrfExtraBlocks = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8", // unspecified / "this" network
		"fec0::/10", // deprecated IPv6 site-local
	}
	blocks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, _ := net.ParseCIDR(cidr)
		blocks = append(blocks, block)
	}
	return blocks
}()
