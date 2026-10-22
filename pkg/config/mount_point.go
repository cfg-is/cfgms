// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package config provides mount-point metadata constants and config source parsing
package config

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
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

// SecretMetaKeyBoundRepositoryURL is the secret-metadata key holding the normalized
// repository URL a git config-source credential was stored for.
const SecretMetaKeyBoundRepositoryURL = "bound_repository_url"

// ConfigSourceCredentialKeyName is the secret key suffix under a tenant namespace
// that holds the git config-source credential: "<tenant id>/config-source-git".
const ConfigSourceCredentialKeyName = "config-source-git"

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
	} else if isNonCanonicalNumericHost(host) {
		return fmt.Errorf("SSRF guard: config_source_url %q uses a non-canonical numeric IP form", parsed.Redacted())
	}

	return nil
}

// isNonCanonicalNumericHost reports whether every dot-separated label of host is a
// number (decimal, leading-zero octal or 0x hexadecimal). Resolvers and HTTP clients
// may interpret such a host as an IPv4 address (2130706433, 0177.0.0.1, 0x7f.1), so
// it is refused without resolution. The caller has already ruled out canonical IP
// literals via net.ParseIP.
func isNonCanonicalNumericHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !isNumericLabel(label) {
			return false
		}
	}
	return true
}

func isNumericLabel(label string) bool {
	if label == "" {
		return false
	}
	digits := label
	hex := false
	if len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
		hex = true
		digits = label[2:]
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		switch {
		case c >= '0' && c <= '9':
		case hex && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')):
		default:
			return false
		}
	}
	return true
}

// HostResolver resolves a host name to its addresses. *net.Resolver satisfies it.
type HostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// sourceURLResolveTimeout bounds the lookup done by the context-free ValidateSourceURL.
const sourceURLResolveTimeout = 5 * time.Second

var defaultHostResolver HostResolver = net.DefaultResolver

// UseHostResolverForTesting replaces the package default resolver and returns a
// function restoring the previous one. FOR TESTS ONLY — never use in production.
func UseHostResolverForTesting(r HostResolver) (restore func()) {
	prev := defaultHostResolver
	defaultHostResolver = r
	return func() { defaultHostResolver = prev }
}

// ValidateSourceURLWithResolver applies validateSourceURL, then — for a host that is
// not an IP literal — resolves it through r and checks every returned address with
// checkSSRF. It fails closed: a resolver error, timeout, cancelled context or empty
// answer rejects the URL. Errors use the redacted URL and never contain an address.
func ValidateSourceURLWithResolver(ctx context.Context, raw string, r HostResolver) error {
	if err := validateSourceURL(raw); err != nil {
		return err
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid config_source_url: %w", err)
	}
	host := parsed.Hostname()
	if net.ParseIP(host) != nil {
		return nil // literal already checked by validateSourceURL
	}
	if r == nil {
		r = defaultHostResolver
	}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("SSRF guard: config_source_url %q host could not be resolved", parsed.Redacted())
	}
	if len(addrs) == 0 {
		return fmt.Errorf("SSRF guard: config_source_url %q host resolved to no addresses", parsed.Redacted())
	}
	for _, a := range addrs {
		if err := checkSSRF(a.IP); err != nil {
			return fmt.Errorf("SSRF guard: config_source_url %q %w", parsed.Redacted(), err)
		}
	}
	return nil
}

// checkSSRF returns an error if ip falls within a disallowed range.
// Covers: RFC 1918, IPv6 ULA (fc00::/7), loopback, link-local, unspecified.
// Also blocks shared address space, multicast/reserved ranges, and IPv6 forms that
// embed an IPv4 address (checked as that IPv4 address). Hostname resolution is done by
// ValidateSourceURLWithResolver; the consumer must still re-validate at dial time.
func checkSSRF(ip net.IP) error {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if len(ip) == net.IPv6len {
		if emb := embeddedIPv4(ip); emb != nil {
			if err := checkSSRF(emb); err != nil {
				return err
			}
		}
	}
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

// embeddedIPv4 returns the IPv4 address carried by a NAT64 (64:ff9b::/96), 6to4
// (2002::/16) or IPv4-compatible (::/96) IPv6 address, or nil.
func embeddedIPv4(ip net.IP) net.IP {
	switch {
	case ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && allZero(ip[4:12]):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	case ip[0] == 0x20 && ip[1] == 0x02:
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	case allZero(ip[:12]):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ssrfExtraBlocks catches ranges not covered by net.IP helper methods above.
var ssrfExtraBlocks = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",     // unspecified / "this" network
		"fec0::/10",     // deprecated IPv6 site-local
		"100.64.0.0/10", // shared address space (CGNAT)
		"192.0.0.0/24",  // IETF protocol assignments
		"198.18.0.0/15", // benchmarking
		"224.0.0.0/4",   // multicast
		"240.0.0.0/4",   // reserved, including broadcast
		"ff00::/8",      // IPv6 multicast
		"64:ff9b::/96",  // NAT64
		"2002::/16",     // 6to4
		"::/96",         // IPv4-compatible
	}
	blocks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, _ := net.ParseCIDR(cidr)
		blocks = append(blocks, block)
	}
	return blocks
}()

// NormalizeRepositoryURL returns the canonical form of a repository URL used for
// credential binding: lowercase scheme and host, default port (80 for http, 443 for
// https) dropped, fragment dropped, and a trailing "/" and ".git" removed from the
// path. A value that does not parse is returned trimmed of surrounding space only,
// so it can still be compared for equality.
func NormalizeRepositoryURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimRight(path, "/")
	out := scheme + "://"
	if u.User != nil {
		out += u.User.String() + "@"
	}
	out += host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// credentialRebindHint names the operator action that fixes a failed binding check.
const credentialRebindHint = "store it again with `cfg tenant config-source set-credential`"

// CheckCredentialBinding returns nil only when secret carries a bound_repository_url
// metadata value exactly equal to the normalized repoURL. Scheme, host, port and path
// must all match; a prefix, suffix or same-host match is refused. Errors never contain
// the secret value.
func CheckCredentialBinding(secret *secretsiface.Secret, repoURL string) error {
	if secret == nil {
		return fmt.Errorf("credential is not bound to a repository: %s", credentialRebindHint)
	}
	bound, ok := secret.Metadata[SecretMetaKeyBoundRepositoryURL]
	if !ok || bound == "" {
		return fmt.Errorf("credential is not bound to a repository: %s", credentialRebindHint)
	}
	want := NormalizeRepositoryURL(repoURL)
	if want == "" || bound != want {
		return fmt.Errorf("credential is not bound to this repository: %s", credentialRebindHint)
	}
	return nil
}

// ValidateSourceURL applies the config_source_url security rules (https scheme, no
// userinfo, no blocked IP literal, and every resolved address checked) to raw. Callers that accept a
// repository URL from an operator use it so the URL is checked exactly as
// ParseConfigSource checks it.
func ValidateSourceURL(raw string) error {
	ctx, cancel := context.WithTimeout(context.Background(), sourceURLResolveTimeout)
	defer cancel()
	return ValidateSourceURLWithResolver(ctx, raw, defaultHostResolver)
}
