// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// profileURIPrefix is the scheme used to reference an unattended-install profile
// from a VM source's unattend field (e.g. "profile://debian-12-base").
const profileURIPrefix = "profile://"

// profileNamePattern bounds profile names to a safe character set and length so
// they map cleanly onto config-store keys and cannot smuggle path separators or
// other control characters into the stored-config backend. (ADR-009 §7,
// ADR-003 key-path conventions.)
var profileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

var (
	// ErrProfileNotFound is the sentinel returned by ProfileStore implementations
	// when no profile exists under the requested name.
	ErrProfileNotFound = errors.New("hyperv: unattend profile not found")

	// ErrInvalidProfileName is returned when a profile reference does not match
	// the allowed name pattern after the profile:// prefix is stripped.
	ErrInvalidProfileName = errors.New("hyperv: invalid profile name: must match ^[a-zA-Z0-9_\\-]{1,64}$")

	// ErrInvalidAnswerFormat is returned when a profile's answer_format is not one
	// of the formats supported in v1 (preseed, autounattend).
	ErrInvalidAnswerFormat = errors.New("hyperv: invalid answer_format: must be preseed or autounattend")
)

// AnswerFormat enumerates the unattended-answer file formats supported in v1.
// preseed is the Debian/Ubuntu installer format; autounattend is the Windows
// Setup answer-file format. The concrete templates for each format are provided
// by sibling stories (#2046 preseed, #2047 autounattend); this story only
// validates the format value and renders the profile's template bytes.
type AnswerFormat string

const (
	// AnswerFormatPreseed is the Debian/Ubuntu preseed.cfg format.
	AnswerFormatPreseed AnswerFormat = "preseed"
	// AnswerFormatAutounattend is the Windows Setup autounattend.xml format.
	AnswerFormatAutounattend AnswerFormat = "autounattend"
)

// valid reports whether the AnswerFormat is one of the v1-supported formats.
func (f AnswerFormat) valid() bool {
	switch f {
	case AnswerFormatPreseed, AnswerFormatAutounattend:
		return true
	default:
		return false
	}
}

// EnrollConfig describes how a freshly provisioned VM enrolls back into CFGMS.
// It carries the secret KEY NAME of the registration token (never the token
// value) plus the bundle URL and a correlation label. The token value is
// resolved from the SecretStore at render time and never persisted in the
// profile or on committed media.
type EnrollConfig struct {
	// RegistrationTokenSecretKey is the SecretStore key under which the
	// enrollment registration token is stored (e.g. "hyperv/enroll/regtoken").
	// The value is fetched at render time; only the key is stored in the profile.
	RegistrationTokenSecretKey string `yaml:"registration_token_secret_key,omitempty"`
	// BundleURL is the location the new endpoint pulls its enrollment bundle from.
	BundleURL string `yaml:"bundle_url,omitempty"`
	// CorrelationLabel ties the provisioned VM back to a provisioning request for
	// the controller-side completion reconciler (sibling story S8).
	CorrelationLabel string `yaml:"correlation_label,omitempty"`
}

// UnattendProfile is the operator-authored, stored-config definition of an
// unattended install. It is YAML-serialised into the controller's stored-config
// backend under hyperv/profiles/<name> (ADR-003) and referenced from a VM
// source as profile://<name>. No secret VALUES live here — only secret key
// names, which are resolved from the secrets provider at render time.
type UnattendProfile struct {
	// Name is the profile identifier (matches the profile:// reference suffix).
	Name string `yaml:"name"`
	// OSFamily is the installer family: linux or windows.
	OSFamily string `yaml:"os_family"`
	// AnswerFormat is the answer-file format: preseed or autounattend.
	AnswerFormat AnswerFormat `yaml:"answer_format"`
	// Template is the text/template source for the answer file. It may reference
	// per-VM vars ({{ .VMName }}, {{ .OSFamily }}, {{ .EnrollToken }}) and
	// secrets ({{ secret "key" }}). It is NOT HTML and is never HTML-escaped.
	Template string `yaml:"template"`
	// Enroll carries enrollment wiring (token secret key, bundle URL, label).
	Enroll EnrollConfig `yaml:"enroll,omitempty"`
}

// validate checks the profile's structural invariants that must hold before any
// rendering is attempted. It returns a typed error (ErrInvalidAnswerFormat,
// ErrInvalidProfileName) so callers and tests can assert on the cause.
func (p *UnattendProfile) validate() error {
	if !profileNamePattern.MatchString(p.Name) {
		return fmt.Errorf("%w: %q", ErrInvalidProfileName, p.Name)
	}
	if !p.AnswerFormat.valid() {
		return fmt.Errorf("%w: %q", ErrInvalidAnswerFormat, p.AnswerFormat)
	}
	return nil
}

// ProfileStore loads unattended-install profiles by name. Implementations read
// from a durable backend (ConfigBackedProfileStore) or, in unit tests, from an
// in-memory double (memProfileStore). GetProfile returns ErrProfileNotFound
// when the named profile does not exist.
type ProfileStore interface {
	GetProfile(ctx context.Context, name string) (*UnattendProfile, error)
}

// ProfileVars are the per-VM values substituted into a profile template at
// render time. They are supplied by the caller (the create-from-source path),
// never stored in the profile itself.
type ProfileVars struct {
	// VMName is the host-side VM name being provisioned.
	VMName string
	// OSFamily is the installer family for this VM (linux or windows).
	OSFamily string
	// EnrollToken is the resolved registration token for this VM. It is supplied
	// pre-resolved by the caller (or left empty when not applicable). Secret
	// VALUES referenced via {{ secret "key" }} are resolved separately from the
	// SecretStore at render time.
	EnrollToken string
}

// ProfileRenderer renders an UnattendProfile's template into answer-file bytes,
// substituting per-VM vars and resolving {{ secret "key" }} placeholders against
// an injected SecretStore at render time. Secret values are inserted into the
// output bytes and never logged. Output is plain text (preseed.cfg or XML);
// text/template is used (NOT html/template) so installer syntax is not corrupted
// by HTML escaping.
type ProfileRenderer struct{}

// NewProfileRenderer returns a ProfileRenderer. It carries no state; a value is
// returned for symmetry with the other store/renderer constructors.
func NewProfileRenderer() *ProfileRenderer {
	return &ProfileRenderer{}
}

// secretResolver is the closure type backing the template "secret" function.
type secretResolver func(key string) (string, error)

// Render validates the profile, then renders its template with the supplied
// per-VM vars and a "secret" function bound to store.GetSecret. On any error —
// invalid profile, unknown template field, parse failure, or a secret lookup
// failure (including secretsif.ErrSecretNotFound) — Render returns the error and
// NO partial output (the all-or-nothing guarantee required by the AC).
func (r *ProfileRenderer) Render(ctx context.Context, profile *UnattendProfile, vars ProfileVars, store secretsif.SecretStore) ([]byte, error) {
	if profile == nil {
		return nil, errors.New("hyperv: nil profile")
	}
	if err := profile.validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("hyperv: nil secret store")
	}

	// secretErr captures a failure from inside the "secret" template func so we
	// can surface the real cause (e.g. ErrSecretNotFound) instead of the wrapped
	// text/template execution error, and guarantee no partial output is returned.
	var secretErr error
	resolve := secretResolver(func(key string) (string, error) {
		sec, err := store.GetSecret(ctx, key)
		if err != nil {
			secretErr = fmt.Errorf("hyperv: resolving secret %q: %w", key, err)
			return "", secretErr
		}
		return sec.Value, nil
	})

	funcMap := template.FuncMap{
		"secret": func(key string) (string, error) { return resolve(key) },
	}

	tmpl, err := template.New(profile.Name).Option("missingkey=error").Funcs(funcMap).Parse(profile.Template)
	if err != nil {
		return nil, fmt.Errorf("hyperv: parsing profile template %q: %w", profile.Name, err)
	}

	data := struct {
		VMName      string
		OSFamily    string
		EnrollToken string
	}{
		VMName:      vars.VMName,
		OSFamily:    vars.OSFamily,
		EnrollToken: vars.EnrollToken,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		// A secret-resolution failure inside the func surfaces here wrapped in a
		// template error; return the real cause so errors.Is(err, ErrSecretNotFound)
		// works and no partial output escapes.
		if secretErr != nil {
			return nil, secretErr
		}
		return nil, fmt.Errorf("hyperv: rendering profile template %q: %w", profile.Name, err)
	}
	if secretErr != nil {
		return nil, secretErr
	}

	return buf.Bytes(), nil
}

// parseProfileName strips the profile:// prefix from a source.unattend reference
// and validates the remainder against profileNamePattern. It returns
// ErrInvalidProfileName for any reference that is malformed or whose name fails
// validation, so the caller never issues a store lookup for an unsafe key.
func parseProfileName(ref string) (string, error) {
	if !strings.HasPrefix(ref, profileURIPrefix) {
		return "", fmt.Errorf("%w: missing %q prefix in %q", ErrInvalidProfileName, profileURIPrefix, ref)
	}
	name := strings.TrimPrefix(ref, profileURIPrefix)
	if !profileNamePattern.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidProfileName, name)
	}
	return name, nil
}
