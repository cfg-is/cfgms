// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// memProfileStore is an in-memory ProfileStore double used by unit tests. It is
// a real implementation of the ProfileStore contract (not a mock framework):
// it stores profiles in a map and returns ErrProfileNotFound for unknown names.
type memProfileStore struct {
	profiles map[string]*UnattendProfile
}

func newMemProfileStore() *memProfileStore {
	return &memProfileStore{profiles: make(map[string]*UnattendProfile)}
}

func (m *memProfileStore) put(p *UnattendProfile) { m.profiles[p.Name] = p }

func (m *memProfileStore) GetProfile(_ context.Context, name string) (*UnattendProfile, error) {
	p, ok := m.profiles[name]
	if !ok {
		return nil, ErrProfileNotFound
	}
	return p, nil
}

var _ ProfileStore = (*memProfileStore)(nil)

// TestProfileRenderer_SubstitutesSecretsAtRenderTime is the REQUIRED TEST from
// the AC: a real inlineStore supplies known key/value pairs; the rendered output
// must contain the resolved secret values and per-VM vars, and must NOT contain
// the raw secret key names.
func TestProfileRenderer_SubstitutesSecretsAtRenderTime(t *testing.T) {
	store := newInlineStore(
		"hyperv/enroll/regtoken", "tok-abc123",
		"hyperv/admin/password", "S3cr3t-Pass",
	)

	profile := &UnattendProfile{
		Name:         "debian-12-base",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template: strings.Join([]string{
			"hostname={{ .VMName }}",
			"os={{ .OSFamily }}",
			"enroll-token={{ .EnrollToken }}",
			`regtoken={{ secret "hyperv/enroll/regtoken" }}`,
			`admin-pass={{ secret "hyperv/admin/password" }}`,
		}, "\n"),
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{
		VMName:      "vm-web-01",
		OSFamily:    "linux",
		EnrollToken: "enroll-xyz",
	}, store)
	require.NoError(t, err)

	rendered := string(out)
	assert.Contains(t, rendered, "hostname=vm-web-01")
	assert.Contains(t, rendered, "os=linux")
	assert.Contains(t, rendered, "enroll-token=enroll-xyz")
	assert.Contains(t, rendered, "regtoken=tok-abc123")
	assert.Contains(t, rendered, "admin-pass=S3cr3t-Pass")

	// The raw secret key names must never appear in the rendered output.
	assert.NotContains(t, rendered, "hyperv/enroll/regtoken")
	assert.NotContains(t, rendered, "hyperv/admin/password")
}

// TestProfileRenderer_RejectsUnknownAnswerFormat is the REQUIRED TEST from the
// AC: a profile whose answer_format is not preseed/autounattend is rejected with
// a typed error before any rendering happens.
func TestProfileRenderer_RejectsUnknownAnswerFormat(t *testing.T) {
	store := newInlineStore()
	profile := &UnattendProfile{
		Name:         "bad-format",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormat("invalid"),
		Template:     "should-not-render={{ .VMName }}",
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{VMName: "vm-x"}, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidAnswerFormat)
	assert.Nil(t, out, "no output on validation failure")
}

// TestProfileRenderer_AcceptsAutounattendFormat confirms the second valid v1
// format renders successfully.
func TestProfileRenderer_AcceptsAutounattendFormat(t *testing.T) {
	store := newInlineStore()
	profile := &UnattendProfile{
		Name:         "win-2025-base",
		OSFamily:     "windows",
		AnswerFormat: AnswerFormatAutounattend,
		Template:     "<ComputerName>{{ .VMName }}</ComputerName>",
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{VMName: "WIN-01"}, store)
	require.NoError(t, err)
	assert.Equal(t, "<ComputerName>WIN-01</ComputerName>", string(out))
}

// TestProfileRenderer_SecretNotFoundReturnsErrorNoOutput is the AC path for a
// missing secret: Render returns an error (wrapping ErrSecretNotFound) and emits
// no partial output.
func TestProfileRenderer_SecretNotFoundReturnsErrorNoOutput(t *testing.T) {
	store := newInlineStore() // empty: every secret lookup misses

	profile := &UnattendProfile{
		Name:         "needs-secret",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     `token={{ secret "missing/key" }}`,
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{VMName: "vm-y"}, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound)
	assert.Nil(t, out, "no partial output when a secret cannot be resolved")
}

// TestProfileRenderer_RejectsInvalidProfileName confirms name validation runs
// before rendering.
func TestProfileRenderer_RejectsInvalidProfileName(t *testing.T) {
	store := newInlineStore()
	profile := &UnattendProfile{
		Name:         "bad name/with/slash",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "x={{ .VMName }}",
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{VMName: "vm"}, store)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfileName)
	assert.Nil(t, out)
}

// TestProfileRenderer_BadTemplateSyntaxReturnsError confirms a malformed
// template surfaces a parse error with no output.
func TestProfileRenderer_BadTemplateSyntaxReturnsError(t *testing.T) {
	store := newInlineStore()
	profile := &UnattendProfile{
		Name:         "bad-template",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "x={{ .VMName ", // unterminated action
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{VMName: "vm"}, store)
	require.Error(t, err)
	assert.Nil(t, out)
}

// TestProfileRenderer_UnknownTemplateFieldReturnsError confirms missingkey=error
// makes references to unknown fields fail rather than emit "<no value>".
func TestProfileRenderer_UnknownTemplateFieldReturnsError(t *testing.T) {
	store := newInlineStore()
	profile := &UnattendProfile{
		Name:         "unknown-field",
		OSFamily:     "linux",
		AnswerFormat: AnswerFormatPreseed,
		Template:     "x={{ .DoesNotExist }}",
	}

	r := NewProfileRenderer()
	out, err := r.Render(context.Background(), profile, ProfileVars{VMName: "vm"}, store)
	require.Error(t, err)
	assert.Nil(t, out)
}

// TestParseProfileName covers the profile:// extraction + validation used before
// any store lookup.
func TestParseProfileName(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		name, err := parseProfileName("profile://debian-12_base")
		require.NoError(t, err)
		assert.Equal(t, "debian-12_base", name)
	})
	t.Run("missing prefix", func(t *testing.T) {
		_, err := parseProfileName("debian-12")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidProfileName)
	})
	t.Run("illegal chars", func(t *testing.T) {
		_, err := parseProfileName("profile://../etc/passwd")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidProfileName)
	})
	t.Run("too long", func(t *testing.T) {
		_, err := parseProfileName("profile://" + strings.Repeat("a", 65))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidProfileName)
	})
}

// TestMemProfileStore_GetProfile exercises the in-memory double used by other
// unit tests, including the not-found path.
func TestMemProfileStore_GetProfile(t *testing.T) {
	ms := newMemProfileStore()
	want := &UnattendProfile{Name: "p1", OSFamily: "linux", AnswerFormat: AnswerFormatPreseed, Template: "x"}
	ms.put(want)

	got, err := ms.GetProfile(context.Background(), "p1")
	require.NoError(t, err)
	assert.Equal(t, want, got)

	_, err = ms.GetProfile(context.Background(), "nope")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrProfileNotFound))
}

// TestRenderedProfiles_NoTokenValue asserts no built-in profile renders the
// enrollment token value; each installs from the staged token file.
func TestRenderedProfiles_NoTokenValue(t *testing.T) {
	const token = "tok-must-not-render-9f3"
	cases := []struct {
		name    string
		profile *UnattendProfile
		vars    ProfileVars
		want    []string
	}{
		{"windows", defaultWindowsProfile(), ProfileVars{
			VMName: "WIN-01", OSFamily: "windows", CorrelationID: "c1", ProductEdition: defaultWindowsEdition,
			EnrollTokenFile: enrollTokenFilePath("windows"), CAFingerprint: "FP",
		}, []string{"copy /y", "icacls", "del /f /q", `--regtoken-file "%SystemRoot%\Temp\cfgms-regtoken"`}},
		{"preseed", defaultLinuxProfile(), ProfileVars{
			VMName: "lin-01", OSFamily: "linux", CorrelationID: "c1", BundleURL: "https://controller.example/x.deb",
			EnrollTokenFile: enrollTokenFilePath("linux"), AdminPassword: "pw",
		}, []string{"cp /mnt/cfgms-seed/regtoken /target/root/.cfgms-regtoken", "chmod 0600", "rm -f /target/root/.cfgms-regtoken", "--regtoken-file /root/.cfgms-regtoken"}},
		{"cloud-init", defaultLinuxCloudInitProfile(), ProfileVars{
			VMName: "lin-01", OSFamily: "linux", CorrelationID: "c1",
			EnrollTokenFile: enrollTokenFilePath("linux"), CAFingerprint: "FP", AdminPassword: "pw",
		}, []string{"cp, /mnt/cidata/regtoken", `chmod, "0600"`, "rm, -f", "--regtoken-file"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.vars.EnrollToken = token
			store := newInlineStore("hyperv/enroll/user-password-crypted", "$6$x$y")
			out, err := NewProfileRenderer().Render(context.Background(), tc.profile, tc.vars, store)
			require.NoError(t, err)
			rendered := string(out)
			assert.NotContains(t, rendered, token)
			assert.Contains(t, rendered, "--regtoken-file")
			assert.NotRegexp(t, `--regtoken(\s|")`, rendered)
			for _, w := range tc.want {
				assert.Contains(t, rendered, w)
			}
		})
	}
}

// TestRender_EnrollTokenStillResolvesForCustomProfiles keeps custom profiles
// that reference {{ .EnrollToken }} rendering, and exposes {{ .EnrollTokenFile }}.
func TestRender_EnrollTokenStillResolvesForCustomProfiles(t *testing.T) {
	p := &UnattendProfile{Name: "custom", AnswerFormat: AnswerFormatPreseed, Template: "t={{ .EnrollToken }} f={{ .EnrollTokenFile }}"}
	out, err := NewProfileRenderer().Render(context.Background(), p,
		ProfileVars{EnrollToken: "abc", EnrollTokenFile: "/root/.cfgms-regtoken"}, newInlineStore())
	require.NoError(t, err)
	assert.Equal(t, "t=abc f=/root/.cfgms-regtoken", string(out))

	_, err = NewProfileRenderer().Render(context.Background(), p,
		ProfileVars{EnrollToken: "abc", EnrollTokenFile: "/root/x\ny"}, newInlineStore())
	require.Error(t, err, "control characters in EnrollTokenFile must be rejected")
}
