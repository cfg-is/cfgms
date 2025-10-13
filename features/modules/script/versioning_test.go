package script

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    *Version
		wantErr bool
	}{
		{
			name:    "simple version",
			version: "1.2.3",
			want:    &Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:    "version with v prefix",
			version: "v2.0.0",
			want:    &Version{Major: 2, Minor: 0, Patch: 0},
		},
		{
			name:    "version with prerelease",
			version: "1.0.0-alpha.1",
			want:    &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha.1"},
		},
		{
			name:    "version with build metadata",
			version: "1.0.0+20230101",
			want:    &Version{Major: 1, Minor: 0, Patch: 0, BuildMeta: "20230101"},
		},
		{
			name:    "version with prerelease and build metadata",
			version: "1.0.0-beta.2+exp.sha.5114f85",
			want:    &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta.2", BuildMeta: "exp.sha.5114f85"},
		},
		{
			name:    "invalid version",
			version: "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		v1   *Version
		v2   *Version
		want int
	}{
		{
			name: "equal versions",
			v1:   &Version{Major: 1, Minor: 0, Patch: 0},
			v2:   &Version{Major: 1, Minor: 0, Patch: 0},
			want: 0,
		},
		{
			name: "v1 greater major",
			v1:   &Version{Major: 2, Minor: 0, Patch: 0},
			v2:   &Version{Major: 1, Minor: 0, Patch: 0},
			want: 1,
		},
		{
			name: "v1 greater minor",
			v1:   &Version{Major: 1, Minor: 1, Patch: 0},
			v2:   &Version{Major: 1, Minor: 0, Patch: 0},
			want: 1,
		},
		{
			name: "v1 greater patch",
			v1:   &Version{Major: 1, Minor: 0, Patch: 1},
			v2:   &Version{Major: 1, Minor: 0, Patch: 0},
			want: 1,
		},
		{
			name: "release greater than prerelease",
			v1:   &Version{Major: 1, Minor: 0, Patch: 0},
			v2:   &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.v1.Compare(tt.v2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVersionIsCompatibleWith(t *testing.T) {
	tests := []struct {
		name     string
		version  *Version
		required *Version
		want     bool
	}{
		{
			name:     "same version",
			version:  &Version{Major: 1, Minor: 0, Patch: 0},
			required: &Version{Major: 1, Minor: 0, Patch: 0},
			want:     true,
		},
		{
			name:     "higher minor version",
			version:  &Version{Major: 1, Minor: 2, Patch: 0},
			required: &Version{Major: 1, Minor: 0, Patch: 0},
			want:     true,
		},
		{
			name:     "different major version",
			version:  &Version{Major: 2, Minor: 0, Patch: 0},
			required: &Version{Major: 1, Minor: 0, Patch: 0},
			want:     false,
		},
		{
			name:     "lower version",
			version:  &Version{Major: 1, Minor: 0, Patch: 0},
			required: &Version{Major: 1, Minor: 1, Patch: 0},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.version.IsCompatibleWith(tt.required)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScriptMetadataValidate(t *testing.T) {
	tests := []struct {
		name     string
		metadata *ScriptMetadata
		wantErr  bool
	}{
		{
			name: "valid metadata",
			metadata: &ScriptMetadata{
				ID:       "test-script",
				Name:     "Test Script",
				Version:  &Version{Major: 1, Minor: 0, Patch: 0},
				Shell:    ShellBash,
				Platform: []string{"linux"},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			metadata: &ScriptMetadata{
				Name:     "Test Script",
				Version:  &Version{Major: 1, Minor: 0, Patch: 0},
				Shell:    ShellBash,
				Platform: []string{"linux"},
			},
			wantErr: true,
		},
		{
			name: "missing shell",
			metadata: &ScriptMetadata{
				ID:       "test-script",
				Name:     "Test Script",
				Version:  &Version{Major: 1, Minor: 0, Patch: 0},
				Platform: []string{"linux"},
			},
			wantErr: true,
		},
		{
			name: "invalid platform",
			metadata: &ScriptMetadata{
				ID:       "test-script",
				Name:     "Test Script",
				Version:  &Version{Major: 1, Minor: 0, Patch: 0},
				Shell:    ShellBash,
				Platform: []string{"invalid"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.metadata.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScriptMetadataClone(t *testing.T) {
	original := &ScriptMetadata{
		ID:          "test-script",
		Name:        "Test Script",
		Description: "Original description",
		Version:     &Version{Major: 1, Minor: 0, Patch: 0},
		Author:      "test@example.com",
		Tags:        []string{"tag1", "tag2"},
		Category:    "testing",
		Platform:    []string{"linux", "darwin"},
		Shell:       ShellBash,
		Parameters: []ScriptParameter{
			{Name: "param1", Type: "string", Required: true},
		},
		CreatedAt: time.Now().Add(-24 * time.Hour),
		UpdatedAt: time.Now().Add(-1 * time.Hour),
	}

	newVersion := &Version{Major: 1, Minor: 1, Patch: 0}
	clone := original.Clone(newVersion)

	assert.Equal(t, original.ID, clone.ID)
	assert.Equal(t, original.Name, clone.Name)
	assert.Equal(t, newVersion, clone.Version)
	assert.Equal(t, original.CreatedAt, clone.CreatedAt)
	assert.True(t, clone.UpdatedAt.After(original.UpdatedAt))
	assert.Equal(t, original.Tags, clone.Tags)
	assert.Equal(t, original.Platform, clone.Platform)

	// Ensure deep copy (modifying clone doesn't affect original)
	clone.Tags[0] = "modified"
	assert.NotEqual(t, original.Tags[0], clone.Tags[0])
}
