// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package operatorroster

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildManifestURL_ValidBase(t *testing.T) {
	got, err := BuildManifestURL("https://controller.example:9443")
	require.NoError(t, err)
	assert.Equal(t, "https://controller.example:9443"+ManifestPath, got)
}

func TestBuildManifestURL_TrimsTrailingSlash(t *testing.T) {
	got, err := BuildManifestURL("https://controller.example:9443/")
	require.NoError(t, err)
	assert.Equal(t, "https://controller.example:9443"+ManifestPath, got)
}

func TestBuildManifestURL_EmptyBase_Errors(t *testing.T) {
	_, err := BuildManifestURL("")
	assert.Error(t, err)
}

func TestBuildManifestURL_NonHTTPS_Errors(t *testing.T) {
	_, err := BuildManifestURL("http://controller.example:9080")
	assert.Error(t, err)
}

func TestBuildManifestURL_Unparsable_Errors(t *testing.T) {
	_, err := BuildManifestURL("://not-a-url")
	assert.Error(t, err)
}

func TestBuildManifestURL_DropsQueryAndFragment(t *testing.T) {
	got, err := BuildManifestURL("https://controller.example:9443/legacy-path?foo=bar#frag")
	require.NoError(t, err)
	assert.Equal(t, "https://controller.example:9443/legacy-path"+ManifestPath, got)
}
