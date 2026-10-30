// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityDistinctInits(t *testing.T) {
	fsys := fstest.MapFS{
		"p/a.go": {Data: []byte("package p\n\nfunc init() {}\n\nfunc init() {}\n")},
		"p/b.go": {Data: []byte("package p\n\nfunc init() {}\n")},
	}
	fns, err := Analyze(fsys, []string{"."})
	require.NoError(t, err)
	require.Len(t, fns, 3)
	ids := map[string]bool{}
	for _, fn := range fns {
		ids[fn.Identity] = true
	}
	assert.Len(t, ids, 3)
	assert.True(t, ids["p/a.go::.init#0"] && ids["p/a.go::.init#1"] && ids["p/b.go::.init#0"])
}

func TestIdentityPerBuildVariantFile(t *testing.T) {
	const src = "package p\n\nfunc F() {}\n"
	fsys := fstest.MapFS{"p/x_windows.go": {Data: []byte(src)}, "p/x_linux.go": {Data: []byte(src)}}
	fns, err := Analyze(fsys, []string{"."})
	require.NoError(t, err)
	require.Len(t, fns, 2)
	assert.NotEqual(t, fns[0].Identity, fns[1].Identity)
}

func TestIdentityStableUnderMoveButNotEarlierInsert(t *testing.T) {
	base := analyzeSrc(t, "a.go", "package p\n\nfunc init() {}\n\nfunc F() {}\n")
	moved := analyzeSrc(t, "a.go", "package p\n\n\n\n\nfunc init() {}\n\nfunc F() {}\n")
	require.Len(t, base, 2)
	assert.Equal(t, base[0].Identity, moved[0].Identity)
	assert.Equal(t, base[1].Identity, moved[1].Identity)
	assert.NotEqual(t, base[0].Line, moved[0].Line)

	// Recorded limitation: an earlier init() shifts the later one's ordinal.
	inserted := analyzeSrc(t, "a.go", "package p\n\nfunc init() {}\n\nfunc init() {}\n")
	require.Len(t, inserted, 2)
	assert.Equal(t, "a.go::.init#0", inserted[0].Identity)
	assert.Equal(t, "a.go::.init#1", inserted[1].Identity)
}

func TestReceiverNameStripsPointerAndTypeParams(t *testing.T) {
	src := "package p\n\ntype Set[T any] struct{}\n\nfunc (s *Set[T]) Add(v T) {}\n\nfunc (s Set[T]) Len() int { return 0 }\n\nfunc (m *M2[K, V]) Get() {}\n"
	fns := analyzeSrc(t, "a.go", src)
	require.Len(t, fns, 3)
	byName := map[string]Function{}
	for _, fn := range fns {
		byName[fn.Name] = fn
	}
	assert.Equal(t, "Set", byName["Add"].Recv)
	assert.Equal(t, "Set", byName["Len"].Recv)
	assert.Equal(t, "M2", byName["Get"].Recv)
	assert.Equal(t, "a.go::Set.Add#0", byName["Add"].Identity)
}

func TestBuildConstraintBothMechanisms(t *testing.T) {
	fsys := fstest.MapFS{
		"p/a_tagged.go":      {Data: []byte("//go:build windows\n\npackage p\n\nfunc F() {}\n")},
		"p/b_windows.go":     {Data: []byte("package p\n\nfunc G() {}\n")},
		"p/c_linux_arm64.go": {Data: []byte("package p\n\nfunc H() {}\n")},
		"p/d_both_linux.go":  {Data: []byte("//go:build !cgo\n\npackage p\n\nfunc I() {}\n")},
		"p/e.go":             {Data: []byte("package p\n\nfunc J() {}\n")},
	}
	fns, err := Analyze(fsys, []string{"."})
	require.NoError(t, err)
	got := map[string]string{}
	for _, fn := range fns {
		got[fn.Name] = fn.BuildConstraint
	}
	assert.Equal(t, map[string]string{
		"F": "windows", "G": "windows", "H": "linux && arm64", "I": "!cgo && linux", "J": "",
	}, got)
}

func TestCheckDuplicatesNamesBothLocations(t *testing.T) {
	err := checkDuplicates([]Function{
		{Identity: "a.go::.F#0", File: "a.go", Line: 3},
		{Identity: "b.go::.G#0", File: "b.go", Line: 1},
		{Identity: "a.go::.F#0", File: "a.go", Line: 9},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a.go:3")
	assert.Contains(t, err.Error(), "a.go:9")
	assert.NoError(t, checkDuplicates([]Function{{Identity: "x"}, {Identity: "y"}}))
}

func TestAnalyzeOverlappingRootsIsDuplicateError(t *testing.T) {
	fsys := fstest.MapFS{"pkg/x/f.go": {Data: []byte("package x\n\nfunc F() {}\n")}}
	_, err := Analyze(fsys, []string{"pkg", "pkg/x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkg/x/f.go:3")
}
