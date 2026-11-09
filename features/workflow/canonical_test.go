// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package workflow

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateCanonicalGolden = flag.Bool("update-canonical-golden", false, "rewrite the canonical workflow golden file")

func sampleVersionedWorkflow() *VersionedWorkflow {
	return &VersionedWorkflow{
		Workflow: Workflow{
			Name:        "sample",
			Description: "sample workflow",
			Version:     "1.2.3",
			Variables:   map[string]interface{}{"zeta": 1, "alpha": "a", "mid": map[string]interface{}{"b": true, "a": []interface{}{"x", 2.5}}},
			Inputs:      []InputSpec{{Name: "region", Type: "string", Required: true, Default: "eu", Options: []string{"eu", "us"}}},
			Timeout:     time.Minute,
			OnFailure:   ActionStop,
			Steps: []Step{
				{
					Name:      "check",
					ID:        "s1",
					Type:      StepTypeTask,
					Module:    "file",
					Config:    map[string]interface{}{"path": "/etc/app.conf", "mode": "0644", "content": "x"},
					Condition: &Condition{Type: ConditionTypeVariable, Variable: "region", Operator: OperatorEqual, Value: "eu"},
					Timeout:   30 * time.Second,
					OnFailure: ActionContinue,
				},
				{
					Name: "fetch",
					Type: StepTypeHTTP,
					HTTP: &HTTPConfig{URL: "https://example.com/hook", Method: "POST", Headers: map[string]string{"B": "2", "A": "1"}, ExpectedStatus: []int{200, 204}},
				},
				{
					Name:  "group",
					Type:  StepTypeSequential,
					Steps: []Step{{Name: "inner", Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Second}}},
				},
			},
		},
		SemanticVersion: SemanticVersion{Major: 1, Minor: 2, Patch: 3},
	}
}

func mustHash(t *testing.T, vw *VersionedWorkflow) string {
	t.Helper()
	h, err := CanonicalWorkflowHash(vw)
	require.NoError(t, err)
	return h
}

func TestCanonicalWorkflowBytes_Deterministic(t *testing.T) {
	first, err := CanonicalWorkflowBytes(sampleVersionedWorkflow())
	require.NoError(t, err)
	for i := 0; i < 50; i++ {
		// Rebuilding the maps each iteration varies their internal iteration order.
		again, err := CanonicalWorkflowBytes(sampleVersionedWorkflow())
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}
	assert.True(t, strings.HasPrefix(string(first), canonicalWorkflowPrefix))

	h1 := mustHash(t, sampleVersionedWorkflow())
	assert.Len(t, h1, 64)
	assert.Equal(t, h1, mustHash(t, sampleVersionedWorkflow()))
}

func TestCanonicalWorkflowBytes_MapInsertionOrderIrrelevant(t *testing.T) {
	keys := []string{"k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9"}
	build := func(order []int) *VersionedWorkflow {
		vw := sampleVersionedWorkflow()
		m := map[string]interface{}{}
		for _, i := range order {
			m[keys[i]] = i
		}
		vw.Steps[0].Config = m
		return vw
	}
	forward := make([]int, len(keys))
	reverse := make([]int, len(keys))
	for i := range keys {
		forward[i] = i
		reverse[i] = len(keys) - 1 - i
	}
	assert.Equal(t, mustHash(t, build(forward)), mustHash(t, build(reverse)))
}

func TestCanonicalWorkflowBytes_NilAndErrors(t *testing.T) {
	_, err := CanonicalWorkflowBytes(nil)
	require.Error(t, err)
	_, err = CanonicalWorkflowHash(nil)
	require.Error(t, err)

	vw := sampleVersionedWorkflow()
	vw.Steps[0].Config = map[string]interface{}{"bad": func() {}}
	_, err = CanonicalWorkflowBytes(vw)
	require.Error(t, err)
}

func TestCanonicalWorkflowBytes_TypeDistinctions(t *testing.T) {
	a := sampleVersionedWorkflow()
	b := sampleVersionedWorkflow()
	a.Steps[0].Config = map[string]interface{}{"v": "1"}
	b.Steps[0].Config = map[string]interface{}{"v": 1}
	assert.NotEqual(t, mustHash(t, a), mustHash(t, b))
}

func TestCanonicalWorkflowHash_NonExecutableFieldsExcluded(t *testing.T) {
	base := mustHash(t, sampleVersionedWorkflow())
	vw := sampleVersionedWorkflow()
	vw.Deprecated = true
	vw.DeprecationNote = "use v2"
	vw.VersionTags = []string{"stable"}
	vw.Changelog = []ChangelogEntry{{Version: SemanticVersion{Major: 1}, Description: "d", Changes: []Change{{Type: ChangeTypeAdded, Description: "x"}}}}
	assert.Equal(t, base, mustHash(t, vw))
}

func TestCanonicalWorkflowHash_SemanticVersionCovered(t *testing.T) {
	base := mustHash(t, sampleVersionedWorkflow())
	vw := sampleVersionedWorkflow()
	vw.SemanticVersion.Patch++
	assert.NotEqual(t, base, mustHash(t, vw))
}

// --- reflection coverage test ---------------------------------------------------

// fillValue populates every field of v. A struct type is entered at most twice along
// one path so recursive types (Step, Condition) terminate.
func fillValue(v reflect.Value, seen map[reflect.Type]int) {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.String:
		v.SetString("v")
	case reflect.Interface:
		v.Set(reflect.ValueOf("iface"))
	case reflect.Pointer:
		if seen[v.Type().Elem()] >= 2 {
			return
		}
		v.Set(reflect.New(v.Type().Elem()))
		fillValue(v.Elem(), seen)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Struct && seen[v.Type().Elem()] >= 2 {
			return
		}
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillValue(s.Index(0), seen)
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		val := reflect.New(v.Type().Elem()).Elem()
		fillValue(val, seen)
		m.SetMapIndex(reflect.ValueOf("k").Convert(v.Type().Key()), val)
		v.Set(m)
	case reflect.Struct:
		t := v.Type()
		seen[t]++
		defer func() { seen[t]-- }()
		if seen[t] > 2 {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				fillValue(v.Field(i), seen)
			}
		}
	}
}

// mutateValue changes v so that its encoding must differ; it reports false for kinds
// it cannot mutate.
func mutateValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(v.Float() + 1)
	case reflect.String:
		v.SetString(v.String() + "-mutated")
	case reflect.Interface:
		v.Set(reflect.ValueOf("mutated-iface"))
	case reflect.Pointer:
		v.Set(reflect.Zero(v.Type()))
	case reflect.Slice:
		elem := reflect.New(v.Type().Elem()).Elem()
		fillValue(elem, map[reflect.Type]int{})
		v.Set(reflect.Append(v, elem))
	case reflect.Map:
		val := reflect.New(v.Type().Elem()).Elem()
		fillValue(val, map[reflect.Type]int{})
		m := reflect.MakeMap(v.Type())
		for _, k := range v.MapKeys() {
			m.SetMapIndex(k, v.MapIndex(k))
		}
		m.SetMapIndex(reflect.ValueOf("mutated-key").Convert(v.Type().Key()), val)
		v.Set(m)
	default:
		return false
	}
	return true
}

type fieldVisit struct {
	covered  map[string]bool // "Type.Field" mutated and changed the hash
	excluded map[string]bool // "Type.Field" mutated and left the hash unchanged
}

func walkMutations(t *testing.T, root *VersionedWorkflow, v reflect.Value, visit *fieldVisit) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			walkMutations(t, root, v.Elem(), visit)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			walkMutations(t, root, v.Index(i), visit)
		}
	case reflect.Struct:
		st := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			name := st.Name() + "." + st.Field(i).Name
			if f.Kind() != reflect.Struct {
				before := mustHash(t, root)
				orig := reflect.New(f.Type()).Elem()
				orig.Set(f)
				require.True(t, mutateValue(f), "cannot mutate %s (%s); teach the test about this kind", name, f.Kind())
				after := mustHash(t, root)
				f.Set(orig)
				if before == after {
					visit.excluded[name] = true
				} else {
					visit.covered[name] = true
				}
			}
			if visit.excluded[name] && !visit.covered[name] {
				// Contents of an excluded field are excluded with it.
				continue
			}
			walkMutations(t, root, f, visit)
		}
	}
}

// reviewedExclusions is the reviewed list of fields whose mutation may leave the hash
// unchanged. Adding a field to Workflow, Step or any type reachable from them either
// changes the hash (and passes) or must be added here deliberately.
var reviewedExclusions = map[string]bool{
	"VersionedWorkflow.VersionTags":     true,
	"VersionedWorkflow.Deprecated":      true,
	"VersionedWorkflow.DeprecationNote": true,
	"VersionedWorkflow.Changelog":       true,
	"VersionedWorkflow.Publication":     true,
	"VersionedWorkflow.Signature":       true,
}

func TestCanonicalWorkflowHash_EveryFieldCovered(t *testing.T) {
	vw := &VersionedWorkflow{}
	fillValue(reflect.ValueOf(vw).Elem(), map[reflect.Type]int{})
	require.NotEmpty(t, vw.Steps)

	visit := &fieldVisit{covered: map[string]bool{}, excluded: map[string]bool{}}
	walkMutations(t, vw, reflect.ValueOf(vw).Elem(), visit)

	for name := range visit.excluded {
		if visit.covered[name] {
			// The same type is reached at several depths; some instances are
			// unpopulated, and only a field that never changes the hash is excluded.
			delete(visit.excluded, name)
			continue
		}
		assert.True(t, reviewedExclusions[name], "field %s does not affect the canonical hash and is not on the reviewed exclusion list", name)
	}
	for name := range reviewedExclusions {
		assert.True(t, visit.excluded[name], "reviewed exclusion %s is stale or no longer excluded", name)
		assert.False(t, visit.covered[name], "reviewed exclusion %s changed the hash", name)
	}
	for _, name := range []string{"Workflow.Name", "Workflow.Steps", "Step.Config", "Step.Steps", "Step.Timeout", "Step.OnFailure", "Workflow.Inputs", "Workflow.Variables"} {
		assert.True(t, visit.covered[name], "expected %s to be walked and covered", name)
	}
}

func TestCanonicalWorkflowBytes_Golden(t *testing.T) {
	got, err := CanonicalWorkflowBytes(sampleVersionedWorkflow())
	require.NoError(t, err)
	path := filepath.Join("testdata", "canonical_workflow.golden")
	if *updateCanonicalGolden {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func TestCanonicalWorkflowBytes_RejectsInvalidUTF8(t *testing.T) {
	vw := sampleVersionedWorkflow()
	vw.Steps[0].Module = "file\xff"
	_, err := CanonicalWorkflowBytes(vw)
	require.Error(t, err)

	vw = sampleVersionedWorkflow()
	vw.Steps[0].Config = map[string]interface{}{"k\xfe": "v"}
	_, err = CanonicalWorkflowBytes(vw)
	require.Error(t, err)
}
