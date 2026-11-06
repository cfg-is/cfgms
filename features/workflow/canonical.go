// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// canonicalWorkflowPrefix is the versioned prefix field of the canonical form. Any
// change to the encoding below must bump the version so old and new bytes can never
// be confused.
const canonicalWorkflowPrefix = "cfgms-workflow-version/v1\n"

// canonicalExcludedFields lists the VersionedWorkflow fields that are not part of the
// canonical form because they change without changing behavior. Every other field,
// including any field added to Workflow, Step or a type reachable from them, is
// covered automatically. canonical_test.go fails when this list goes stale.
var canonicalExcludedFields = map[string]bool{
	"VersionedWorkflow.VersionTags":     true,
	"VersionedWorkflow.Deprecated":      true,
	"VersionedWorkflow.DeprecationNote": true,
	"VersionedWorkflow.Changelog":       true,
}

// CanonicalWorkflowBytes returns the deterministic byte form of a workflow version:
// the embedded Workflow definition and the semantic version. Struct fields are emitted
// in sorted key order, map keys are sorted, and zero-valued fields are omitted, so the
// bytes are identical across processes and map iteration orders.
func CanonicalWorkflowBytes(vw *VersionedWorkflow) ([]byte, error) {
	if vw == nil {
		return nil, errors.New("workflow version is nil")
	}
	var sb strings.Builder
	sb.WriteString(canonicalWorkflowPrefix)
	if err := canonicalEncode(&sb, reflect.ValueOf(*vw), "", 0); err != nil {
		return nil, fmt.Errorf("canonical workflow encoding: %w", err)
	}
	return []byte(sb.String()), nil
}

// CanonicalWorkflowHash returns the lowercase hex SHA-256 of CanonicalWorkflowBytes.
func CanonicalWorkflowHash(vw *VersionedWorkflow) (string, error) {
	b, err := CanonicalWorkflowBytes(vw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

const canonicalMaxDepth = 256

type canonicalField struct {
	key string
	val reflect.Value
}

func canonicalEncode(sb *strings.Builder, v reflect.Value, path string, depth int) error {
	if depth > canonicalMaxDepth {
		return errors.New("value nesting too deep")
	}
	if canonicalScalar(sb, v) {
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		return canonicalString(sb, v.String())
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			sb.WriteString("null")
			return nil
		}
		return canonicalEncode(sb, v.Elem(), path, depth+1)
	case reflect.Slice, reflect.Array:
		return canonicalSlice(sb, v, path, depth)
	case reflect.Map:
		return canonicalMap(sb, v, path, depth)
	case reflect.Struct:
		return canonicalStruct(sb, v, path, depth)
	default:
		return fmt.Errorf("unsupported kind %s at %q", v.Kind(), path)
	}
}

// canonicalScalar writes v when it is null, a bool or a number and reports whether
// it did so.
func canonicalScalar(sb *strings.Builder, v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Invalid:
		sb.WriteString("null")
	case reflect.Bool:
		sb.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sb.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		sb.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		sb.WriteString(strconv.FormatFloat(v.Float(), 'g', -1, 64))
	default:
		return false
	}
	return true
}

func canonicalSlice(sb *strings.Builder, v reflect.Value, path string, depth int) error {
	sb.WriteByte('[')
	for i := 0; i < v.Len(); i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		if err := canonicalEncode(sb, v.Index(i), path, depth+1); err != nil {
			return err
		}
	}
	sb.WriteByte(']')
	return nil
}

func canonicalString(sb *strings.Builder, s string) error {
	// json.Marshal would rewrite invalid UTF-8 to U+FFFD, making the encoding many-to-one.
	if !utf8.ValidString(s) {
		return errors.New("string is not valid UTF-8")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	sb.Write(b)
	return nil
}

func canonicalMap(sb *strings.Builder, v reflect.Value, path string, depth int) error {
	entries := make([]canonicalField, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		k := iter.Key()
		for k.Kind() == reflect.Interface && !k.IsNil() {
			k = k.Elem()
		}
		if k.Kind() != reflect.String {
			return fmt.Errorf("unsupported map key kind %s at %q", k.Kind(), path)
		}
		entries = append(entries, canonicalField{key: k.String(), val: iter.Value()})
	}
	return canonicalObject(sb, entries, path, depth)
}

func canonicalStruct(sb *strings.Builder, v reflect.Value, path string, depth int) error {
	t := v.Type()
	fields := make([]canonicalField, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if canonicalExcludedFields[t.Name()+"."+sf.Name] {
			continue
		}
		if !sf.IsExported() {
			return fmt.Errorf("unexported field %s.%s cannot be canonicalized", t.Name(), sf.Name)
		}
		fv := v.Field(i)
		if key, ok := canonicalStructFieldKey(sf, fv); ok {
			fields = append(fields, canonicalField{key: key, val: fv})
		}
	}
	return canonicalObject(sb, fields, path, depth)
}

// canonicalStructFieldKey returns the object key for a struct field and whether the
// field is emitted at all.
func canonicalStructFieldKey(sf reflect.StructField, fv reflect.Value) (string, bool) {
	if sf.Anonymous && fv.Kind() == reflect.Struct {
		// An embedded struct is flattened under its own type name so the
		// definition and its wrapper stay distinguishable.
		return sf.Name, true
	}
	if canonicalOmitted(fv) {
		return "", false
	}
	if tag := strings.Split(sf.Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
		return tag, true
	}
	return sf.Name, true
}

// canonicalOmitted reports whether a non-struct field is zero-valued or an empty
// slice or map, and so left out of the canonical form.
func canonicalOmitted(fv reflect.Value) bool {
	if fv.Kind() == reflect.Struct {
		return false
	}
	if fv.IsZero() {
		return true
	}
	return (fv.Kind() == reflect.Slice || fv.Kind() == reflect.Map) && fv.Len() == 0
}

// canonicalObject sorts fields by key and writes them as a JSON object.
func canonicalObject(sb *strings.Builder, fields []canonicalField, path string, depth int) error {
	sort.Slice(fields, func(i, j int) bool { return fields[i].key < fields[j].key })
	sb.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			sb.WriteByte(',')
		}
		if err := canonicalString(sb, f.key); err != nil {
			return err
		}
		sb.WriteByte(':')
		if err := canonicalEncode(sb, f.val, path+"."+f.key, depth+1); err != nil {
			return err
		}
	}
	sb.WriteByte('}')
	return nil
}
