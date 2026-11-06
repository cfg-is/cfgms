// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"reflect"
	"testing"
)

func TestMergeControllerTags(t *testing.T) {
	t.Run("empty ctrlTags returns the same map", func(t *testing.T) {
		attrs := map[string]string{"tags": "a,b", "os": "linux"}
		got := MergeControllerTags(attrs, nil)
		got["probe"] = "x"
		if attrs["probe"] != "x" {
			t.Fatal("expected the same map to be returned when ctrlTags is empty")
		}
		delete(attrs, "probe")
		if got2 := MergeControllerTags(attrs, []string{}); !reflect.DeepEqual(got2, attrs) {
			t.Fatalf("got %v, want %v", got2, attrs)
		}
	})

	t.Run("DNA tags come before controller tags", func(t *testing.T) {
		got := MergeControllerTags(map[string]string{"tags": "dna1,dna2"}, []string{"ctrl1", "ctrl2"})
		if want := "dna1,dna2,ctrl1,ctrl2"; got["tags"] != want {
			t.Fatalf("tags = %q, want %q", got["tags"], want)
		}
	})

	t.Run("empty and duplicate tags are dropped", func(t *testing.T) {
		got := MergeControllerTags(map[string]string{"tags": "a,,b,a"}, []string{"b", "", "c", "c"})
		if want := "a,b,c"; got["tags"] != want {
			t.Fatalf("tags = %q, want %q", got["tags"], want)
		}
	})

	t.Run("whitespace is trimmed", func(t *testing.T) {
		got := MergeControllerTags(map[string]string{"tags": " a , b "}, []string{"  b", " c  ", "   "})
		if want := "a,b,c"; got["tags"] != want {
			t.Fatalf("tags = %q, want %q", got["tags"], want)
		}
	})

	t.Run("missing tags key uses controller tags only", func(t *testing.T) {
		got := MergeControllerTags(map[string]string{"os": "linux"}, []string{"x"})
		if got["tags"] != "x" || got["os"] != "linux" {
			t.Fatalf("unexpected result %v", got)
		}
	})

	t.Run("input map is not mutated", func(t *testing.T) {
		attrs := map[string]string{"tags": "a", "os": "linux"}
		got := MergeControllerTags(attrs, []string{"b"})
		if attrs["tags"] != "a" || len(attrs) != 2 {
			t.Fatalf("input mutated: %v", attrs)
		}
		if got["tags"] != "a,b" {
			t.Fatalf("tags = %q", got["tags"])
		}
	})
}
