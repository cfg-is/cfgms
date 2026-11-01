// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package analyzer

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHalsteadHandCounted(t *testing.T) {
	// Body: x := f(a, a); return x
	// operators: := () , return -> n1=4 N1=4 ; operands: x f a a x -> n2=3 N2=5
	fns := analyzeSrc(t, "a.go", "package a\n\nfunc F() int {\n\tx := f(a, a)\n\treturn x\n}\n")
	require.Len(t, fns, 1)
	fn := fns[0]
	assert.Equal(t, 4, fn.DistinctOperators)
	assert.Equal(t, 3, fn.DistinctOperands)
	assert.Equal(t, 4, fn.TotalOperators)
	assert.Equal(t, 5, fn.TotalOperands)
	assert.Equal(t, 9*math.Log2(7), fn.Volume)
	assert.Equal(t, 2.0*5.0/3.0, fn.Difficulty)
	assert.Equal(t, fn.Difficulty*fn.Volume, fn.Effort)
}

func TestHalsteadEdgeTokens(t *testing.T) {
	// Body: return a + 1 -> operators return + ; operands a 1
	fns := analyzeSrc(t, "a.go", "package a\n\nfunc F(a int) int { return a + 1 } // c\n")
	fn := fns[0]
	assert.Equal(t, 2, fn.TotalOperators)
	assert.Equal(t, 2, fn.TotalOperands)
	assert.Equal(t, 8.0, fn.Volume)
	assert.Equal(t, 1.0, fn.Difficulty)
	assert.Equal(t, 8.0, fn.Effort)

	// Brackets count once at the opener; explicit ; counts; comments do not.
	fns = analyzeSrc(t, "b.go", "package a\n\nfunc G() { a[0] = 1; /* x */ }\n")
	fn = fns[0]
	assert.Equal(t, 3, fn.DistinctOperators) // [] = ;
	assert.Equal(t, 3, fn.TotalOperators)
	assert.Equal(t, 3, fn.TotalOperands) // a 0 1
}

func TestHalsteadEmptyBodyIsZeroNotNaN(t *testing.T) {
	fns := analyzeSrc(t, "a.go", "package a\n\nfunc F() {}\n")
	fn := fns[0]
	for _, v := range []float64{fn.Volume, fn.Difficulty, fn.Effort} {
		assert.Equal(t, 0.0, v)
		assert.False(t, math.IsNaN(v) || math.IsInf(v, 0))
	}
	assert.Zero(t, fn.TotalOperators+fn.TotalOperands+fn.DistinctOperators+fn.DistinctOperands)
}

func TestHalsteadMetricsGuards(t *testing.T) {
	v, d, e := halsteadMetrics(0, 0, 0, 0)
	assert.Equal(t, [3]float64{0, 0, 0}, [3]float64{v, d, e})
	v, d, e = halsteadMetrics(2, 0, 3, 0) // n2 == 0
	assert.Equal(t, 3.0, v)
	assert.Equal(t, 0.0, d)
	assert.Equal(t, 0.0, e)
}
