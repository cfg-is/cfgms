// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

func TestNewOperatorOrigin_CarriesPrincipal(t *testing.T) {
	ctx := commands.NewOperatorOrigin(context.Background(), "alice")
	got, ok := commands.OperatorOrigin(ctx)
	require.True(t, ok)
	assert.Equal(t, "alice", got)

	viaProvider, ok := interfaces.OperatorOriginFrom(ctx)
	require.True(t, ok)
	assert.Equal(t, "alice", viaProvider)
}

func TestNewOperatorOrigin_NoPrincipalNoMarker(t *testing.T) {
	_, ok := commands.OperatorOrigin(commands.NewOperatorOrigin(context.Background(), ""))
	assert.False(t, ok)
	_, ok = commands.OperatorOrigin(context.Background())
	assert.False(t, ok)
}

// repoRoot is the module root relative to this package.
const repoRoot = "../../.."

// callersOf returns the repo-relative path of every non-test Go file under
// cmd/, features/ and pkg/ that calls a function or method named one of names.
func callersOf(t *testing.T, names ...string) []string {
	t.Helper()
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	found := map[string]bool{}
	for _, top := range []string{"cmd", "features", "pkg"} {
		root := filepath.Join(repoRoot, top)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				case *ast.Ident:
					name = fn.Name
				}
				if want[name] {
					rel, _ := filepath.Rel(repoRoot, path)
					found[filepath.ToSlash(rel)] = true
				}
				return true
			})
			return nil
		})
		require.NoError(t, err)
	}
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// A new non-test caller of SendCommand/FanOutCommand fails here until it is
// classified: it must sit behind the gate (every control-plane provider's own
// SendCommand/FanOutCommand gates) and be named below with how it is origin-marked.
func TestInventory_SendCommandFanOutCommandCallers(t *testing.T) {
	assert.Equal(t, []string{
		"features/controller/api/relay_handler.go",            // relay_response; origin from the dispatcher's open operator execution
		"features/controller/commands/publisher.go",           // Publisher: never creates the marker
		"features/controller/dispatcher/dispatcher.go",        // execute_script / steward_action; operator marker only for operator-created runs
		"pkg/controlplane/internaldelivery/cluster_sender.go", // forwards the context's marker to the peer
		"pkg/controlplane/internaldelivery/server.go",         // receiving node; marker restored only from an authenticated peer
	}, callersOf(t, "SendCommand", "FanOutCommand"))
}

func TestInventory_NewOperatorOriginCallers(t *testing.T) {
	assert.Equal(t, []string{
		"features/controller/dispatcher/dispatcher.go",
		"features/controller/transport/terminal_handler.go",
	}, callersOf(t, "NewOperatorOrigin"))
}

// The storage primitive behind the constructor has exactly two callers: the
// constructor itself and the peer-authenticated restore on the receiving node.
func TestInventory_WithOperatorOriginCallers(t *testing.T) {
	assert.Equal(t, []string{
		"features/controller/commands/operator_origin.go",
		"pkg/controlplane/internaldelivery/server.go",
	}, callersOf(t, "WithOperatorOrigin"))
}

// Publisher methods and the signer variants never create the marker.
func TestInventory_PublisherNeverCreatesOperatorOrigin(t *testing.T) {
	for _, f := range callersOf(t, "NewOperatorOrigin", "WithOperatorOrigin") {
		assert.NotEqual(t, "features/controller/commands/publisher.go", f)
	}
}
