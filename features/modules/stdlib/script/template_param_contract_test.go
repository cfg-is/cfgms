// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// templateParamContractFiles are the in-repo bash script templates, relative to
// the repository root. They are copied as the starting point for new modules, so
// whatever parameter-passing shape they carry propagates by design.
var templateParamContractFiles = []string{
	"templates/scripts/backup/config-backup.yaml",
	"templates/scripts/system/log-rotation.yaml",
}

// stripTemplateCommentLines removes whole-line shell comments so an assertion
// about the script's executable text is not satisfied (or tripped) by a comment
// that merely names a variable or an argument shape.
func stripTemplateCommentLines(content string) string {
	lines := strings.Split(content, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// stripTemplateFunctionBodies removes shell function definitions from the script
// body. `$1` inside a function is that function's own argument — a local calling
// convention with nothing to do with the script's argv — whereas `$1` at the top
// level reads the process's own positional arguments, which the executor never
// supplies. Only the latter is a defect, so the positional-argument assertion is
// scoped to top-level text.
//
// Definitions are recognised as `name() {` opening a block that a line
// consisting solely of `}` closes, which is the shape both templates use; a
// function written any other way would keep its body in the checked text (fail
// closed) rather than silently escaping the assertion.
func stripTemplateFunctionBodies(content string) string {
	openFn := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\(\)[[:space:]]*\{[[:space:]]*$`)
	lines := strings.Split(content, "\n")
	kept := make([]string, 0, len(lines))
	inFunction := false
	for _, line := range lines {
		if inFunction {
			if strings.TrimSpace(line) == "}" {
				inFunction = false
			}
			continue
		}
		if openFn.MatchString(strings.TrimSpace(line)) {
			inFunction = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// TestScriptTemplatesReadParamsFromEnvOnly pins the two bash templates to the
// parameter contract the executor actually implements (Issue #4343).
//
// Executor.Execute resolves every parameter and injects it into cmd.Env for the
// child process alone — deliberately, to keep values out of /proc/<pid>/cmdline,
// ps output and Windows event 4688 — and buildCommand execs
// `<interpreter> <scriptPath>` with no positional arguments, ever. Two distinct
// regressions follow from a template that ignores this, and both are asserted
// here:
//
//   - reading $1/$2 at the top level is permanently broken on the real execution
//     path, because no positional argument is ever passed;
//   - a bare `$PARAM_NAME` token in the script text is the shape a
//     text-substituting caller (ParameterInjector.InjectParameters) replaces with
//     the parameter value before execution, turning an attacker-controlled value
//     into literal shell source.
//
// The expected environment variable names come from the real
// ParamEnvVarName/SecretEnvVarName functions rather than being hardcoded, so a
// change to either naming scheme surfaces here as a template that no longer
// matches its own executor.
func TestScriptTemplatesReadParamsFromEnvOnly(t *testing.T) {
	// The templates live outside this package; four levels up from
	// features/modules/stdlib/script is the repository root.
	repoRoot := filepath.Join("..", "..", "..", "..")

	positionalArg := regexp.MustCompile(`\$\{?[1-9]`)

	for _, rel := range templateParamContractFiles {
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(repoRoot, filepath.FromSlash(rel))
			data, err := os.ReadFile(path) // #nosec G304 -- fixed in-repo template path, not caller-supplied
			require.NoError(t, err, "template %s must exist", rel)

			var script VersionedScript
			require.NoError(t, yaml.Unmarshal(data, &script), "template %s must parse as a VersionedScript", rel)
			require.NotNil(t, script.Metadata, "template %s declares no metadata", rel)
			require.Equal(t, ShellBash, script.Metadata.Shell,
				"this contract test covers bash templates; %s declares another shell", rel)
			require.NotEmpty(t, script.Metadata.Parameters, "template %s declares no parameters", rel)

			body := stripTemplateCommentLines(script.Content)

			require.NotRegexp(t, positionalArg, stripTemplateFunctionBodies(body),
				"%s reads a positional argument at the top level, but the executor never passes one "+
					"(parameters are injected into cmd.Env) — the template would always fail", rel)

			for _, param := range script.Metadata.Parameters {
				literalVar := ParamEnvVarName(ShellBash, param.Name)
				secretVar := SecretEnvVarName(ShellBash, param.Name)

				// Braced reference required: the brace is what stops a
				// text-substituting caller from matching a bare $NAME token.
				literalRead := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(literalVar) + `[:}]`)
				secretRead := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(secretVar) + `[:}]`)

				require.Regexp(t, literalRead, body,
					"%s must read parameter %q from the environment as ${%s} (literal binding)",
					rel, param.Name, literalVar)
				require.Regexp(t, secretRead, body,
					"%s must read parameter %q from the environment as ${%s} (secret-store binding on bash)",
					rel, param.Name, secretVar)
				require.NotContains(t, body, "$"+strings.ToUpper(param.Name),
					"%s contains a bare $%s token: a text-substituting caller replaces that with the "+
						"parameter value, making an attacker-controlled value literal shell source",
					rel, strings.ToUpper(param.Name))
			}
		})
	}
}
