// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #6152: docs/administration/agent-onboarding.md tells an operator which
// cfg commands to run. These tests keep the guide honest: every cfg command in a
// code block resolves in rootCmd with every flag it uses defined (and every
// required flag present), and the guide carries no environment specifics.

const agentOnboardingGuide = "../../../docs/administration/agent-onboarding.md"

// agentGuideVendorDenylist holds real third-party vendor and product names the
// guide must not use as examples (CLAUDE.md: use vendor-a, acme-corp, ...).
var agentGuideVendorDenylist = []string{
	"microsoft", "azure", "entra", "okta", "google", "amazon", "aws", "cloudflare",
	"datto", "connectwise", "kaseya", "ninjaone", "salt", "terraform", "puppet", "ansible",
}

var (
	ipv4LiteralRE     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	localHostnameRE   = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:local|internal)\b`)
	codeFenceRE       = regexp.MustCompile("^\\s*```")
	envAssignmentWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

func readAgentOnboardingGuide(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(agentOnboardingGuide)) // #nosec G304 -- fixed repo doc path
	require.NoError(t, err, "the agent onboarding guide must exist")
	return string(data)
}

// codeBlockLines returns the lines inside fenced code blocks, with a trailing
// backslash continuation joined to the next line.
func codeBlockLines(doc string) []string {
	var out []string
	inBlock := false
	var pending string
	for _, line := range strings.Split(doc, "\n") {
		if codeFenceRE.MatchString(line) {
			inBlock = !inBlock
			pending = ""
			continue
		}
		if !inBlock {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if pending != "" {
			trimmed = pending + " " + trimmed
			pending = ""
		}
		if strings.HasSuffix(trimmed, "\\") {
			pending = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// splitShellWords splits a line into words, honouring single and double quotes.
// An unterminated quote is an error.
func splitShellWords(line string) ([]string, error) {
	var words []string
	var cur strings.Builder
	var quote rune
	started := false
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			if started || cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in %q", line)
	}
	if started || cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words, nil
}

// cfgInvocations extracts every `cfg ...` invocation from the code lines. A
// comment tail is dropped, a pipeline contributes each stage that runs cfg, and
// leading VAR=value words are skipped.
func cfgInvocations(lines []string) ([][]string, error) {
	var out [][]string
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, stage := range strings.Split(line, "|") {
			words, err := splitShellWords(strings.TrimSpace(stage))
			if err != nil {
				return nil, err
			}
			for len(words) > 0 && envAssignmentWord.MatchString(words[0]) {
				words = words[1:]
			}
			if len(words) == 0 || words[0] != "cfg" {
				continue
			}
			args := []string{}
			for _, w := range words[1:] {
				if strings.HasPrefix(w, "#") {
					break
				}
				args = append(args, w)
			}
			out = append(out, args)
		}
	}
	return out, nil
}

func findSubcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, sub := range parent.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return sub
		}
	}
	return nil
}

func lookupFlag(c *cobra.Command, token string) (*pflag.Flag, error) {
	c.InitDefaultHelpFlag()
	name := strings.TrimLeft(token, "-")
	if i := strings.Index(name, "="); i >= 0 {
		name = name[:i]
	}
	if strings.HasPrefix(token, "--") {
		if f := c.Flag(name); f != nil {
			return f, nil
		}
		return nil, fmt.Errorf("flag --%s is not defined on %q", name, c.CommandPath())
	}
	if len(name) == 1 {
		if f := c.Flags().ShorthandLookup(name); f != nil {
			return f, nil
		}
		if f := c.InheritedFlags().ShorthandLookup(name); f != nil {
			return f, nil
		}
	}
	return nil, fmt.Errorf("flag -%s is not defined on %q", name, c.CommandPath())
}

// checkCfgInvocation resolves args (the words after `cfg`) against root: every
// command word must exist, the final command must be runnable, every flag must be
// defined on it and every flag it marks required must be present.
func checkCfgInvocation(root *cobra.Command, args []string) error {
	cur := root
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if strings.HasPrefix(tok, "-") && tok != "-" {
			f, err := lookupFlag(cur, tok)
			if err != nil {
				return err
			}
			seen[f.Name] = true
			if !strings.Contains(tok, "=") && f.NoOptDefVal == "" {
				i++ // the flag takes its value from the next word
			}
			continue
		}
		if cur.HasSubCommands() {
			sub := findSubcommand(cur, tok)
			if sub == nil {
				return fmt.Errorf("%q is not a subcommand of %q", tok, cur.CommandPath())
			}
			cur = sub
		}
	}
	if !cur.Runnable() {
		return fmt.Errorf("%q is a command group, not a runnable command", cur.CommandPath())
	}
	var missing []string
	cur.Flags().VisitAll(func(f *pflag.Flag) {
		if _, required := f.Annotations[cobra.BashCompOneRequiredFlag]; required && !seen[f.Name] {
			missing = append(missing, "--"+f.Name)
		}
	})
	if len(missing) > 0 {
		return fmt.Errorf("%q is missing required flag(s) %s", cur.CommandPath(), strings.Join(missing, ", "))
	}
	return nil
}

// TestAgentOnboardingGuide_EveryCfgCommandExists fails when the guide documents a
// cfg command or flag the CLI does not define.
func TestAgentOnboardingGuide_EveryCfgCommandExists(t *testing.T) {
	invocations, err := cfgInvocations(codeBlockLines(readAgentOnboardingGuide(t)))
	require.NoError(t, err)
	require.NotEmpty(t, invocations, "the guide must show cfg commands in code blocks")

	// The commands the onboarding sequence depends on must all be present.
	var joined []string
	for _, inv := range invocations {
		joined = append(joined, strings.Join(inv, " "))
	}
	all := "\n" + strings.Join(joined, "\n")
	for _, want := range []string{
		"account create", "account software-authenticator", "tenant break-glass",
		"authenticator create", "authenticator enroll", "authenticator list",
		"workflow publish", "module approve", "steward exec",
	} {
		assert.True(t, strings.Contains(all, want), "the guide must show `cfg %s`", want)
	}

	for _, inv := range invocations {
		t.Run(strings.Join(inv, " "), func(t *testing.T) {
			assert.NoError(t, checkCfgInvocation(rootCmd, inv))
		})
	}
}

// TestAgentOnboardingGuide_NoEnvironmentSpecifics keeps test-cell and vendor
// specifics out of the guide.
func TestAgentOnboardingGuide_NoEnvironmentSpecifics(t *testing.T) {
	doc := readAgentOnboardingGuide(t)
	assert.Empty(t, ipv4LiteralRE.FindAllString(doc, -1), "no IPv4 literal")
	assert.Empty(t, localHostnameRE.FindAllString(doc, -1), "no .local or .internal hostname")
	lower := strings.ToLower(doc)
	for _, vendor := range agentGuideVendorDenylist {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(vendor) + `\b`)
		assert.False(t, re.MatchString(lower), "the guide must not name %q", vendor)
	}
}

// TestAgentOnboardingGuide_StatesTheContract pins the statements the story
// requires: startup-only tenant list, the three limits, the root-scope
// exclusion, the bearer-secret handling and the step order.
func TestAgentOnboardingGuide_StatesTheContract(t *testing.T) {
	doc := readAgentOnboardingGuide(t)
	lower := strings.ToLower(doc)

	for _, phrase := range []string{
		"webauthn.allow_software_authenticators.tenants",
		"read at controller startup",
		"controller restart",
		"no `cfg` command writes",
		"self-asserted",
		"not a boundary",
		"not non-exportable",
		"counter is always 0",
		"bearer secret",
		"never argv",
		"root-scope",
		"exact match",
		"inert",
	} {
		assert.True(t, strings.Contains(lower, strings.ToLower(phrase)), "the guide must state %q", phrase)
	}

	// The flag is set before the link is redeemed.
	flagAt := strings.Index(doc, "cfg account software-authenticator")
	enrollAt := strings.Index(doc, "cfg authenticator enroll")
	require.GreaterOrEqual(t, flagAt, 0)
	require.GreaterOrEqual(t, enrollAt, 0)
	assert.Less(t, flagAt, enrollAt, "the account flag must be set before the enrollment link is redeemed")

	// No command line carries the enrollment link as an argument.
	invocations, err := cfgInvocations(codeBlockLines(doc))
	require.NoError(t, err)
	for _, inv := range invocations {
		if len(inv) >= 2 && inv[0] == "authenticator" && inv[1] == "enroll" {
			assert.True(t, containsAny(inv, "--link-file", "--link-stdin"),
				"enroll must read the link from a file or stdin: %v", inv)
		}
	}
}

func containsAny(words []string, wanted ...string) bool {
	for _, w := range words {
		for _, x := range wanted {
			if w == x {
				return true
			}
		}
	}
	return false
}

// TestAgentOnboardingDocChecks_RejectBadInput proves the checkers fail on what
// they exist to catch, so a green run is not vacuous.
func TestAgentOnboardingDocChecks_RejectBadInput(t *testing.T) {
	t.Run("unknown subcommand", func(t *testing.T) {
		assert.Error(t, checkCfgInvocation(rootCmd, []string{"account", "no-such-verb"}))
	})
	t.Run("unknown flag", func(t *testing.T) {
		err := checkCfgInvocation(rootCmd, []string{"authenticator", "list", "--no-such-flag"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--no-such-flag")
	})
	t.Run("missing required flag", func(t *testing.T) {
		err := checkCfgInvocation(rootCmd, []string{"account", "software-authenticator", "agent-admin"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--enabled")
	})
	t.Run("command group is not runnable", func(t *testing.T) {
		assert.Error(t, checkCfgInvocation(rootCmd, []string{"account"}))
	})
	t.Run("valid invocation with a flag value and a global flag", func(t *testing.T) {
		assert.NoError(t, checkCfgInvocation(rootCmd,
			[]string{"--authenticator", "agent-1", "account", "software-authenticator", "agent-admin", "--enabled=true"}))
	})
	t.Run("extraction", func(t *testing.T) {
		doc := "text\n```bash\n# comment\nprintf '%s' \"$LINK\" | cfg authenticator enroll agent-1 --link-stdin\nCFGMS_AUTHENTICATOR=a cfg token list # tail\ncfg tenant break-glass client-1 \\\n  --reason account_recovery\n```\ncfg not-in-a-block\n"
		got, err := cfgInvocations(codeBlockLines(doc))
		require.NoError(t, err)
		assert.Equal(t, [][]string{
			{"authenticator", "enroll", "agent-1", "--link-stdin"},
			{"token", "list"},
			{"tenant", "break-glass", "client-1", "--reason", "account_recovery"},
		}, got)
	})
	t.Run("unterminated quote", func(t *testing.T) {
		_, err := cfgInvocations([]string{`cfg account create --username "alice`})
		assert.Error(t, err)
	})
	t.Run("environment specifics are detected", func(t *testing.T) {
		assert.NotEmpty(t, ipv4LiteralRE.FindAllString("controller at 10.0.0.5:9443", -1))
		assert.NotEmpty(t, localHostnameRE.FindAllString("https://ctl-1.cell.internal:9443", -1))
		assert.NotEmpty(t, localHostnameRE.FindAllString("host.local", -1))
		assert.Empty(t, ipv4LiteralRE.FindAllString("version 1.2.3", -1))
	})
}
