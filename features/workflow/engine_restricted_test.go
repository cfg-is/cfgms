// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

const restrictedTestTenant = "tenant-a"

// countingScriptExecutor is a script step executor that counts the steps that
// reach it, so a test can prove nothing ran.
type countingScriptExecutor struct {
	runs atomic.Int32
}

func (c *countingScriptExecutor) ExecuteStep(_ context.Context, _ Step, _ *WorkflowExecution) (StepResult, error) {
	c.runs.Add(1)
	return StepResult{Status: StatusCompleted}, nil
}

// tenantChannels resolves tenant notify channels from a fixed table.
type tenantChannels struct {
	mu       sync.Mutex
	channels map[string]map[string]bool
	err      error
}

func (c *tenantChannels) IsTenantChannel(_ context.Context, tenantID, url string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.channels[tenantID][url], c.err
}

const configuredChannelURL = "https://hooks.acme-corp.example/ops"

func newRestrictedEngine(t *testing.T) (*Engine, *countingScriptExecutor) {
	t.Helper()
	scripts := &countingScriptExecutor{}
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil,
		WithScriptStepExecutor(scripts),
		WithNotifyChannels(&tenantChannels{channels: map[string]map[string]bool{
			restrictedTestTenant: {configuredChannelURL: true},
		}}),
	)
	t.Cleanup(func() { engine.Shutdown() })
	return engine, scripts
}

func restrictedCtx() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, restrictedTestTenant)
}

func runRestricted(engine *Engine, wf Workflow, vars map[string]interface{}) (*WorkflowExecution, error) {
	return engine.ExecuteRestrictedWorkflow(restrictedCtx(), wf, vars,
		RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: restrictedTestTenant})
}

func scriptStep(name string) Step {
	return Step{Name: name, Type: StepTypeScript, Config: map[string]interface{}{"script_id": "s1"}}
}

func restrictedDelayStep(name string) Step {
	return Step{Name: name, Type: StepTypeDelay, Delay: &DelayConfig{Duration: time.Millisecond}}
}

func notifyStep(name, url string) Step {
	return Step{Name: name, Type: StepTypeNotify, Notify: &NotifyConfig{URL: url, Title: "t"}}
}

// stepTypeConstants returns every StepType constant declared in types.go, read
// from the source so a type added later is enumerated without editing the test.
func stepTypeConstants(t *testing.T) map[string]StepType {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "types.go", nil, 0)
	require.NoError(t, err)
	found := map[string]StepType{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "StepType" {
				continue
			}
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				require.True(t, ok, "StepType constant %s must be a string literal", name.Name)
				value, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)
				found[name.Name] = StepType(value)
			}
		}
	}
	require.NotEmpty(t, found)
	return found
}

func TestRestrictedPolicy_ClassifiesEveryStepType(t *testing.T) {
	consts := stepTypeConstants(t)
	for name, stepType := range consts {
		policy, classified := restrictedStepPolicies[stepType]
		require.True(t, classified, "step type %s (%q) is not classified allowed or denied for restricted automation", name, stepType)
		if !policy.allowed {
			assert.NotEmpty(t, policy.reason, "denied step type %s needs a reason", name)
		}
		assert.Equal(t, policy.allowed, classifyRestrictedStep(stepType).allowed)
	}

	// Every classified type is a type the engine defines.
	defined := map[StepType]bool{}
	for _, stepType := range consts {
		defined[stepType] = true
	}
	for stepType := range restrictedStepPolicies {
		assert.True(t, defined[stepType], "policy classifies %q, which is not a StepType constant", stepType)
	}
}

func TestRestrictedPolicy_AllowlistIsExactlyTheV1Set(t *testing.T) {
	var allowed []string
	for stepType, policy := range restrictedStepPolicies {
		if policy.allowed {
			allowed = append(allowed, string(stepType))
		}
	}
	sort.Strings(allowed)
	assert.Equal(t, []string{
		"break", "conditional", "continue", "delay", "for", "foreach", "notify",
		"parallel", "script", "sequential", "switch", "try", "while",
	}, allowed)
}

func TestRestrictedPolicy_UnclassifiedTypeIsDenied(t *testing.T) {
	policy := classifyRestrictedStep(StepType("added_later"))
	assert.False(t, policy.allowed)
	assert.NotEmpty(t, policy.reason)

	engine, scripts := newRestrictedEngine(t)
	exec, err := runRestricted(engine, Workflow{Name: "wf", Steps: []Step{scriptStep("first"), {Name: "x", Type: "added_later"}}}, nil)
	var refused *RestrictedWorkflowError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, StatusFailed, exec.GetStatus())
	assert.Zero(t, scripts.runs.Load())
}

// deniedStep returns a minimal step of the given denied type.
func deniedStep(stepType StepType) Step {
	return Step{
		Name:         "denied-" + string(stepType),
		Type:         stepType,
		Module:       "file",
		HTTP:         &HTTPConfig{URL: "https://example.invalid"},
		WorkflowCall: &WorkflowCallConfig{},
		Composite:    &CompositeConfig{},
	}
}

func deniedStepTypes() []StepType {
	var types []StepType
	for stepType, policy := range restrictedStepPolicies {
		if !policy.allowed {
			types = append(types, stepType)
		}
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// nestings wrap a step inside every nested body shape the engine executes.
var nestings = map[string]func(Step) Step{
	"top level":   func(s Step) Step { return s },
	"sequential":  func(s Step) Step { return Step{Name: "wrap", Type: StepTypeSequential, Steps: []Step{s}} },
	"parallel":    func(s Step) Step { return Step{Name: "wrap", Type: StepTypeParallel, Steps: []Step{s}} },
	"conditional": func(s Step) Step { return Step{Name: "wrap", Type: StepTypeConditional, Steps: []Step{s}} },
	"for":         func(s Step) Step { return Step{Name: "wrap", Type: StepTypeFor, Steps: []Step{s}} },
	"while":       func(s Step) Step { return Step{Name: "wrap", Type: StepTypeWhile, Steps: []Step{s}} },
	"foreach":     func(s Step) Step { return Step{Name: "wrap", Type: StepTypeForeach, Steps: []Step{s}} },
	"try body":    func(s Step) Step { return Step{Name: "wrap", Type: StepTypeTry, Try: &TryConfig{Try: []Step{s}}} },
	"try finally": func(s Step) Step { return Step{Name: "wrap", Type: StepTypeTry, Try: &TryConfig{Finally: []Step{s}}} },
	"try catch": func(s Step) Step {
		return Step{Name: "wrap", Type: StepTypeTry, Try: &TryConfig{Catch: []CatchBlock{{Steps: []Step{s}}}}}
	},
	"switch case": func(s Step) Step {
		return Step{Name: "wrap", Type: StepTypeSwitch, Switch: &SwitchConfig{Cases: []SwitchCase{{Steps: []Step{s}}}}}
	},
	"switch default": func(s Step) Step {
		return Step{Name: "wrap", Type: StepTypeSwitch, Switch: &SwitchConfig{Default: []Step{s}}}
	},
	"fallback": func(s Step) Step {
		return Step{Name: "wrap", Type: StepTypeDelay, ErrorHandling: &ErrorHandlingConfig{FallbackStep: &s}}
	},
	"nested parallel": func(s Step) Step {
		return Step{Name: "o", Type: StepTypeParallel, Steps: []Step{{Name: "i", Type: StepTypeTry, Try: &TryConfig{Try: []Step{s}}}}}
	},
}

func TestRestricted_DeniedStepRejectedBeforeFirstStep(t *testing.T) {
	for _, stepType := range deniedStepTypes() {
		for nestName, nest := range nestings {
			t.Run(string(stepType)+"/"+nestName, func(t *testing.T) {
				engine, scripts := newRestrictedEngine(t)
				// The script step before the denied one would run first if validation
				// did not finish before the first step starts.
				wf := Workflow{Name: "wf", Steps: []Step{scriptStep("first"), nest(deniedStep(stepType))}}

				exec, err := runRestricted(engine, wf, nil)

				var refused *RestrictedWorkflowError
				require.ErrorAs(t, err, &refused)
				require.Len(t, refused.Violations, 1)
				assert.Equal(t, stepType, refused.Violations[0].Type)
				require.NotNil(t, exec)
				assert.Equal(t, StatusFailed, exec.GetStatus())
				assert.Empty(t, exec.GetStepResults(), "no step may start")
				assert.Zero(t, scripts.runs.Load(), "the script step before the denied step must not run")
			})
		}
	}
}

func TestRestricted_EveryViolationIsReported(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{
		deniedStep(StepTypeTask),
		{Name: "p", Type: StepTypeParallel, Steps: []Step{deniedStep(StepTypeHTTP), restrictedDelayStep("ok")}},
	}}
	_, err := runRestricted(engine, wf, nil)
	var refused *RestrictedWorkflowError
	require.ErrorAs(t, err, &refused)
	require.Len(t, refused.Violations, 2)
	assert.Equal(t, "p/denied-http", refused.Violations[1].Path)
	assert.Contains(t, err.Error(), "denied-task")
}

func TestRestricted_WorkflowLevelErrorWorkflowsRefused(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{restrictedDelayStep("ok")}, ErrorWorkflows: []ErrorWorkflowConfig{{WorkflowName: "other"}}}
	_, err := runRestricted(engine, wf, nil)
	var refused *RestrictedWorkflowError
	require.ErrorAs(t, err, &refused)
}

func TestRestricted_StepDepthIsBounded(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	step := restrictedDelayStep("leaf")
	for i := 0; i < maxRestrictedDepth+2; i++ {
		step = Step{Name: "n", Type: StepTypeSequential, Steps: []Step{step}}
	}
	_, err := runRestricted(engine, Workflow{Name: "wf", Steps: []Step{step}}, nil)
	var refused *RestrictedWorkflowError
	require.ErrorAs(t, err, &refused)
	assert.Contains(t, err.Error(), "nested too deeply")
}

func TestRestricted_NotifyDestination(t *testing.T) {
	tests := []struct {
		name    string
		step    Step
		vars    map[string]interface{}
		allowed bool
	}{
		{name: "tenant-configured channel", step: notifyStep("n", configuredChannelURL), allowed: true},
		{name: "free-form url", step: notifyStep("n", "https://attacker.example/collect")},
		{name: "url built from an input", step: notifyStep("n", "{{ .target }}"), vars: map[string]interface{}{"target": configuredChannelURL}},
		{name: "configured channel with a templated suffix", step: notifyStep("n", configuredChannelURL+"/{{ .x }}")},
		{name: "address instead of url", step: notifyStep("n", "ops@acme-corp.example")},
		{name: "missing notify configuration", step: Step{Name: "n", Type: StepTypeNotify}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine, _ := newRestrictedEngine(t)
			exec, err := runRestricted(engine, Workflow{Name: "wf", Steps: []Step{tc.step}}, tc.vars)
			if tc.allowed {
				require.NoError(t, err)
				require.NotNil(t, exec)
				return
			}
			var refused *RestrictedWorkflowError
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, StepTypeNotify, refused.Violations[0].Type)
			assert.Empty(t, exec.GetStepResults())
		})
	}
}

func TestRestricted_NotifyIsPerTenant(t *testing.T) {
	engine, _ := newRestrictedEngine(t)
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-b")
	_, err := engine.ExecuteRestrictedWorkflow(ctx, Workflow{Name: "wf", Steps: []Step{notifyStep("n", configuredChannelURL)}}, nil,
		RestrictedRun{RunID: "r", GrantID: "g", Ceiling: "tenant-b"})
	var refused *RestrictedWorkflowError
	require.ErrorAs(t, err, &refused, "tenant-a's channel must not be usable by tenant-b")
}

func TestRestricted_NotifyFailsClosed(t *testing.T) {
	t.Run("no resolver", func(t *testing.T) {
		engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
		t.Cleanup(func() { engine.Shutdown() })
		_, err := runRestricted(engine, Workflow{Name: "wf", Steps: []Step{notifyStep("n", configuredChannelURL)}}, nil)
		var refused *RestrictedWorkflowError
		require.ErrorAs(t, err, &refused)
	})
	t.Run("resolver error", func(t *testing.T) {
		resolver := &tenantChannels{channels: map[string]map[string]bool{restrictedTestTenant: {configuredChannelURL: true}}, err: errors.New("store down")}
		engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil, WithNotifyChannels(resolver))
		t.Cleanup(func() { engine.Shutdown() })
		_, err := runRestricted(engine, Workflow{Name: "wf", Steps: []Step{notifyStep("n", configuredChannelURL)}}, nil)
		var refused *RestrictedWorkflowError
		require.ErrorAs(t, err, &refused)
	})
}

func TestRestricted_AllowedWorkflowValidatesAndRuns(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)
	wf := Workflow{Name: "wf", Steps: []Step{
		scriptStep("collect"),
		{Name: "fan", Type: StepTypeParallel, Steps: []Step{restrictedDelayStep("d1"), restrictedDelayStep("d2")}},
		{Name: "guard", Type: StepTypeTry, Try: &TryConfig{Try: []Step{restrictedDelayStep("t1")}, Finally: []Step{restrictedDelayStep("f1")}}},
		{Name: "pick", Type: StepTypeSwitch, Switch: &SwitchConfig{Variable: "mode", Default: []Step{restrictedDelayStep("sd")}}},
		{Name: "seq", Type: StepTypeSequential, Steps: []Step{scriptStep("collect-2")}},
	}}

	require.NoError(t, engine.validateRestrictedWorkflow(restrictedCtx(), wf))

	exec, err := runRestricted(engine, wf, map[string]interface{}{"mode": "a"})
	require.NoError(t, err)
	waitForWorkflowCompletion(t, exec, 5*time.Second)
	assert.Equal(t, StatusCompleted, exec.GetStatus())
	assert.EqualValues(t, 2, scripts.runs.Load())
	require.NotNil(t, exec.Restricted)
	assert.Equal(t, "run-1", exec.Restricted.RunID)
}

func TestRestricted_ValidationRunsOnEveryRestrictedStart(t *testing.T) {
	// The restricted run never starts when validation fails, and the denied step
	// never reaches an executor even when the denied step is the only one.
	engine, scripts := newRestrictedEngine(t)
	exec, err := runRestricted(engine, Workflow{Name: "wf", Steps: []Step{deniedStep(StepTypeTask)}}, nil)
	require.Error(t, err)
	assert.Equal(t, StatusFailed, exec.GetStatus())
	assert.Zero(t, scripts.runs.Load())
	assert.Empty(t, exec.GetStepResults())
}

func TestRestricted_DispatchRefusesDeniedStepsOnRestrictedExecution(t *testing.T) {
	// A step the start-time walk cannot see (built at run time) is still refused
	// as it is dispatched.
	engine, _ := newRestrictedEngine(t)
	execution := &WorkflowExecution{
		ID: "e1", TenantID: restrictedTestTenant, Variables: map[string]interface{}{},
		StepResults: map[string]StepResult{}, Context: context.Background(),
		Restricted: &RestrictedRun{RunID: "r", GrantID: "g"},
	}
	err := engine.executeStep(context.Background(), deniedStep(StepTypeTask), execution)
	require.ErrorIs(t, err, ErrRestrictedStepRefused)

	err = engine.executeStep(context.Background(), notifyStep("n", "https://attacker.example"), execution)
	require.ErrorIs(t, err, ErrRestrictedStepRefused)
}

func TestRestricted_FlagNotSettableByWorkflowOrInputs(t *testing.T) {
	engine, scripts := newRestrictedEngine(t)

	// Variables and inputs that look like the flag change nothing on either path.
	vars := map[string]interface{}{"restricted": false, "Restricted": nil, "run_id": "x"}
	wf := Workflow{Name: "wf", Variables: vars, Steps: []Step{deniedStep(StepTypeTask)}}
	_, err := runRestricted(engine, wf, vars)
	var refused *RestrictedWorkflowError
	require.ErrorAs(t, err, &refused, "a restricted run stays restricted whatever the definition says")

	// The unrestricted path never yields a restricted execution, and refuses a
	// script step instead of running it.
	plain, err := engine.ExecuteWorkflow(restrictedCtx(), Workflow{Name: "p", Variables: map[string]interface{}{"restricted": true}, Steps: []Step{restrictedDelayStep("d")}}, map[string]interface{}{"Restricted": true})
	require.NoError(t, err)
	waitForWorkflowCompletion(t, plain, 5*time.Second)
	assert.Nil(t, plain.Restricted)

	_, err = engine.ExecuteWorkflow(restrictedCtx(), Workflow{Name: "p", Steps: []Step{scriptStep("s")}}, nil)
	require.ErrorIs(t, err, ErrScriptStepNotRestricted)
	assert.Zero(t, scripts.runs.Load())

	// The flag has no serialized form a definition or input could carry.
	raw, err := json.Marshal(&WorkflowExecution{Restricted: &RestrictedRun{RunID: "r"}})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "RunID")
	assert.NotContains(t, string(raw), "estricted")
}

func TestRestricted_UnrestrictedExecutionOfDeniedTypesIsUnchanged(t *testing.T) {
	// The same workflows that restricted execution refuses still start on the
	// unrestricted path.
	engine, _ := newRestrictedEngine(t)
	for _, stepType := range []StepType{StepTypeTask, StepTypeHTTP, StepTypeAPI, StepTypeWebhook, StepTypeWorkflow, StepTypeComposite} {
		exec, err := engine.ExecuteWorkflow(restrictedCtx(), Workflow{Name: "wf", Steps: []Step{deniedStep(stepType)}}, nil)
		require.NoError(t, err, string(stepType))
		waitForWorkflowCompletion(t, exec, 5*time.Second)
	}
}

func TestStepRunners_EveryStepTypeHasAnExecutor(t *testing.T) {
	for name, stepType := range stepTypeConstants(t) {
		assert.Contains(t, stepRunners, stepType, "step type %s has no executor", name)
	}
	engine, _ := newRestrictedEngine(t)
	err := engine.dispatchStep(context.Background(), Step{Name: "x", Type: "added_later"},
		&WorkflowExecution{Variables: map[string]interface{}{}, StepResults: map[string]StepResult{}}, "x")
	assert.ErrorContains(t, err, "unknown step type")
}
