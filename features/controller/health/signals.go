// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package health

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Service-level signals are controller-wide measurements (queue depths, error
// counts, latencies) recorded in-process and exposed in Prometheus text format
// on the private metrics listener.
//
// A signal must never carry tenant, steward or path data. Each metric therefore
// declares, at registration, the label names it accepts and the closed set of
// values each label may take. A record that names an undeclared label, uses an
// undeclared value or omits a declared label is rejected and records nothing, so
// series cardinality is bounded by what the code declared, never by runtime
// input.

var (
	metricNamePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelNamePattern  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// SignalRegistry holds the service-level signals of one Collector. It is safe
// for concurrent registration, recording and scraping.
type SignalRegistry struct {
	mu      sync.RWMutex
	claimed map[string]struct{} // every series name owned by a registered metric
	metrics map[string]signalMetric
}

// signalMetric is a registered metric that can render itself.
type signalMetric interface {
	render(sb *strings.Builder)
}

// NewSignalRegistry creates an empty registry. Collector.Signals returns the
// registry a controller uses; this constructor exists for standalone use.
func NewSignalRegistry() *SignalRegistry {
	return &SignalRegistry{
		claimed: make(map[string]struct{}),
		metrics: make(map[string]signalMetric),
	}
}

// claim reserves series names for a metric. It fails, and reserves nothing, if
// any name is invalid, already registered or emitted by the built-in renderer.
func (r *SignalRegistry) claim(metric signalMetric, family string, seriesNames ...string) error {
	if !metricNamePattern.MatchString(family) {
		return fmt.Errorf("invalid metric name %q", family)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range seriesNames {
		if isBuiltinSeriesName(name) {
			return fmt.Errorf("metric name %q is already emitted by the controller health exposition", name)
		}
		if _, taken := r.claimed[name]; taken {
			return fmt.Errorf("metric name %q is already registered", name)
		}
	}
	for _, name := range seriesNames {
		r.claimed[name] = struct{}{}
	}
	r.metrics[family] = metric
	return nil
}

// WriteText writes every registered metric in Prometheus text exposition
// format, ordered by metric name and then by label values.
func (r *SignalRegistry) WriteText(w io.Writer) error {
	var sb strings.Builder
	r.render(&sb)
	_, err := io.WriteString(w, sb.String())
	return err
}

func (r *SignalRegistry) render(sb *strings.Builder) {
	r.mu.RLock()
	names := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]signalMetric, len(names))
	for i, name := range names {
		ordered[i] = r.metrics[name]
	}
	r.mu.RUnlock()

	for _, m := range ordered {
		m.render(sb)
	}
}

// RegisterGauge registers a gauge. labels maps each allowed label name to the
// closed set of values it may take; nil declares an unlabeled metric.
func (r *SignalRegistry) RegisterGauge(name, help string, labels map[string][]string) (*Gauge, error) {
	ls, err := newLabelSet(labels)
	if err != nil {
		return nil, fmt.Errorf("gauge %q: %w", name, err)
	}
	g := &Gauge{base: newSignalBase(name, help, "gauge", ls), series: make(map[string]*gaugeSeries)}
	if err := r.claim(g, name, name); err != nil {
		return nil, err
	}
	return g, nil
}

// RegisterCounter registers a monotonically increasing counter.
func (r *SignalRegistry) RegisterCounter(name, help string, labels map[string][]string) (*Counter, error) {
	ls, err := newLabelSet(labels)
	if err != nil {
		return nil, fmt.Errorf("counter %q: %w", name, err)
	}
	c := &Counter{base: newSignalBase(name, help, "counter", ls), series: make(map[string]*gaugeSeries)}
	if err := r.claim(c, name, name); err != nil {
		return nil, err
	}
	return c, nil
}

// RegisterHistogram registers a histogram with fixed bucket upper bounds, which
// must be finite and strictly increasing. The +Inf bucket is implicit. The
// histogram owns the <name>_bucket, <name>_sum and <name>_count series names.
func (r *SignalRegistry) RegisterHistogram(name, help string, buckets []float64, labels map[string][]string) (*Histogram, error) {
	if len(buckets) == 0 {
		return nil, fmt.Errorf("histogram %q: at least one bucket is required", name)
	}
	for i, b := range buckets {
		if math.IsNaN(b) || math.IsInf(b, 0) {
			return nil, fmt.Errorf("histogram %q: bucket bounds must be finite", name)
		}
		if i > 0 && b <= buckets[i-1] {
			return nil, fmt.Errorf("histogram %q: bucket bounds must be strictly increasing", name)
		}
	}
	ls, err := newLabelSet(labels)
	if err != nil {
		return nil, fmt.Errorf("histogram %q: %w", name, err)
	}
	h := &Histogram{
		base:    newSignalBase(name, help, "histogram", ls),
		bounds:  append([]float64(nil), buckets...),
		series:  make(map[string]*histogramSeries),
		leTexts: make([]string, len(buckets)),
	}
	for i, b := range buckets {
		h.leTexts[i] = formatSampleValue(b)
	}
	if err := r.claim(h, name, name, name+"_bucket", name+"_sum", name+"_count"); err != nil {
		return nil, err
	}
	return h, nil
}

// labelSet is a metric's declared label names and allowed values.
type labelSet struct {
	names   []string // sorted
	allowed map[string]map[string]struct{}
}

func newLabelSet(declared map[string][]string) (*labelSet, error) {
	ls := &labelSet{allowed: make(map[string]map[string]struct{}, len(declared))}
	for name, values := range declared {
		if !labelNamePattern.MatchString(name) || strings.HasPrefix(name, "__") {
			return nil, fmt.Errorf("invalid label name %q", name)
		}
		if name == "le" {
			return nil, fmt.Errorf("label name %q is reserved for histogram buckets", name)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("label %q declares no allowed values", name)
		}
		set := make(map[string]struct{}, len(values))
		for _, v := range values {
			if !utf8.ValidString(v) {
				return nil, fmt.Errorf("label %q declares a value that is not valid UTF-8", name)
			}
			set[v] = struct{}{}
		}
		ls.allowed[name] = set
		ls.names = append(ls.names, name)
	}
	sort.Strings(ls.names)
	return ls, nil
}

// resolve validates a label assignment and returns the values in declared name
// order. Every declared label must be supplied with an allowed value, and no
// other label may be present.
func (ls *labelSet) resolve(labels map[string]string) ([]string, error) {
	if len(labels) != len(ls.names) {
		return nil, fmt.Errorf("expected labels %v, got %d label(s)", ls.names, len(labels))
	}
	values := make([]string, len(ls.names))
	for i, name := range ls.names {
		v, ok := labels[name]
		if !ok {
			return nil, fmt.Errorf("label %q is not supplied", name)
		}
		if _, ok := ls.allowed[name][v]; !ok {
			return nil, fmt.Errorf("value for label %q is not in its declared set", name)
		}
		values[i] = v
	}
	return values, nil
}

// signalBase is the state shared by every metric kind.
type signalBase struct {
	name   string
	help   string
	kind   string
	labels *labelSet
	mu     sync.Mutex
}

func newSignalBase(name, help, kind string, ls *labelSet) signalBase {
	return signalBase{name: name, help: help, kind: kind, labels: ls}
}

func (b *signalBase) header(sb *strings.Builder) {
	sb.WriteString("# HELP " + b.name + " " + escapeHelp(b.help) + "\n")
	sb.WriteString("# TYPE " + b.name + " " + b.kind + "\n")
}

// labelText formats {a="x",b="y"}; extra is appended after the declared labels
// (used for a histogram's le). It returns "" when there is nothing to write.
func (b *signalBase) labelText(values []string, extraName, extraValue string) string {
	if len(values) == 0 && extraName == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, name := range b.labels.names {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(name + `="` + escapeLabelValue(values[i]) + `"`)
	}
	if extraName != "" {
		if len(values) > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(extraName + `="` + escapeLabelValue(extraValue) + `"`)
	}
	sb.WriteByte('}')
	return sb.String()
}

func seriesKey(values []string) string {
	// 0xff never occurs in valid UTF-8, so the join is unambiguous.
	return strings.Join(values, "\xff")
}

func checkSampleValue(v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("sample value must be finite")
	}
	return nil
}

type gaugeSeries struct {
	values []string
	value  float64
}

// Gauge is a metric that can go up and down.
type Gauge struct {
	base   signalBase
	series map[string]*gaugeSeries
}

// Set records v for the series named by labels.
func (g *Gauge) Set(v float64, labels map[string]string) error {
	return recordSeries(&g.base, g.series, labels, v, true)
}

// Add adds delta (which may be negative) to the series named by labels.
func (g *Gauge) Add(delta float64, labels map[string]string) error {
	return recordSeries(&g.base, g.series, labels, delta, false)
}

func (g *Gauge) render(sb *strings.Builder) { renderSeries(&g.base, g.series, sb) }

// Counter is a metric that only increases.
type Counter struct {
	base   signalBase
	series map[string]*gaugeSeries
}

// Inc adds one to the series named by labels.
func (c *Counter) Inc(labels map[string]string) error { return c.Add(1, labels) }

// Add adds a non-negative delta to the series named by labels.
func (c *Counter) Add(delta float64, labels map[string]string) error {
	if delta < 0 {
		return fmt.Errorf("counter %q: cannot decrease", c.base.name)
	}
	return recordSeries(&c.base, c.series, labels, delta, false)
}

func (c *Counter) render(sb *strings.Builder) { renderSeries(&c.base, c.series, sb) }

func recordSeries(b *signalBase, series map[string]*gaugeSeries, labels map[string]string, v float64, set bool) error {
	if err := checkSampleValue(v); err != nil {
		return fmt.Errorf("metric %q: %w", b.name, err)
	}
	values, err := b.labels.resolve(labels)
	if err != nil {
		return fmt.Errorf("metric %q: %w", b.name, err)
	}
	key := seriesKey(values)
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := series[key]
	if !ok {
		s = &gaugeSeries{values: values}
		series[key] = s
	}
	if set {
		s.value = v
	} else {
		s.value += v
	}
	return nil
}

func renderSeries(b *signalBase, series map[string]*gaugeSeries, sb *strings.Builder) {
	b.header(sb)
	b.mu.Lock()
	defer b.mu.Unlock()
	keys := sortedKeys(series)
	for _, k := range keys {
		s := series[k]
		sb.WriteString(b.name + b.labelText(s.values, "", "") + " " + formatSampleValue(s.value) + "\n")
	}
}

type histogramSeries struct {
	values []string
	counts []uint64 // per finite bucket, non-cumulative
	count  uint64
	sum    float64
}

// Histogram counts observations into fixed buckets.
type Histogram struct {
	base    signalBase
	bounds  []float64
	leTexts []string
	series  map[string]*histogramSeries
}

// Observe records v in the series named by labels. A bucket's upper bound is
// inclusive.
func (h *Histogram) Observe(v float64, labels map[string]string) error {
	if err := checkSampleValue(v); err != nil {
		return fmt.Errorf("histogram %q: %w", h.base.name, err)
	}
	values, err := h.base.labels.resolve(labels)
	if err != nil {
		return fmt.Errorf("histogram %q: %w", h.base.name, err)
	}
	key := seriesKey(values)
	h.base.mu.Lock()
	defer h.base.mu.Unlock()
	s, ok := h.series[key]
	if !ok {
		s = &histogramSeries{values: values, counts: make([]uint64, len(h.bounds))}
		h.series[key] = s
	}
	if i := sort.SearchFloat64s(h.bounds, v); i < len(h.bounds) {
		s.counts[i]++
	}
	s.count++
	s.sum += v
	return nil
}

func (h *Histogram) render(sb *strings.Builder) {
	h.base.header(sb)
	h.base.mu.Lock()
	defer h.base.mu.Unlock()
	for _, k := range sortedKeys(h.series) {
		s := h.series[k]
		var cumulative uint64
		for i := range h.bounds {
			cumulative += s.counts[i]
			sb.WriteString(h.base.name + "_bucket" + h.base.labelText(s.values, "le", h.leTexts[i]) + " " + strconv.FormatUint(cumulative, 10) + "\n")
		}
		sb.WriteString(h.base.name + "_bucket" + h.base.labelText(s.values, "le", "+Inf") + " " + strconv.FormatUint(s.count, 10) + "\n")
		sb.WriteString(h.base.name + "_sum" + h.base.labelText(s.values, "", "") + " " + formatSampleValue(s.sum) + "\n")
		sb.WriteString(h.base.name + "_count" + h.base.labelText(s.values, "", "") + " " + strconv.FormatUint(s.count, 10) + "\n")
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatSampleValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// escapeLabelValue escapes backslash, double quote and newline as the
// Prometheus text format requires inside a label value.
func escapeLabelValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// escapeHelp escapes backslash and newline in HELP text.
func escapeHelp(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(v)
}
