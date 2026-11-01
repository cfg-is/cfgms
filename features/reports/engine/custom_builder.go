// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/dna/drift"
)

// Supported custom report data sources.
const (
	sourceDNA         = "dna"
	sourceDrift       = "drift"
	sourceDeviceStats = "device_stats"
	sourceTrends      = "trends"
)

// Query keys that name devices, in CustomQuery.Filters and CustomReportRequest.UserParams.
const (
	keyDeviceID  = "device_id"
	keyDeviceIDs = "device_ids"
)

const streamTokenBytes = 32 // 256 bits from crypto/rand

// DeviceTenantResolver resolves the tenant that owns a device.
type DeviceTenantResolver interface {
	// TenantForDevice returns the tenant ID owning deviceID. known is false when the
	// device is not present in the registry.
	TenantForDevice(deviceID string) (tenantID string, known bool)
}

// TenantAncestryFunc reports whether descendant is a descendant of ancestor in the tenant
// store's ParentID ancestry. A tenant ID is a single token, so containment is never a
// string-prefix test.
type TenantAncestryFunc func(ctx context.Context, ancestor, descendant string) (bool, error)

var (
	// errRootTenantRefused: the root tenant's TenantIDs filter is a subtree filter that
	// would read every MSP without an ADR-025 tenant crossing.
	errRootTenantRefused = errors.New("custom reports cannot be built for the root tenant")
	// errCustomDeviceOutsideTenant covers an unknown device and another tenant's device
	// alike, and names no device.
	errCustomDeviceOutsideTenant = errors.New("device is not within the caller's tenant")
	// errCustomDeviceScopeUnverifiable means no resolver or ancestry function is wired.
	errCustomDeviceScopeUnverifiable = errors.New("device tenant ownership cannot be verified")
)

var scopedTrendMetrics = []string{"drift_events", "compliance_score", "device_count"}

// CustomReportBuilder implements interfaces.CustomReportBuilder on a DataProvider. Every
// query it builds is scoped to the request's tenant.
type CustomReportBuilder struct {
	provider  interfaces.DataProvider
	cfg       interfaces.CustomReportConfig
	pageCache *cache.Cache
	devices   DeviceTenantResolver
	ancestry  TenantAncestryFunc
	rootID    string
}

var _ interfaces.CustomReportBuilder = (*CustomReportBuilder)(nil)

// NewCustomReportBuilder builds a builder. A zero cfg selects DefaultCustomReportConfig().
// The provider, page cache and root tenant ID are required. A nil devices resolver or
// ancestry function is accepted, but then any request naming devices is refused.
func NewCustomReportBuilder(
	provider interfaces.DataProvider,
	cfg interfaces.CustomReportConfig,
	pageCache *cache.Cache,
	devices DeviceTenantResolver,
	ancestry TenantAncestryFunc,
	rootTenantID string,
) (*CustomReportBuilder, error) {
	if provider == nil {
		return nil, errors.New("custom report builder requires a data provider")
	}
	if pageCache == nil {
		return nil, errors.New("custom report builder requires a page cache")
	}
	if rootTenantID == "" {
		return nil, errors.New("custom report builder requires the root tenant ID")
	}
	if cfg == (interfaces.CustomReportConfig{}) {
		cfg = interfaces.DefaultCustomReportConfig()
	}
	if cfg.MaxDataSources <= 0 || cfg.MaxFilters <= 0 || cfg.MaxAggregations <= 0 || cfg.MaxParameters <= 0 ||
		cfg.DefaultPageSize <= 0 || cfg.MaxPageSize < cfg.DefaultPageSize ||
		cfg.DefaultTimeout <= 0 || cfg.MaxTimeout < cfg.DefaultTimeout || cfg.CacheTTL <= 0 ||
		(cfg.EnableStreaming && cfg.StreamThreshold <= 0) {
		return nil, errors.New("custom report builder config is invalid")
	}
	return &CustomReportBuilder{
		provider:  provider,
		cfg:       cfg,
		pageCache: pageCache,
		devices:   devices,
		ancestry:  ancestry,
		rootID:    rootTenantID,
	}, nil
}

// ValidateParameters checks params against the template's parameter definitions.
func (b *CustomReportBuilder) ValidateParameters(template *interfaces.CustomReportTemplate, params map[string]interface{}) error {
	if template == nil {
		return fmt.Errorf("%w: template is required", interfaces.ErrParameterValidationFailed)
	}
	if len(template.Parameters) > b.cfg.MaxParameters {
		return fmt.Errorf("%w: %d parameters defined, maximum is %d",
			interfaces.ErrParameterValidationFailed, len(template.Parameters), b.cfg.MaxParameters)
	}
	for _, def := range template.Parameters {
		value, present := params[def.Name]
		if !present || value == nil {
			if def.Default != nil {
				value = def.Default
			} else if def.Required {
				return paramError(def.Name, "is required")
			} else {
				continue
			}
		}
		if err := validateParameterValue(def, value); err != nil {
			return err
		}
	}
	return nil
}

func paramError(name, msg string) error {
	return fmt.Errorf("%w: parameter %q %s", interfaces.ErrParameterValidationFailed, name, msg)
}

func validateParameterValue(def interfaces.CustomParameter, value interface{}) error {
	switch def.Type {
	case "string":
		s, ok := value.(string)
		if !ok {
			return paramError(def.Name, "must be a string")
		}
		return validateStringValue(def, s)
	case "number":
		n, ok := toFloat(value)
		if !ok {
			return paramError(def.Name, "must be a number")
		}
		if def.MinValue != nil && n < *def.MinValue {
			return paramError(def.Name, "is below the minimum")
		}
		if def.MaxValue != nil && n > *def.MaxValue {
			return paramError(def.Name, "is above the maximum")
		}
		return nil
	case "boolean":
		if _, ok := value.(bool); !ok {
			return paramError(def.Name, "must be a boolean")
		}
		return nil
	case "date":
		switch v := value.(type) {
		case time.Time:
			return nil
		case string:
			if _, err := time.Parse(time.RFC3339, v); err == nil {
				return nil
			}
			if _, err := time.Parse("2006-01-02", v); err == nil {
				return nil
			}
		}
		return paramError(def.Name, "must be a date")
	case "array":
		rv := reflect.ValueOf(value)
		if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
			return paramError(def.Name, "must be an array")
		}
		if def.MinLength != nil && rv.Len() < *def.MinLength {
			return paramError(def.Name, "has too few elements")
		}
		if def.MaxLength != nil && rv.Len() > *def.MaxLength {
			return paramError(def.Name, "has too many elements")
		}
		if len(def.Options) > 0 {
			for i := 0; i < rv.Len(); i++ {
				if !containsString(def.Options, fmt.Sprint(rv.Index(i).Interface())) {
					return paramError(def.Name, "has an element that is not an allowed option")
				}
			}
		}
		return nil
	default:
		return paramError(def.Name, "has an unsupported type")
	}
}

func validateStringValue(def interfaces.CustomParameter, s string) error {
	n := utf8.RuneCountInString(s)
	if def.MinLength != nil && n < *def.MinLength {
		return paramError(def.Name, "is too short")
	}
	if def.MaxLength != nil && n > *def.MaxLength {
		return paramError(def.Name, "is too long")
	}
	if len(def.Options) > 0 && !containsString(def.Options, s) {
		return paramError(def.Name, "is not an allowed option")
	}
	if def.Pattern != "" {
		re, err := regexp.Compile(def.Pattern)
		if err != nil {
			return paramError(def.Name, "has an invalid pattern")
		}
		if !re.MatchString(s) {
			return paramError(def.Name, "does not match the required pattern")
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// BuildQuery validates query and returns its processing metadata. It has no tenant, so the
// cache key it returns is tenant-neutral and must not key shared cache entries; the
// generation path uses BuildQueryForTenant.
func (b *CustomReportBuilder) BuildQuery(query interfaces.CustomQuery) (*interfaces.ProcessedQuery, error) {
	return b.buildQuery("", query, nil)
}

// BuildQueryForTenant is BuildQuery with the tenant mixed into the cache key, so equal
// queries from different tenants never share an entry. extraDeviceIDs are device IDs named
// outside the query (user parameters).
func (b *CustomReportBuilder) BuildQueryForTenant(tenantID string, query interfaces.CustomQuery, extraDeviceIDs []string) (*interfaces.ProcessedQuery, error) {
	if tenantID == "" {
		return nil, errEmptyTenant
	}
	return b.buildQuery(tenantID, query, extraDeviceIDs)
}

func (b *CustomReportBuilder) buildQuery(tenantID string, query interfaces.CustomQuery, extraDeviceIDs []string) (*interfaces.ProcessedQuery, error) {
	if len(query.DataSources) == 0 {
		return nil, fmt.Errorf("%w: at least one data source is required", interfaces.ErrInvalidQuery)
	}
	if len(query.DataSources) > b.cfg.MaxDataSources {
		return nil, fmt.Errorf("%w: %d data sources, maximum is %d", interfaces.ErrInvalidQuery, len(query.DataSources), b.cfg.MaxDataSources)
	}
	if len(query.Filters) > b.cfg.MaxFilters {
		return nil, fmt.Errorf("%w: %d filters, maximum is %d", interfaces.ErrInvalidQuery, len(query.Filters), b.cfg.MaxFilters)
	}
	if len(query.Aggregations) > b.cfg.MaxAggregations {
		return nil, fmt.Errorf("%w: %d aggregations, maximum is %d", interfaces.ErrInvalidQuery, len(query.Aggregations), b.cfg.MaxAggregations)
	}

	sources := make([]string, 0, len(query.DataSources))
	for _, s := range query.DataSources {
		switch s {
		case sourceDNA, sourceDrift, sourceDeviceStats, sourceTrends:
		default:
			return nil, fmt.Errorf("%w: %q", interfaces.ErrDataSourceNotSupported, s)
		}
		if !containsString(sources, s) {
			sources = append(sources, s)
		}
	}
	sort.Strings(sources)

	for _, agg := range query.Aggregations {
		if agg.Field == "" {
			return nil, fmt.Errorf("%w: aggregation field is required", interfaces.ErrInvalidQuery)
		}
		switch agg.Operation {
		case "sum", "avg", "count", "min", "max", "distinct":
		default:
			return nil, fmt.Errorf("%w: unsupported aggregation operation", interfaces.ErrInvalidQuery)
		}
	}
	for _, s := range query.Sorting {
		if s.Field == "" || (s.Direction != "asc" && s.Direction != "desc") {
			return nil, fmt.Errorf("%w: invalid sort specification", interfaces.ErrInvalidQuery)
		}
	}
	tr := query.TimeRange
	if !tr.Start.IsZero() && !tr.End.IsZero() && tr.End.Before(tr.Start) {
		return nil, fmt.Errorf("%w: time range ends before it starts", interfaces.ErrInvalidQuery)
	}
	if p := query.Pagination; p != nil && (p.PageSize < 0 || p.MaxPages < 0) {
		return nil, fmt.Errorf("%w: invalid pagination", interfaces.ErrInvalidQuery)
	}

	if _, err := dataQueryFilters(query.Filters); err != nil {
		return nil, err
	}
	filterDevices, err := deviceIDsFromMap(query.Filters)
	if err != nil {
		return nil, err
	}
	devices := unionDeviceIDs(filterDevices, extraDeviceIDs)

	complexity := complexityOf(len(sources), len(query.Filters), len(query.Aggregations))
	processed := &interfaces.ProcessedQuery{
		DataSources:   sources,
		Filters:       copyFilters(query.Filters),
		Aggregations:  append([]interfaces.QueryAggregation(nil), query.Aggregations...),
		Sorting:       append([]interfaces.QuerySort(nil), query.Sorting...),
		TimeRange:     query.TimeRange,
		Pagination:    query.Pagination,
		EstimatedRows: estimateRows(sources, len(query.Filters)),
		Complexity:    complexity,
		Timeout:       b.timeoutFor(complexity),
	}
	key, err := cacheKey(tenantID, processed, devices)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot derive cache key", interfaces.ErrInvalidQuery)
	}
	processed.CacheKey = key
	return processed, nil
}

func copyFilters(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func complexityOf(sources, filters, aggregations int) string {
	score := sources + filters + 2*aggregations
	switch {
	case score <= 3:
		return "low"
	case score <= 7:
		return "medium"
	default:
		return "high"
	}
}

func estimateRows(sources []string, filters int) int {
	total := 0
	for _, s := range sources {
		switch s {
		case sourceDNA:
			total += 1000
		case sourceDrift:
			total += 5000
		case sourceDeviceStats:
			total += 500
		case sourceTrends:
			total += 100
		}
	}
	for i := 0; i < filters && total > 1; i++ {
		total /= 2
	}
	return total
}

func (b *CustomReportBuilder) timeoutFor(complexity string) time.Duration {
	t := b.cfg.DefaultTimeout
	switch complexity {
	case "medium":
		t *= 2
	case "high":
		t *= 3
	}
	if t > b.cfg.MaxTimeout {
		t = b.cfg.MaxTimeout
	}
	return t
}

// cacheKey hashes the tenant-prefixed canonical query. encoding/json sorts map keys, so
// equal queries always yield the same key.
func cacheKey(tenantID string, q *interfaces.ProcessedQuery, devices []string) (string, error) {
	sorted := append([]string(nil), devices...)
	sort.Strings(sorted)
	canonical := struct {
		DataSources  []string                      `json:"d"`
		Filters      map[string]interface{}        `json:"f"`
		Aggregations []interfaces.QueryAggregation `json:"a"`
		Sorting      []interfaces.QuerySort        `json:"s"`
		Start        time.Time                     `json:"ts"`
		End          time.Time                     `json:"te"`
		Pagination   *interfaces.PaginationConfig  `json:"p"`
		Devices      []string                      `json:"v"`
	}{q.DataSources, q.Filters, q.Aggregations, q.Sorting, q.TimeRange.Start.UTC(), q.TimeRange.End.UTC(), q.Pagination, sorted}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dataQueryFilters converts non-device filters to DataQuery.Filters. Device keys are carried
// in DataQuery.DeviceIDs instead; a non-scalar value is ErrInvalidQuery.
func dataQueryFilters(in map[string]interface{}) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == keyDeviceID || k == keyDeviceIDs {
			continue
		}
		if v == nil {
			return nil, fmt.Errorf("%w: filter %q has no value", interfaces.ErrInvalidQuery, k)
		}
		switch reflect.ValueOf(v).Kind() {
		case reflect.String, reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			out[k] = fmt.Sprint(v)
		default:
			return nil, fmt.Errorf("%w: filter %q must be a scalar", interfaces.ErrInvalidQuery, k)
		}
	}
	return out, nil
}

// deviceIDsFromMap extracts the device IDs named by the device_id and device_ids keys.
func deviceIDsFromMap(m map[string]interface{}) ([]string, error) {
	var ids []string
	if v, ok := m[keyDeviceID]; ok {
		s, isStr := v.(string)
		if !isStr {
			return nil, fmt.Errorf("%w: %s must be a string", interfaces.ErrInvalidQuery, keyDeviceID)
		}
		ids = append(ids, trimmedNonEmpty([]string{s})...)
	}
	if v, ok := m[keyDeviceIDs]; ok {
		switch t := v.(type) {
		case []string:
			ids = append(ids, trimmedNonEmpty(t)...)
		case []interface{}:
			strs := make([]string, 0, len(t))
			for _, e := range t {
				s, isStr := e.(string)
				if !isStr {
					return nil, fmt.Errorf("%w: %s entries must be strings", interfaces.ErrInvalidQuery, keyDeviceIDs)
				}
				strs = append(strs, s)
			}
			ids = append(ids, trimmedNonEmpty(strs)...)
		case string:
			ids = append(ids, trimmedNonEmpty(strings.Split(t, ","))...)
		default:
			return nil, fmt.Errorf("%w: %s must be a list or comma-separated string", interfaces.ErrInvalidQuery, keyDeviceIDs)
		}
	}
	return ids, nil
}

func trimmedNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// unionDeviceIDs merges lists, de-duplicated, in first-seen order.
func unionDeviceIDs(lists ...[]string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, l := range lists {
		for _, id := range l {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// authorizeDevices checks every device ID against the tenant's subtree before any
// provider call. Unknown and foreign devices fail identically.
func (b *CustomReportBuilder) authorizeDevices(ctx context.Context, tenantID string, deviceIDs []string) error {
	if len(deviceIDs) == 0 {
		return nil
	}
	if b.devices == nil || b.ancestry == nil {
		return errCustomDeviceScopeUnverifiable
	}
	for _, id := range deviceIDs {
		owner, known := b.devices.TenantForDevice(id)
		if !known || owner == "" {
			return errCustomDeviceOutsideTenant
		}
		if owner == tenantID {
			continue
		}
		ok, err := b.ancestry(ctx, tenantID, owner)
		if err != nil || !ok {
			return errCustomDeviceOutsideTenant
		}
	}
	return nil
}

// checkTenant refuses an empty or root tenant.
func (b *CustomReportBuilder) checkTenant(tenantID string) error {
	if tenantID == "" {
		return errEmptyTenant
	}
	if tenantID == b.rootID {
		return errRootTenantRefused
	}
	return nil
}

// querySpec is everything needed to fetch a report's rows; it is also what a stream token
// stores.
type querySpec struct {
	tenantID  string
	sources   []string
	timeRange interfaces.TimeRange
	deviceIDs []string
	filters   map[string]string
	pageSize  int
	timeout   time.Duration
}

func (s querySpec) dataQuery() interfaces.DataQuery {
	return interfaces.DataQuery{
		TimeRange: s.timeRange,
		DeviceIDs: s.deviceIDs,
		TenantIDs: []string{s.tenantID},
		Filters:   s.filters,
	}
}

// prepare validates the request and returns the authorized spec. No provider call happens
// before it succeeds.
func (b *CustomReportBuilder) prepare(ctx context.Context, req interfaces.CustomReportRequest) (*querySpec, *interfaces.ProcessedQuery, error) {
	if err := b.checkTenant(req.TenantID); err != nil {
		return nil, nil, err
	}
	if len(req.Parameters) > b.cfg.MaxParameters {
		return nil, nil, fmt.Errorf("%w: %d parameters, maximum is %d", interfaces.ErrInvalidQuery, len(req.Parameters), b.cfg.MaxParameters)
	}
	if err := b.ValidateParameters(&interfaces.CustomReportTemplate{Parameters: req.Parameters}, req.UserParams); err != nil {
		return nil, nil, err
	}
	userDevices, err := deviceIDsFromMap(req.UserParams)
	if err != nil {
		return nil, nil, err
	}
	processed, err := b.buildQuery(req.TenantID, req.Query, userDevices)
	if err != nil {
		return nil, nil, err
	}
	filterDevices, err := deviceIDsFromMap(req.Query.Filters)
	if err != nil {
		return nil, nil, err
	}
	devices := unionDeviceIDs(filterDevices, userDevices)
	if err := b.authorizeDevices(ctx, req.TenantID, devices); err != nil {
		return nil, nil, err
	}
	filters, err := dataQueryFilters(req.Query.Filters)
	if err != nil {
		return nil, nil, err
	}
	pageSize := b.cfg.DefaultPageSize
	if p := req.Query.Pagination; p != nil && p.PageSize > 0 {
		pageSize = p.PageSize
	}
	if pageSize > b.cfg.MaxPageSize {
		pageSize = b.cfg.MaxPageSize
	}
	return &querySpec{
		tenantID:  req.TenantID,
		sources:   processed.DataSources,
		timeRange: req.Query.TimeRange,
		deviceIDs: devices,
		filters:   filters,
		pageSize:  pageSize,
		timeout:   processed.Timeout,
	}, processed, nil
}

// fetch reads the rows of every requested source. Provider errors are returned.
func (b *CustomReportBuilder) fetch(ctx context.Context, spec *querySpec) (*interfaces.ReportData, error) {
	q := spec.dataQuery()
	data := &interfaces.ReportData{
		TimeRange:   spec.timeRange,
		DeviceStats: map[string]interfaces.DeviceStats{},
		TrendData:   map[string][]interfaces.TrendPoint{},
	}
	wants := func(s string) bool { return containsString(spec.sources, s) }

	var dna []storage.DNARecord
	if wants(sourceDNA) || wants(sourceDeviceStats) {
		var err error
		dna, err = b.provider.GetDNAData(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("failed to get DNA data: %w", err)
		}
		if wants(sourceDNA) {
			data.DNARecords = dna
		}
	}
	if wants(sourceDrift) {
		events, err := b.provider.GetDriftEvents(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("failed to get drift events: %w", err)
		}
		data.DriftEvents = events
	}
	if wants(sourceDeviceStats) {
		// GetDeviceStats takes no tenant: ask only for authorized named devices, or for
		// devices found in the tenant-scoped DNA rows.
		ids := spec.deviceIDs
		if len(ids) == 0 {
			ids = distinctDeviceIDs(dna)
		}
		if len(ids) > 0 {
			stats, err := b.provider.GetDeviceStats(ctx, ids, spec.timeRange)
			if err != nil {
				return nil, fmt.Errorf("failed to get device stats: %w", err)
			}
			data.DeviceStats = stats
		}
	}
	if wants(sourceTrends) {
		for _, metric := range scopedTrendMetrics {
			points, err := b.provider.GetTrendData(ctx, metric, q)
			if err != nil {
				return nil, fmt.Errorf("failed to get trend data: %w", err)
			}
			data.TrendData[metric] = points
		}
	}
	return data, nil
}

func rowCount(d *interfaces.ReportData) int {
	n := len(d.DNARecords) + len(d.DriftEvents) + len(d.DeviceStats)
	for _, pts := range d.TrendData {
		n += len(pts)
	}
	return n
}

func maxSourceRows(d *interfaces.ReportData) int {
	m := max(len(d.DNARecords), len(d.DriftEvents), len(d.DeviceStats))
	for _, pts := range d.TrendData {
		m = max(m, len(pts))
	}
	return m
}

// streamEntry is the page-cache record behind a stream token.
type streamEntry struct {
	spec querySpec
}

// CreateCustomReport validates req, builds its query and generates the report.
func (b *CustomReportBuilder) CreateCustomReport(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	return b.generate(ctx, req)
}

// GenerateReport validates req, builds its query and generates the report, or above the
// streaming threshold returns a streamed report whose pages GetReportData serves.
func (b *CustomReportBuilder) GenerateReport(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	return b.generate(ctx, req)
}

func (b *CustomReportBuilder) generate(ctx context.Context, req interfaces.CustomReportRequest) (*interfaces.CustomReport, error) {
	spec, _, err := b.prepare(ctx, req)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	fetchCtx, cancel := context.WithTimeout(ctx, spec.timeout)
	defer cancel()
	data, err := b.fetch(fetchCtx, spec)
	if err != nil {
		return nil, err
	}

	report := &interfaces.CustomReport{
		ID:          uuid.NewString(),
		Name:        req.Name,
		Description: req.Description,
		TenantID:    req.TenantID,
		CreatedBy:   req.CreatedBy,
		CreatedAt:   start,
		Query:       req.Query,
		Parameters:  req.Parameters,
		UserParams:  req.UserParams,
		Summary:     (&Engine{}).generateReportSummary(data),
		Format:      req.Format,
		DataPoints:  rowCount(data),
	}
	if b.cfg.EnableStreaming && report.DataPoints > b.cfg.StreamThreshold {
		token, err := b.issueToken(spec)
		if err != nil {
			return nil, err
		}
		report.IsStreamed = true
		report.StreamToken = token
		report.TotalPages = (maxSourceRows(data) + spec.pageSize - 1) / spec.pageSize
	} else {
		report.Data = data
	}
	report.GeneratedAt = time.Now()
	report.GenerationMS = report.GeneratedAt.Sub(start).Milliseconds()
	return report, nil
}

func (b *CustomReportBuilder) issueToken(spec *querySpec) (string, error) {
	raw := make([]byte, streamTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate stream token: %w", err)
	}
	token := hex.EncodeToString(raw)
	if err := b.pageCache.Set(tokenKey(token), &streamEntry{spec: *spec}, b.cfg.CacheTTL); err != nil {
		return "", fmt.Errorf("failed to store stream token: %w", err)
	}
	return token, nil
}

func tokenKey(token string) string { return "token:" + token }

func pageKey(tenantID, token string, page, size int) string {
	return "page:" + tenantID + ":" + token + ":" + strconv.Itoa(page) + ":" + strconv.Itoa(size)
}

func validToken(token string) bool {
	if len(token) != 2*streamTokenBytes {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

// pageView is the JSON body of one stream page.
type pageView struct {
	Page     int                    `json:"page"`
	PageSize int                    `json:"page_size"`
	Data     *interfaces.ReportData `json:"data"`
}

// GetReportData returns one page of a streamed report and whether more pages follow. Pages
// are 1-based. A token that is unknown, expired, malformed or issued to another tenant is
// ErrStreamTokenInvalid.
func (b *CustomReportBuilder) GetReportData(ctx context.Context, pagination interfaces.PaginationRequest) ([]byte, bool, error) {
	if pagination.TenantID == "" {
		return nil, false, errEmptyTenant
	}
	if !validToken(pagination.StreamToken) {
		return nil, false, interfaces.ErrStreamTokenInvalid
	}
	v, ok := b.pageCache.Get(tokenKey(pagination.StreamToken))
	entry, isEntry := v.(*streamEntry)
	if !ok || !isEntry || entry.spec.tenantID != pagination.TenantID {
		return nil, false, interfaces.ErrStreamTokenInvalid
	}
	if err := b.checkTenant(pagination.TenantID); err != nil {
		return nil, false, err
	}
	if pagination.Page < 1 || pagination.PageSize < 0 {
		return nil, false, fmt.Errorf("%w: invalid page", interfaces.ErrInvalidQuery)
	}
	spec := entry.spec
	if pagination.PageSize > 0 {
		spec.pageSize = min(pagination.PageSize, b.cfg.MaxPageSize)
	}
	// Page is caller-supplied: reject values whose row offsets (Page-1)*pageSize and
	// Page*pageSize would overflow int, which would otherwise wrap negative.
	if pagination.Page-1 > (math.MaxInt-spec.pageSize)/spec.pageSize {
		return nil, false, fmt.Errorf("%w: invalid page", interfaces.ErrInvalidQuery)
	}

	// Device ownership can change after the token was issued.
	if err := b.authorizeDevices(ctx, spec.tenantID, spec.deviceIDs); err != nil {
		return nil, false, err
	}

	key := pageKey(spec.tenantID, pagination.StreamToken, pagination.Page, spec.pageSize)
	if cached, hit := b.pageCache.Get(key); hit {
		if page, isPage := cached.(*cachedPage); isPage {
			return page.body, page.more, nil
		}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, spec.timeout)
	defer cancel()
	data, err := b.fetch(fetchCtx, &spec)
	if err != nil {
		return nil, false, err
	}
	from := (pagination.Page - 1) * spec.pageSize
	to := from + spec.pageSize
	more := to < maxSourceRows(data)
	body, err := json.Marshal(pageView{Page: pagination.Page, PageSize: spec.pageSize, Data: slicePage(data, from, to)})
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode page: %w", err)
	}
	if err := b.pageCache.Set(key, &cachedPage{body: body, more: more}, b.cfg.CacheTTL); err != nil {
		return nil, false, fmt.Errorf("failed to cache page: %w", err)
	}
	return body, more, nil
}

type cachedPage struct {
	body []byte
	more bool
}

func window[T any](in []T, from, to int) []T {
	if from < 0 || to < from || from >= len(in) {
		return nil
	}
	return in[from:min(to, len(in))]
}

func slicePage(d *interfaces.ReportData, from, to int) *interfaces.ReportData {
	out := &interfaces.ReportData{
		DNARecords:  window(d.DNARecords, from, to),
		DriftEvents: window[drift.DriftEvent](d.DriftEvents, from, to),
		TimeRange:   d.TimeRange,
		DeviceStats: map[string]interfaces.DeviceStats{},
		TrendData:   map[string][]interfaces.TrendPoint{},
	}
	ids := make([]string, 0, len(d.DeviceStats))
	for id := range d.DeviceStats {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range window(ids, from, to) {
		out.DeviceStats[id] = d.DeviceStats[id]
	}
	for metric, pts := range d.TrendData {
		out.TrendData[metric] = window(pts, from, to)
	}
	return out
}
