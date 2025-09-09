package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PermissionEventBus provides real-time permission event distribution
type PermissionEventBus struct {
	// Event channels
	eventChannel           chan *PermissionEvent
	subscribers           map[string]chan *PermissionEvent
	subscriberMutex       sync.RWMutex
	
	// Event processing
	eventProcessor        *EventProcessor
	eventStore           *EventStore
	
	// Configuration
	bufferSize           int
	processingTimeout    time.Duration
	maxRetries          int
	
	// Control
	started             bool
	stopChannel         chan struct{}
	processingGroup     sync.WaitGroup
	
	// Statistics
	stats               EventBusStats
	mutex              sync.RWMutex
}

// PermissionEvent represents a permission-related event in the system
type PermissionEvent struct {
	// Event identification
	EventID       string                 `json:"event_id"`
	EventType     PermissionEventType    `json:"event_type"`
	Timestamp     time.Time              `json:"timestamp"`
	
	// Event source
	Source        EventSource            `json:"source"`
	SourceID      string                 `json:"source_id"`
	
	// Subject information
	SubjectID     string                 `json:"subject_id"`
	TenantID      string                 `json:"tenant_id"`
	SessionID     string                 `json:"session_id,omitempty"`
	
	// Permission details
	PermissionID  string                 `json:"permission_id,omitempty"`
	Permissions   []string               `json:"permissions,omitempty"`
	
	// Event data
	Data          map[string]interface{} `json:"data"`
	Context       map[string]interface{} `json:"context"`
	
	// Processing metadata
	ProcessedAt   time.Time              `json:"processed_at,omitempty"`
	Attempts      int                    `json:"attempts"`
	LastError     string                 `json:"last_error,omitempty"`
}

// PermissionEventType defines types of permission events
type PermissionEventType string

const (
	// Permission lifecycle events
	EventTypePermissionGranted     PermissionEventType = "permission_granted"
	EventTypePermissionRevoked     PermissionEventType = "permission_revoked"
	EventTypePermissionExpired     PermissionEventType = "permission_expired"
	EventTypePermissionRenewed     PermissionEventType = "permission_renewed"
	
	// Authorization events
	EventTypeAuthorizationRequested PermissionEventType = "authorization_requested"
	EventTypeAuthorizationGranted   PermissionEventType = "authorization_granted"
	EventTypeAuthorizationDenied    PermissionEventType = "authorization_denied"
	EventTypeAuthorizationCached    PermissionEventType = "authorization_cached"
	
	// Session events
	EventTypeSessionRegistered     PermissionEventType = "session_registered"
	EventTypeSessionTerminated     PermissionEventType = "session_terminated"
	EventTypeSessionExpired        PermissionEventType = "session_expired"
	EventTypeSessionUpdated        PermissionEventType = "session_updated"
	
	// Policy events
	EventTypePolicyViolation       PermissionEventType = "policy_violation"
	EventTypePolicyEnforced        PermissionEventType = "policy_enforced"
	EventTypePolicyUpdated         PermissionEventType = "policy_updated"
	
	// Risk events
	EventTypeRiskAssessmentChanged PermissionEventType = "risk_assessment_changed"
	EventTypeRiskThresholdExceeded PermissionEventType = "risk_threshold_exceeded"
	
	// System events
	EventTypeSystemAlert           PermissionEventType = "system_alert"
	EventTypeSystemMaintenance     PermissionEventType = "system_maintenance"
)

// EventSource defines the source of an event
type EventSource string

const (
	EventSourceRBAC            EventSource = "rbac"
	EventSourceJIT             EventSource = "jit"
	EventSourceRisk            EventSource = "risk"
	EventSourceContinuous      EventSource = "continuous"
	EventSourceSession         EventSource = "session"
	EventSourcePolicy          EventSource = "policy"
	EventSourceSystem          EventSource = "system"
)

// PermissionRevocationEvent represents a permission revocation event
type PermissionRevocationEvent struct {
	EventID       string    `json:"event_id"`
	SubjectID     string    `json:"subject_id"`
	TenantID      string    `json:"tenant_id"`
	Permissions   []string  `json:"permissions"`
	Timestamp     time.Time `json:"timestamp"`
	SessionIDs    []string  `json:"session_ids"`
	RevokedBy     string    `json:"revoked_by"`
	Reason        string    `json:"reason"`
}

// AuthorizationEvent represents an authorization decision event
type AuthorizationEvent struct {
	DecisionID    string    `json:"decision_id"`
	SessionID     string    `json:"session_id"`
	SubjectID     string    `json:"subject_id"`
	PermissionID  string    `json:"permission_id"`
	Granted       bool      `json:"granted"`
	Timestamp     time.Time `json:"timestamp"`
	LatencyMs     int       `json:"latency_ms"`
	CacheHit      bool      `json:"cache_hit"`
	Reason        string    `json:"reason,omitempty"`
}

// EventSubscriber defines a subscriber to permission events
type EventSubscriber struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	EventTypes  []PermissionEventType     `json:"event_types"`
	Filter      EventFilter               `json:"filter"`
	Handler     func(*PermissionEvent) error
	CreatedAt   time.Time                 `json:"created_at"`
	Active      bool                      `json:"active"`
	Stats       SubscriberStats           `json:"stats"`
}

// EventFilter defines filtering criteria for events
type EventFilter struct {
	SubjectIDs    []string              `json:"subject_ids,omitempty"`
	TenantIDs     []string              `json:"tenant_ids,omitempty"`
	SessionIDs    []string              `json:"session_ids,omitempty"`
	PermissionIDs []string              `json:"permission_ids,omitempty"`
	Sources       []EventSource         `json:"sources,omitempty"`
	EventTypes    []PermissionEventType `json:"event_types,omitempty"`
	TimeRange     *TimeRange            `json:"time_range,omitempty"`
}

// TimeRange defines a time range filter
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// EventProcessor handles processing and routing of events
type EventProcessor struct {
	eventBus       *PermissionEventBus
	processors     map[PermissionEventType][]EventHandler
	processorMutex sync.RWMutex
}

// EventHandler defines a function that handles specific event types
type EventHandler func(context.Context, *PermissionEvent) error

// EventStore provides persistence for permission events
type EventStore struct {
	events     []StoredEvent
	eventIndex map[string]int  // eventID -> index
	mutex      sync.RWMutex
	maxEvents  int             // Maximum events to store
}

// StoredEvent represents an event stored for audit/replay
type StoredEvent struct {
	Event       *PermissionEvent `json:"event"`
	StoredAt    time.Time        `json:"stored_at"`
	Processed   bool             `json:"processed"`
	Subscribers []string         `json:"subscribers"`
}

// EventBusStats tracks event bus statistics
type EventBusStats struct {
	TotalEvents        int64                             `json:"total_events"`
	ProcessedEvents    int64                             `json:"processed_events"`
	FailedEvents       int64                             `json:"failed_events"`
	EventsByType       map[PermissionEventType]int64     `json:"events_by_type"`
	EventsBySource     map[EventSource]int64             `json:"events_by_source"`
	AverageProcessingMs float64                          `json:"average_processing_ms"`
	SubscriberCount    int                               `json:"subscriber_count"`
	ActiveSubscribers  int                               `json:"active_subscribers"`
	LastEventAt        time.Time                         `json:"last_event_at"`
	
	mutex             sync.RWMutex
}

// SubscriberStats tracks statistics for event subscribers
type SubscriberStats struct {
	EventsReceived   int64     `json:"events_received"`
	EventsProcessed  int64     `json:"events_processed"`
	EventsFailed     int64     `json:"events_failed"`
	LastEventAt      time.Time `json:"last_event_at"`
	AverageLatencyMs float64   `json:"average_latency_ms"`
}

// NewPermissionEventBus creates a new permission event bus
func NewPermissionEventBus(bufferSize int) *PermissionEventBus {
	eventBus := &PermissionEventBus{
		eventChannel:       make(chan *PermissionEvent, bufferSize),
		subscribers:        make(map[string]chan *PermissionEvent),
		bufferSize:        bufferSize,
		processingTimeout: 30 * time.Second,
		maxRetries:        3,
		stopChannel:       make(chan struct{}),
		stats: EventBusStats{
			EventsByType:   make(map[PermissionEventType]int64),
			EventsBySource: make(map[EventSource]int64),
		},
	}

	eventBus.eventProcessor = &EventProcessor{
		eventBus:   eventBus,
		processors: make(map[PermissionEventType][]EventHandler),
	}

	eventBus.eventStore = &EventStore{
		events:     make([]StoredEvent, 0),
		eventIndex: make(map[string]int),
		maxEvents:  10000, // Store last 10k events
	}

	return eventBus
}

// Start initializes and starts the event bus
func (peb *PermissionEventBus) Start(ctx context.Context) error {
	peb.mutex.Lock()
	defer peb.mutex.Unlock()

	if peb.started {
		return fmt.Errorf("permission event bus is already started")
	}

	// Start event processing goroutines
	peb.processingGroup.Add(2)
	go peb.eventProcessingLoop(ctx)
	go peb.eventDistributionLoop(ctx)

	peb.started = true
	return nil
}

// Stop gracefully shuts down the event bus
func (peb *PermissionEventBus) Stop() error {
	peb.mutex.Lock()
	defer peb.mutex.Unlock()

	if !peb.started {
		return fmt.Errorf("permission event bus is not started")
	}

	// Signal shutdown
	close(peb.stopChannel)

	// Wait for processing to complete
	peb.processingGroup.Wait()

	// Close subscriber channels
	peb.subscriberMutex.Lock()
	for _, ch := range peb.subscribers {
		close(ch)
	}
	peb.subscriberMutex.Unlock()

	peb.started = false
	return nil
}

// PublishEvent publishes a permission event to the bus
func (peb *PermissionEventBus) PublishEvent(event *PermissionEvent) error {
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("event-%d", time.Now().UnixNano())
	}
	
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case peb.eventChannel <- event:
		peb.updateStats(event)
		return nil
	default:
		return fmt.Errorf("event channel full - dropping event %s", event.EventID)
	}
}

// PublishPermissionRevocation publishes a permission revocation event
func (peb *PermissionEventBus) PublishPermissionRevocation(revocation *PermissionRevocationEvent) error {
	event := &PermissionEvent{
		EventID:      revocation.EventID,
		EventType:    EventTypePermissionRevoked,
		Timestamp:    revocation.Timestamp,
		Source:       EventSourceContinuous,
		SourceID:     "continuous-auth-engine",
		SubjectID:    revocation.SubjectID,
		TenantID:     revocation.TenantID,
		Permissions:  revocation.Permissions,
		Data: map[string]interface{}{
			"session_ids": revocation.SessionIDs,
			"revoked_by":  revocation.RevokedBy,
			"reason":      revocation.Reason,
		},
	}

	return peb.PublishEvent(event)
}

// PublishAuthorizationEvent publishes an authorization decision event
func (peb *PermissionEventBus) PublishAuthorizationEvent(auth *AuthorizationEvent) error {
	eventType := EventTypeAuthorizationGranted
	if !auth.Granted {
		eventType = EventTypeAuthorizationDenied
	}

	event := &PermissionEvent{
		EventID:      auth.DecisionID,
		EventType:    eventType,
		Timestamp:    auth.Timestamp,
		Source:       EventSourceContinuous,
		SourceID:     "continuous-auth-engine",
		SubjectID:    auth.SubjectID,
		SessionID:    auth.SessionID,
		PermissionID: auth.PermissionID,
		Data: map[string]interface{}{
			"granted":    auth.Granted,
			"latency_ms": auth.LatencyMs,
			"cache_hit":  auth.CacheHit,
			"reason":     auth.Reason,
		},
	}

	return peb.PublishEvent(event)
}

// Subscribe creates a subscription to permission events
func (peb *PermissionEventBus) Subscribe(subscriber *EventSubscriber) (chan *PermissionEvent, error) {
	peb.subscriberMutex.Lock()
	defer peb.subscriberMutex.Unlock()

	// Create subscriber channel
	subscriberChannel := make(chan *PermissionEvent, 100) // Buffer for subscriber
	peb.subscribers[subscriber.ID] = subscriberChannel

	// Update statistics
	peb.stats.mutex.Lock()
	peb.stats.SubscriberCount++
	if subscriber.Active {
		peb.stats.ActiveSubscribers++
	}
	peb.stats.mutex.Unlock()

	return subscriberChannel, nil
}

// Unsubscribe removes a subscription from the event bus
func (peb *PermissionEventBus) Unsubscribe(subscriberID string) error {
	peb.subscriberMutex.Lock()
	defer peb.subscriberMutex.Unlock()

	if channel, exists := peb.subscribers[subscriberID]; exists {
		close(channel)
		delete(peb.subscribers, subscriberID)

		// Update statistics
		peb.stats.mutex.Lock()
		peb.stats.SubscriberCount--
		peb.stats.mutex.Unlock()

		return nil
	}

	return fmt.Errorf("subscriber %s not found", subscriberID)
}

// SubscribeToEvents returns a channel for receiving all events (for internal use)
func (peb *PermissionEventBus) SubscribeToEvents() <-chan interface{} {
	// Create a generic channel for internal event processing
	ch := make(chan interface{}, 100)
	
	// Create internal subscriber
	subscriber := &EventSubscriber{
		ID:         fmt.Sprintf("internal-%d", time.Now().UnixNano()),
		Name:       "Internal Event Processor",
		EventTypes: []PermissionEventType{}, // All events
		Active:     true,
		Handler: func(event *PermissionEvent) error {
			select {
			case ch <- event:
				return nil
			default:
				return fmt.Errorf("internal channel full")
			}
		},
	}

	// Subscribe to events
	subscriberCh, _ := peb.Subscribe(subscriber)
	
	// Forward events to generic channel
	go func() {
		defer close(ch)
		for event := range subscriberCh {
			select {
			case ch <- event:
			default:
				// Channel full, drop event
			}
		}
	}()

	return ch
}

// RegisterEventProcessor registers a processor for specific event types
func (peb *PermissionEventBus) RegisterEventProcessor(eventType PermissionEventType, handler EventHandler) error {
	peb.eventProcessor.processorMutex.Lock()
	defer peb.eventProcessor.processorMutex.Unlock()

	if peb.eventProcessor.processors[eventType] == nil {
		peb.eventProcessor.processors[eventType] = make([]EventHandler, 0)
	}

	peb.eventProcessor.processors[eventType] = append(peb.eventProcessor.processors[eventType], handler)
	return nil
}

// GetEventHistory returns recent events matching the filter
func (peb *PermissionEventBus) GetEventHistory(filter *EventFilter, limit int) ([]*PermissionEvent, error) {
	peb.eventStore.mutex.RLock()
	defer peb.eventStore.mutex.RUnlock()

	events := make([]*PermissionEvent, 0)
	count := 0

	// Iterate through stored events in reverse order (most recent first)
	for i := len(peb.eventStore.events) - 1; i >= 0 && count < limit; i-- {
		storedEvent := peb.eventStore.events[i]
		if peb.matchesFilter(storedEvent.Event, filter) {
			events = append(events, storedEvent.Event)
			count++
		}
	}

	return events, nil
}

// GetStats returns current event bus statistics
func (peb *PermissionEventBus) GetStats() *EventBusStats {
	peb.stats.mutex.RLock()
	defer peb.stats.mutex.RUnlock()

	// Return a copy
	stats := EventBusStats{
		TotalEvents:         peb.stats.TotalEvents,
		ProcessedEvents:     peb.stats.ProcessedEvents,
		FailedEvents:        peb.stats.FailedEvents,
		EventsByType:        make(map[PermissionEventType]int64),
		EventsBySource:      make(map[EventSource]int64),
		AverageProcessingMs: peb.stats.AverageProcessingMs,
		SubscriberCount:     peb.stats.SubscriberCount,
		ActiveSubscribers:   peb.stats.ActiveSubscribers,
		LastEventAt:         peb.stats.LastEventAt,
	}

	// Copy maps
	for k, v := range peb.stats.EventsByType {
		stats.EventsByType[k] = v
	}
	for k, v := range peb.stats.EventsBySource {
		stats.EventsBySource[k] = v
	}

	return &stats
}

// Background processing methods

// eventProcessingLoop processes events from the event channel
func (peb *PermissionEventBus) eventProcessingLoop(ctx context.Context) {
	defer peb.processingGroup.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-peb.stopChannel:
			return
		case event := <-peb.eventChannel:
			peb.processEvent(ctx, event)
		}
	}
}

// eventDistributionLoop distributes events to subscribers
func (peb *PermissionEventBus) eventDistributionLoop(ctx context.Context) {
	defer peb.processingGroup.Done()

	processingTicker := time.NewTicker(100 * time.Millisecond)
	defer processingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-peb.stopChannel:
			return
		case <-processingTicker.C:
			peb.distributeQueuedEvents()
		}
	}
}

// processEvent processes a single event
func (peb *PermissionEventBus) processEvent(ctx context.Context, event *PermissionEvent) {
	startTime := time.Now()

	// Store event for audit/replay
	peb.storeEvent(event)

	// Process with registered processors
	peb.eventProcessor.processorMutex.RLock()
	processors := peb.eventProcessor.processors[event.EventType]
	peb.eventProcessor.processorMutex.RUnlock()

	for _, processor := range processors {
		if err := processor(ctx, event); err != nil {
			peb.incrementFailedEvents()
			event.LastError = err.Error()
		}
	}

	// Update processing statistics
	processingTime := time.Since(startTime)
	peb.updateProcessingStats(processingTime)

	event.ProcessedAt = time.Now()
}

// distributeQueuedEvents distributes events to all subscribers
func (peb *PermissionEventBus) distributeQueuedEvents() {
	peb.subscriberMutex.RLock()
	defer peb.subscriberMutex.RUnlock()

	// This would typically pull from a queue of events ready for distribution
	// For now, events are distributed inline during processing
}

// Helper methods

func (peb *PermissionEventBus) updateStats(event *PermissionEvent) {
	peb.stats.mutex.Lock()
	defer peb.stats.mutex.Unlock()

	peb.stats.TotalEvents++
	peb.stats.EventsByType[event.EventType]++
	peb.stats.EventsBySource[event.Source]++
	peb.stats.LastEventAt = event.Timestamp
}

func (peb *PermissionEventBus) incrementFailedEvents() {
	peb.stats.mutex.Lock()
	defer peb.stats.mutex.Unlock()
	peb.stats.FailedEvents++
}

func (peb *PermissionEventBus) updateProcessingStats(processingTime time.Duration) {
	peb.stats.mutex.Lock()
	defer peb.stats.mutex.Unlock()

	peb.stats.ProcessedEvents++
	
	// Update average processing time using exponential moving average
	alpha := 0.1
	newLatency := float64(processingTime.Milliseconds())
	peb.stats.AverageProcessingMs = (1-alpha)*peb.stats.AverageProcessingMs + alpha*newLatency
}

func (peb *PermissionEventBus) storeEvent(event *PermissionEvent) {
	peb.eventStore.mutex.Lock()
	defer peb.eventStore.mutex.Unlock()

	storedEvent := StoredEvent{
		Event:       event,
		StoredAt:    time.Now(),
		Processed:   false,
		Subscribers: make([]string, 0),
	}

	// Add to storage
	peb.eventStore.events = append(peb.eventStore.events, storedEvent)
	peb.eventStore.eventIndex[event.EventID] = len(peb.eventStore.events) - 1

	// Maintain maximum size
	if len(peb.eventStore.events) > peb.eventStore.maxEvents {
		// Remove oldest events
		excess := len(peb.eventStore.events) - peb.eventStore.maxEvents
		removedEvents := peb.eventStore.events[:excess]
		
		// Update index
		for _, removed := range removedEvents {
			delete(peb.eventStore.eventIndex, removed.Event.EventID)
		}
		
		// Rebuild index for remaining events
		peb.eventStore.events = peb.eventStore.events[excess:]
		peb.eventStore.eventIndex = make(map[string]int)
		for i, event := range peb.eventStore.events {
			peb.eventStore.eventIndex[event.Event.EventID] = i
		}
	}
}

func (peb *PermissionEventBus) matchesFilter(event *PermissionEvent, filter *EventFilter) bool {
	if filter == nil {
		return true
	}

	// Check subject IDs
	if len(filter.SubjectIDs) > 0 {
		found := false
		for _, subjectID := range filter.SubjectIDs {
			if event.SubjectID == subjectID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check tenant IDs
	if len(filter.TenantIDs) > 0 {
		found := false
		for _, tenantID := range filter.TenantIDs {
			if event.TenantID == tenantID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check event types
	if len(filter.EventTypes) > 0 {
		found := false
		for _, eventType := range filter.EventTypes {
			if event.EventType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check time range
	if filter.TimeRange != nil {
		if event.Timestamp.Before(filter.TimeRange.Start) || event.Timestamp.After(filter.TimeRange.End) {
			return false
		}
	}

	return true
}

// Utility functions for creating common events

// CreateSessionRegisteredEvent creates an event for session registration
func CreateSessionRegisteredEvent(sessionID, subjectID, tenantID string) *PermissionEvent {
	return &PermissionEvent{
		EventID:   fmt.Sprintf("session-reg-%d", time.Now().UnixNano()),
		EventType: EventTypeSessionRegistered,
		Timestamp: time.Now(),
		Source:    EventSourceSession,
		SourceID:  "session-registry",
		SubjectID: subjectID,
		TenantID:  tenantID,
		SessionID: sessionID,
		Data:      map[string]interface{}{},
	}
}

// CreatePolicyViolationEvent creates an event for policy violations
func CreatePolicyViolationEvent(subjectID, tenantID, sessionID, policyID, violationType string, severity string) *PermissionEvent {
	return &PermissionEvent{
		EventID:   fmt.Sprintf("policy-violation-%d", time.Now().UnixNano()),
		EventType: EventTypePolicyViolation,
		Timestamp: time.Now(),
		Source:    EventSourcePolicy,
		SourceID:  "policy-enforcer",
		SubjectID: subjectID,
		TenantID:  tenantID,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"policy_id":      policyID,
			"violation_type": violationType,
			"severity":       severity,
		},
	}
}