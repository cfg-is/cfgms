// Package events provides DNA change event publisher implementation.

package events

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// publisher implements the EventPublisher interface.
type publisher struct {
	logger logging.Logger
	config *PublisherConfig

	// Subscriber registry
	subscribers   map[string][]subscriberRegistration
	subscribersMu sync.RWMutex

	// Worker pool
	workers    []*eventWorker
	eventQueue chan *eventTask

	// State management
	running   bool
	runningMu sync.RWMutex
	stopChan  chan struct{}
	workerWg  sync.WaitGroup

	// Statistics
	stats     *PublisherStats
	statsMu   sync.RWMutex
	startTime time.Time
}

// subscriberRegistration holds a subscriber with its info.
type subscriberRegistration struct {
	subscriber EventSubscriber
	info       *SubscriberInfo
}

// eventTask represents a task for the worker pool.
type eventTask struct {
	eventType   string
	event       *DNAChangeEvent
	subscribers []subscriberRegistration
	timestamp   time.Time
}

// eventWorker processes event tasks from the queue.
type eventWorker struct {
	id        int
	publisher *publisher
	stopChan  chan struct{}
}

// NewPublisher creates a new DNA change event publisher.
func NewPublisher(logger logging.Logger, config *PublisherConfig) EventPublisher {
	if config == nil {
		config = DefaultPublisherConfig()
	}

	p := &publisher{
		logger:      logger,
		config:      config,
		subscribers: make(map[string][]subscriberRegistration),
		eventQueue:  make(chan *eventTask, config.QueueSize),
		stopChan:    make(chan struct{}),
		stats: &PublisherStats{
			SubscriberFailures: make(map[string]int64),
		},
	}

	if logger != nil {
		logger.Info("Event publisher created",
			"worker_count", config.WorkerCount,
			"queue_size", config.QueueSize)
	}

	return p
}

// Subscribe registers a subscriber for specific event types.
func (p *publisher) Subscribe(eventType string, subscriber EventSubscriber) error {
	if eventType == "" {
		return fmt.Errorf("event type cannot be empty")
	}

	if subscriber == nil {
		return fmt.Errorf("subscriber cannot be nil")
	}

	info := subscriber.GetSubscriberInfo()
	if info.Name == "" {
		return fmt.Errorf("subscriber name cannot be empty")
	}

	p.subscribersMu.Lock()
	defer p.subscribersMu.Unlock()

	// Check for duplicate subscribers
	for _, reg := range p.subscribers[eventType] {
		if reg.info.Name == info.Name {
			return fmt.Errorf("subscriber %s is already registered for event type %s", info.Name, eventType)
		}
	}

	// Add subscriber
	registration := subscriberRegistration{
		subscriber: subscriber,
		info:       info,
	}

	p.subscribers[eventType] = append(p.subscribers[eventType], registration)

	// Sort by priority (highest first)
	sort.Slice(p.subscribers[eventType], func(i, j int) bool {
		return p.subscribers[eventType][i].info.Priority > p.subscribers[eventType][j].info.Priority
	})

	p.statsMu.Lock()
	p.stats.RegisteredSubscribers = p.countSubscribers()
	p.statsMu.Unlock()

	if p.logger != nil {
		p.logger.Info("Event subscriber registered",
			"event_type", eventType,
			"subscriber", info.Name,
			"priority", info.Priority,
			"async", info.Async)
	}

	return nil
}

// Unsubscribe removes a subscriber.
func (p *publisher) Unsubscribe(eventType string, subscriberName string) error {
	p.subscribersMu.Lock()
	defer p.subscribersMu.Unlock()

	subscribers, exists := p.subscribers[eventType]
	if !exists {
		return fmt.Errorf("no subscribers registered for event type %s", eventType)
	}

	// Find and remove subscriber
	for i, reg := range subscribers {
		if reg.info.Name == subscriberName {
			// Close the subscriber
			if err := reg.subscriber.Close(); err != nil && p.logger != nil {
				p.logger.Warn("Error closing subscriber", "name", subscriberName, "error", err)
			}

			// Remove from slice
			p.subscribers[eventType] = append(subscribers[:i], subscribers[i+1:]...)

			// Remove empty event type entries
			if len(p.subscribers[eventType]) == 0 {
				delete(p.subscribers, eventType)
			}

			p.statsMu.Lock()
			p.stats.RegisteredSubscribers = p.countSubscribers()
			p.statsMu.Unlock()

			if p.logger != nil {
				p.logger.Info("Event subscriber unregistered",
					"event_type", eventType,
					"subscriber", subscriberName)
			}

			return nil
		}
	}

	return fmt.Errorf("subscriber %s not found for event type %s", subscriberName, eventType)
}

// Publish publishes an event to all subscribers.
func (p *publisher) Publish(ctx context.Context, eventType string, event *DNAChangeEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	p.runningMu.RLock()
	if !p.running {
		p.runningMu.RUnlock()
		return fmt.Errorf("event publisher is not running")
	}
	p.runningMu.RUnlock()

	// Get subscribers for this event type
	p.subscribersMu.RLock()
	subscribers, exists := p.subscribers[eventType]
	if !exists || len(subscribers) == 0 {
		p.subscribersMu.RUnlock()
		return nil // No subscribers, not an error
	}

	// Make a copy to avoid holding the lock
	subscribersCopy := make([]subscriberRegistration, len(subscribers))
	copy(subscribersCopy, subscribers)
	p.subscribersMu.RUnlock()

	// Create task
	task := &eventTask{
		eventType:   eventType,
		event:       event,
		subscribers: subscribersCopy,
		timestamp:   time.Now(),
	}

	// Queue task for processing
	select {
	case p.eventQueue <- task:
		atomic.AddInt64(&p.stats.EventsPublished, 1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Queue is full
		switch p.config.QueueFullBehavior {
		case "drop":
			atomic.AddInt64(&p.stats.EventsFailed, 1)
			return fmt.Errorf("event queue is full, dropping event")
		case "expand":
			// Try to process immediately in current goroutine
			return p.processTask(ctx, task)
		default: // "block"
			select {
			case p.eventQueue <- task:
				atomic.AddInt64(&p.stats.EventsPublished, 1)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// Start begins event processing.
func (p *publisher) Start(ctx context.Context) error {
	p.runningMu.Lock()
	defer p.runningMu.Unlock()

	if p.running {
		return fmt.Errorf("event publisher is already running")
	}

	p.running = true
	p.startTime = time.Now()

	// Start workers
	p.workers = make([]*eventWorker, p.config.WorkerCount)
	for i := 0; i < p.config.WorkerCount; i++ {
		worker := &eventWorker{
			id:        i,
			publisher: p,
			stopChan:  make(chan struct{}),
		}
		p.workers[i] = worker

		p.workerWg.Add(1)
		go worker.run(ctx)
	}

	p.statsMu.Lock()
	p.stats.ActiveWorkers = len(p.workers)
	p.stats.StartTime = p.startTime
	p.statsMu.Unlock()

	if p.logger != nil {
		p.logger.Info("Event publisher started",
			"workers", len(p.workers),
			"queue_size", cap(p.eventQueue))
	}

	return nil
}

// Stop gracefully shuts down event processing.
func (p *publisher) Stop(ctx context.Context) error {
	p.runningMu.Lock()
	if !p.running {
		p.runningMu.Unlock()
		return nil
	}
	p.running = false
	p.runningMu.Unlock()

	if p.logger != nil {
		p.logger.Info("Stopping event publisher")
	}

	// Signal stop to all workers
	close(p.stopChan)
	for _, worker := range p.workers {
		close(worker.stopChan)
	}

	// Wait for workers to finish
	done := make(chan struct{})
	go func() {
		p.workerWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		break
	case <-ctx.Done():
		if p.logger != nil {
			p.logger.Warn("Event publisher stop timeout")
		}
		return ctx.Err()
	}

	// Close remaining subscribers
	p.subscribersMu.Lock()
	for eventType, subscribers := range p.subscribers {
		for _, reg := range subscribers {
			if err := reg.subscriber.Close(); err != nil && p.logger != nil {
				p.logger.Warn("Error closing subscriber during shutdown",
					"event_type", eventType,
					"subscriber", reg.info.Name,
					"error", err)
			}
		}
	}
	p.subscribersMu.Unlock()

	p.statsMu.Lock()
	p.stats.ActiveWorkers = 0
	p.statsMu.Unlock()

	if p.logger != nil {
		p.logger.Info("Event publisher stopped")
	}

	return nil
}

// GetStats returns publishing statistics.
func (p *publisher) GetStats() *PublisherStats {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()

	// Create a copy of the stats
	stats := *p.stats
	stats.SubscriberFailures = make(map[string]int64)
	for k, v := range p.stats.SubscriberFailures {
		stats.SubscriberFailures[k] = v
	}

	// Calculate current queue depth
	stats.QueueDepth = len(p.eventQueue)

	return &stats
}

// processTask processes an event task.
func (p *publisher) processTask(ctx context.Context, task *eventTask) error {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		p.statsMu.Lock()
		p.stats.EventsProcessed++
		p.stats.AverageProcessingTime = duration
		p.stats.LastEventTime = startTime
		p.statsMu.Unlock()
	}()

	// Process each subscriber
	var lastErr error
	for _, reg := range task.subscribers {
		// Apply timeout if specified
		subCtx := ctx
		if reg.info.Timeout > 0 {
			var cancel context.CancelFunc
			subCtx, cancel = context.WithTimeout(ctx, reg.info.Timeout)
			defer cancel()
		}

		// Execute subscriber
		if err := reg.subscriber.OnEvent(subCtx, task.event); err != nil {
			lastErr = err

			p.statsMu.Lock()
			p.stats.SubscriberFailures[reg.info.Name]++
			p.statsMu.Unlock()

			if p.logger != nil {
				p.logger.Error("Event subscriber failed",
					"subscriber", reg.info.Name,
					"event_type", task.eventType,
					"device_id", task.event.DeviceID,
					"error", err)
			}
		}
	}

	if lastErr != nil {
		atomic.AddInt64(&p.stats.EventsFailed, 1)
		return lastErr
	}

	return nil
}

// countSubscribers counts total subscribers across all event types.
func (p *publisher) countSubscribers() int {
	count := 0
	for _, subscribers := range p.subscribers {
		count += len(subscribers)
	}
	return count
}

// run processes events for a worker.
func (w *eventWorker) run(ctx context.Context) {
	defer w.publisher.workerWg.Done()

	if w.publisher.logger != nil {
		w.publisher.logger.Debug("Event worker started", "worker_id", w.id)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		case <-w.publisher.stopChan:
			return
		case task := <-w.publisher.eventQueue:
			if err := w.publisher.processTask(ctx, task); err != nil {
				if w.publisher.logger != nil {
					w.publisher.logger.Error("Failed to process event task", "error", err, "worker_id", w.id)
				}
			}
		}
	}
}
