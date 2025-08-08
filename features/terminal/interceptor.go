package terminal

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// CommandInterceptor intercepts and processes terminal commands for security filtering
type CommandInterceptor struct {
	securityValidator *SecurityValidator
	securityContext   *SessionSecurityContext
	auditChannel      chan<- *CommandAuditEvent
	
	// Command buffering for incomplete commands
	commandBuffer strings.Builder
	bufferMutex   sync.Mutex
	
	// State tracking
	commandStart  time.Time
	
	// Callbacks
	onCommandBlocked func(command string, reason string) error
	onCommandAudit   func(event *CommandAuditEvent) error
}

// NewCommandInterceptor creates a new command interceptor with security validation
func NewCommandInterceptor(validator *SecurityValidator, context *SessionSecurityContext, auditChan chan<- *CommandAuditEvent) *CommandInterceptor {
	return &CommandInterceptor{
		securityValidator: validator,
		securityContext:   context,
		auditChannel:      auditChan,
	}
}

// SetCallbacks sets callback functions for security events
func (ci *CommandInterceptor) SetCallbacks(
	onBlocked func(command string, reason string) error,
	onAudit func(event *CommandAuditEvent) error,
) {
	ci.onCommandBlocked = onBlocked
	ci.onCommandAudit = onAudit
}

// InterceptInput processes input data from the user and applies security filtering
func (ci *CommandInterceptor) InterceptInput(ctx context.Context, input []byte) ([]byte, error) {
	ci.bufferMutex.Lock()
	defer ci.bufferMutex.Unlock()
	
	// Process each byte of input
	var processedOutput bytes.Buffer
	
	for _, b := range input {
		switch b {
		case '\n', '\r':
			// Command completed, validate it
			if ci.commandBuffer.Len() > 0 {
				command := strings.TrimSpace(ci.commandBuffer.String())
				if command != "" {
					allowed, filteredCommand, err := ci.validateAndFilterCommand(ctx, command)
					if err != nil {
						return nil, fmt.Errorf("command validation failed: %w", err)
					}
					
					if !allowed {
						// Command blocked - don't forward it
						ci.commandBuffer.Reset()
						continue
					}
					
					// Forward the (potentially modified) command
					processedOutput.WriteString(filteredCommand)
				}
				ci.commandBuffer.Reset()
			}
			processedOutput.WriteByte(b)
			
		case 0x7F, 0x08: // DEL or backspace
			// Handle command editing
			if ci.commandBuffer.Len() > 0 {
				current := ci.commandBuffer.String()
				if len(current) > 0 {
					ci.commandBuffer.Reset()
					ci.commandBuffer.WriteString(current[:len(current)-1])
				}
			}
			processedOutput.WriteByte(b)
			
		case 0x03: // Ctrl+C
			// Command cancelled
			ci.commandBuffer.Reset()
			processedOutput.WriteByte(b)
			
		default:
			// Regular character - add to buffer
			ci.commandBuffer.WriteByte(b)
			processedOutput.WriteByte(b)
		}
	}
	
	return processedOutput.Bytes(), nil
}

// InterceptOutput processes output data from the shell (for audit purposes)
func (ci *CommandInterceptor) InterceptOutput(ctx context.Context, output []byte) ([]byte, error) {
	// For now, just pass through output
	// In future versions, we could filter sensitive output
	return output, nil
}

// validateAndFilterCommand validates a complete command against security rules
func (ci *CommandInterceptor) validateAndFilterCommand(ctx context.Context, command string) (bool, string, error) {
	// Record command start time
	ci.commandStart = time.Now()
	
	// Validate command against security rules
	result, err := ci.securityValidator.ValidateCommand(ctx, ci.securityContext, command)
	if err != nil {
		return false, "", fmt.Errorf("command validation error: %w", err)
	}
	
	// Handle blocked commands
	if !result.Allowed {
		if ci.onCommandBlocked != nil {
			if err := ci.onCommandBlocked(command, result.BlockReason); err != nil {
				return false, "", fmt.Errorf("command block callback failed: %w", err)
			}
		}
		
		// Send audit event
		if result.AuditEvent != nil && ci.auditChannel != nil {
			select {
			case ci.auditChannel <- result.AuditEvent:
			default:
				// Channel full, log warning but don't block
			}
		}
		
		return false, "", nil
	}
	
	// Handle audit-required commands
	if result.Action == FilterActionAudit {
		if ci.onCommandAudit != nil {
			if err := ci.onCommandAudit(result.AuditEvent); err != nil {
				return false, "", fmt.Errorf("command audit callback failed: %w", err)
			}
		}
		
		// Send audit event
		if result.AuditEvent != nil && ci.auditChannel != nil {
			select {
			case ci.auditChannel <- result.AuditEvent:
			default:
				// Channel full, log warning but don't block
			}
		}
	}
	
	return true, command, nil
}

// CommandFilter provides a high-level interface for command filtering
type CommandFilter struct {
	interceptor       *CommandInterceptor
	inputReader       io.Reader
	outputWriter      io.Writer
	shellInput        io.Writer
	shellOutput       io.Reader
	
	ctx               context.Context
	cancel            context.CancelFunc
	
	// Control channels
	done              chan struct{}
	errors            chan error
}

// NewCommandFilter creates a new command filter that sits between user and shell
func NewCommandFilter(
	validator *SecurityValidator,
	securityContext *SessionSecurityContext,
	userInput io.Reader,
	userOutput io.Writer,
	shellInput io.Writer,
	shellOutput io.Reader,
) *CommandFilter {
	ctx, cancel := context.WithCancel(context.Background())
	auditChan := make(chan *CommandAuditEvent, 100) // Buffered channel for audit events
	
	interceptor := NewCommandInterceptor(validator, securityContext, auditChan)
	
	return &CommandFilter{
		interceptor:  interceptor,
		inputReader:  userInput,
		outputWriter: userOutput,
		shellInput:   shellInput,
		shellOutput:  shellOutput,
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		errors:       make(chan error, 10),
	}
}

// Start begins filtering commands between user and shell
func (cf *CommandFilter) Start() error {
	// Set up security event callbacks
	cf.interceptor.SetCallbacks(
		cf.handleBlockedCommand,
		cf.handleAuditCommand,
	)
	
	// Start input filtering goroutine (user -> shell)
	go cf.filterInput()
	
	// Start output filtering goroutine (shell -> user)
	go cf.filterOutput()
	
	return nil
}

// Stop stops the command filter
func (cf *CommandFilter) Stop() error {
	cf.cancel()
	
	// Wait for goroutines to finish with timeout
	select {
	case <-cf.done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for command filter to stop")
	}
}

// GetErrors returns a channel for receiving filter errors
func (cf *CommandFilter) GetErrors() <-chan error {
	return cf.errors
}

// filterInput filters input from user to shell
func (cf *CommandFilter) filterInput() {
	defer close(cf.done)
	
	buffer := make([]byte, 4096)
	reader := bufio.NewReader(cf.inputReader)
	
	for {
		select {
		case <-cf.ctx.Done():
			return
		default:
			// Read from user input
			n, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					select {
					case cf.errors <- fmt.Errorf("input read error: %w", err):
					default:
					}
				}
				return
			}
			
			// Apply security filtering
			filtered, err := cf.interceptor.InterceptInput(cf.ctx, buffer[:n])
			if err != nil {
				select {
				case cf.errors <- fmt.Errorf("input filtering error: %w", err):
				default:
				}
				continue
			}
			
			// Write filtered input to shell
			if len(filtered) > 0 {
				if _, err := cf.shellInput.Write(filtered); err != nil {
					select {
					case cf.errors <- fmt.Errorf("shell input write error: %w", err):
					default:
					}
					return
				}
			}
		}
	}
}

// filterOutput filters output from shell to user
func (cf *CommandFilter) filterOutput() {
	buffer := make([]byte, 4096)
	reader := bufio.NewReader(cf.shellOutput)
	
	for {
		select {
		case <-cf.ctx.Done():
			return
		default:
			// Read from shell output
			n, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					select {
					case cf.errors <- fmt.Errorf("output read error: %w", err):
					default:
					}
				}
				return
			}
			
			// Apply output filtering (currently pass-through)
			filtered, err := cf.interceptor.InterceptOutput(cf.ctx, buffer[:n])
			if err != nil {
				select {
				case cf.errors <- fmt.Errorf("output filtering error: %w", err):
				default:
				}
				continue
			}
			
			// Write filtered output to user
			if _, err := cf.outputWriter.Write(filtered); err != nil {
				select {
				case cf.errors <- fmt.Errorf("user output write error: %w", err):
				default:
				}
				return
			}
		}
	}
}

// handleBlockedCommand handles when a command is blocked by security rules
func (cf *CommandFilter) handleBlockedCommand(command string, reason string) error {
	// Send security warning to user
	warningMsg := fmt.Sprintf("\r\n⚠️  SECURITY: Command blocked - %s\r\n", reason)
	if _, err := cf.outputWriter.Write([]byte(warningMsg)); err != nil {
		return fmt.Errorf("failed to write security warning: %w", err)
	}
	
	// Send new prompt
	promptMsg := "$ "
	if _, err := cf.outputWriter.Write([]byte(promptMsg)); err != nil {
		return fmt.Errorf("failed to write prompt: %w", err)
	}
	
	return nil
}

// handleAuditCommand handles when a command requires auditing
func (cf *CommandFilter) handleAuditCommand(event *CommandAuditEvent) error {
	// For now, just log audit events
	// In production, this would send to audit logging system
	return nil
}

// StreamInterceptor provides real-time command interception for streaming data
type StreamInterceptor struct {
	validator       *SecurityValidator
	securityContext *SessionSecurityContext
	
	// Stream processing
	inputProcessor  *CommandProcessor
	outputProcessor *OutputProcessor
	
	// Security events
	auditChannel chan<- *CommandAuditEvent
	alertChannel chan<- *SecurityAlert
}

// CommandProcessor processes command streams and extracts complete commands
type CommandProcessor struct {
}

// OutputProcessor processes output streams for sensitive data detection
type OutputProcessor struct {
}

// SensitiveDataRule defines patterns for detecting sensitive data in output
type SensitiveDataRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"` // mask, block, audit
	Replacement string `json:"replacement,omitempty"`
}

// SecurityAlert represents a real-time security alert
type SecurityAlert struct {
	Type        string                 `json:"type"`
	Severity    FilterSeverity         `json:"severity"`
	SessionID   string                 `json:"session_id"`
	UserID      string                 `json:"user_id"`
	StewardID   string                 `json:"steward_id"`
	TenantID    string                 `json:"tenant_id"`
	Message     string                 `json:"message"`
	Context     map[string]interface{} `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
	ActionTaken string                 `json:"action_taken"`
}

// NewStreamInterceptor creates a new stream interceptor for real-time processing
func NewStreamInterceptor(
	validator *SecurityValidator,
	context *SessionSecurityContext,
	auditChan chan<- *CommandAuditEvent,
	alertChan chan<- *SecurityAlert,
) *StreamInterceptor {
	return &StreamInterceptor{
		validator:       validator,
		securityContext: context,
		auditChannel:    auditChan,
		alertChannel:    alertChan,
		inputProcessor:  &CommandProcessor{},
		outputProcessor: &OutputProcessor{},
	}
}

// ProcessInput processes input stream and returns filtered data
func (si *StreamInterceptor) ProcessInput(ctx context.Context, data []byte) ([]byte, error) {
	// Implementation would process streaming input data
	// This is a placeholder for the streaming command processing logic
	return data, nil
}

// ProcessOutput processes output stream and returns filtered data
func (si *StreamInterceptor) ProcessOutput(ctx context.Context, data []byte) ([]byte, error) {
	// Implementation would process streaming output data
	// This is a placeholder for the streaming output processing logic
	return data, nil
}