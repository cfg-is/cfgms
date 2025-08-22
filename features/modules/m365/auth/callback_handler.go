package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CallbackHandler manages OAuth2 callback processing and flow state
type CallbackHandler struct {
	// In-memory flow state storage (replace with Redis/DB in production)
	flowStates map[string]*AuthFlowState
	mutex      sync.RWMutex
	
	// HTTP server for handling callbacks
	server     *http.Server
	serverPort string
}

// NewCallbackHandler creates a new callback handler
func NewCallbackHandler() *CallbackHandler {
	return &CallbackHandler{
		flowStates: make(map[string]*AuthFlowState),
		serverPort: "8080", // Default port
	}
}

// StartCallbackServer starts the HTTP server to handle OAuth2 callbacks
func (h *CallbackHandler) StartCallbackServer(ctx context.Context, port string) error {
	if port != "" {
		h.serverPort = port
	}
	
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", h.handleCallback)
	mux.HandleFunc("/auth/status", h.handleStatus)
	mux.HandleFunc("/health", h.handleHealth)
	
	h.server = &http.Server{
		Addr:         ":" + h.serverPort,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	
	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Callback server error: %v\n", err)
		}
	}()
	
	// Wait for server to start
	time.Sleep(100 * time.Millisecond)
	
	return nil
}

// StopCallbackServer gracefully stops the callback server
func (h *CallbackHandler) StopCallbackServer(ctx context.Context) error {
	if h.server == nil {
		return nil
	}
	
	return h.server.Shutdown(ctx)
}

// StoreFlowState stores the flow state temporarily
func (h *CallbackHandler) StoreFlowState(state string, flowState *AuthFlowState) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	h.flowStates[state] = flowState
	
	// Start cleanup timer
	go func() {
		time.Sleep(15 * time.Minute) // Cleanup after 15 minutes
		h.mutex.Lock()
		delete(h.flowStates, state)
		h.mutex.Unlock()
	}()
	
	return nil
}

// GetFlowState retrieves the flow state
func (h *CallbackHandler) GetFlowState(state string) (*AuthFlowState, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	
	flowState, exists := h.flowStates[state]
	if !exists {
		return nil, fmt.Errorf("flow state not found or expired")
	}
	
	return flowState, nil
}

// CleanupFlowState removes the flow state
func (h *CallbackHandler) CleanupFlowState(state string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	delete(h.flowStates, state)
}

// HTTP handlers

func (h *CallbackHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for web applications
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	// Extract parameters from URL
	query := r.URL.Query()
	state := query.Get("state")
	code := query.Get("code")
	errorCode := query.Get("error")
	errorDescription := query.Get("error_description")
	
	// Build response
	response := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"state":     state,
	}
	
	if errorCode != "" {
		response["success"] = false
		response["error"] = errorCode
		response["error_description"] = errorDescription
		response["message"] = "Authorization failed. Please close this window and try again."
	} else if code != "" {
		response["success"] = true
		response["code"] = code
		response["message"] = "Authorization successful! Processing your request..."
		
		// Store the callback information for retrieval
		h.storeCallbackResult(state, &CallbackResult{
			Success:          true,
			AuthorizationCode: code,
			State:           state,
			ReceivedAt:      time.Now(),
		})
	} else {
		response["success"] = false
		response["error"] = "invalid_request"
		response["message"] = "Missing authorization code. Please close this window and try again."
	}
	
	// Return JSON response for API clients
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// Return HTML page for browser clients
	html := h.generateCallbackHTML(response)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (h *CallbackHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}
	
	// Check if we have a result for this state
	result := h.getCallbackResult(state)
	
	w.Header().Set("Content-Type", "application/json")
	if result != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ready":   true,
			"success": result.Success,
			"state":   result.State,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ready": false,
			"state": state,
		})
	}
}

func (h *CallbackHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

// Callback result storage (temporary)

type CallbackResult struct {
	Success           bool      `json:"success"`
	AuthorizationCode string    `json:"authorization_code,omitempty"`
	State             string    `json:"state"`
	Error             string    `json:"error,omitempty"`
	ErrorDescription  string    `json:"error_description,omitempty"`
	ReceivedAt        time.Time `json:"received_at"`
}

var (
	callbackResults = make(map[string]*CallbackResult)
	callbackMutex   sync.RWMutex
)

func (h *CallbackHandler) storeCallbackResult(state string, result *CallbackResult) {
	callbackMutex.Lock()
	defer callbackMutex.Unlock()
	
	callbackResults[state] = result
	
	// Cleanup after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		callbackMutex.Lock()
		delete(callbackResults, state)
		callbackMutex.Unlock()
	}()
}

func (h *CallbackHandler) getCallbackResult(state string) *CallbackResult {
	callbackMutex.RLock()
	defer callbackMutex.RUnlock()
	
	return callbackResults[state]
}

// HTML generation for browser clients

func (h *CallbackHandler) generateCallbackHTML(response map[string]interface{}) string {
	success, _ := response["success"].(bool)
	message, _ := response["message"].(string)
	
	var statusClass, statusIcon string
	if success {
		statusClass = "success"
		statusIcon = "✅"
	} else {
		statusClass = "error"
		statusIcon = "❌"
	}
	
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CFGMS - Microsoft 365 Authorization</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 100%%;
        }
        .status-icon {
            font-size: 4rem;
            margin-bottom: 20px;
        }
        .success {
            color: #10b981;
        }
        .error {
            color: #ef4444;
        }
        h1 {
            margin: 0 0 20px 0;
            color: #1f2937;
        }
        p {
            color: #6b7280;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        .close-button {
            background: #4f46e5;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .close-button:hover {
            background: #4338ca;
        }
        .details {
            margin-top: 20px;
            padding: 15px;
            background: #f9fafb;
            border-radius: 8px;
            font-size: 14px;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="status-icon %s">%s</div>
        <h1>Microsoft 365 Authorization</h1>
        <p>%s</p>
        
        <button class="close-button" onclick="window.close()">
            Close Window
        </button>
        
        <div class="details">
            <strong>Next Steps:</strong><br>
            Return to the CFGMS application to continue setup.
        </div>
    </div>
    
    <script>
        // Auto-close after successful authorization
        if (%t) {
            setTimeout(() => {
                if (window.opener) {
                    window.opener.postMessage({
                        type: 'cfgms-auth-complete',
                        success: %t,
                        state: '%s'
                    }, '*');
                }
                window.close();
            }, 3000);
        }
        
        // Handle manual close
        window.addEventListener('beforeunload', () => {
            if (window.opener) {
                window.opener.postMessage({
                    type: 'cfgms-auth-window-closed',
                    success: %t,
                    state: '%s'
                }, '*');
            }
        });
    </script>
</body>
</html>
`, statusClass, statusIcon, message, success, success, response["state"], success, response["state"])
}

// GetCallbackURL returns the callback URL for the OAuth2 flow
func (h *CallbackHandler) GetCallbackURL() string {
	return fmt.Sprintf("http://localhost:%s/auth/callback", h.serverPort)
}

// WaitForCallback waits for the OAuth2 callback with a timeout
func (h *CallbackHandler) WaitForCallback(ctx context.Context, state string, timeout time.Duration) (*CallbackResult, error) {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if result := h.getCallbackResult(state); result != nil {
			return result, nil
		}
		
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
			// Continue polling
		}
	}
	
	return nil, fmt.Errorf("timeout waiting for callback")
}