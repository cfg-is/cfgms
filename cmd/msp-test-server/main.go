// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules/m365/auth"

	// Import flatfile and sqlite plugins for storage
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func main() {
	// Load MSP credentials from environment
	clientID := os.Getenv("M365_MSP_CLIENT_ID")
	clientSecret := os.Getenv("M365_MSP_CLIENT_SECRET")
	tenantID := os.Getenv("M365_MSP_TENANT_ID")

	// Fallback to regular M365 vars if MSP vars not set
	if clientID == "" {
		clientID = os.Getenv("M365_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("M365_CLIENT_SECRET")
	}
	if tenantID == "" {
		tenantID = os.Getenv("M365_TENANT_ID")
	}

	if clientID == "" || clientSecret == "" || tenantID == "" {
		log.Fatal("Missing M365 MSP credentials. Add M365_MSP_* variables to .env.local or run: source .env.local")
	}

	// Create MSP configuration
	mspConfig := &auth.MultiTenantConfig{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		TenantID:         tenantID,
		AdminCallbackURI: "http://localhost:8080/admin/callback",
		ApplicationPermissions: []string{
			"User.ReadWrite.All",
			"Directory.ReadWrite.All",
			"Group.ReadWrite.All",
			"Policy.ReadWrite.ConditionalAccess",
			"DeviceManagementConfiguration.ReadWrite.All",
			"Organization.Read.All",
		},
	}

	// Create storage using OSS storage provider
	config := &auth.ClientStoreConfig{Type: auth.ClientStoreFile}
	clientStore, err := auth.NewClientTenantStore(config, nil)
	if err != nil {
		log.Fatal("Failed to create client store:", err)
	}

	// Create admin consent flow
	flow := auth.NewAdminConsentFlow(mspConfig, clientStore)
	ctx := context.Background()

	// HTTP handlers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `<!DOCTYPE html>
<html>
<head>
    <title>CFGMS MSP Test Server</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .btn { background: #0078d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 5px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>CFGMS MSP Test Server</h1>
    <p>Test your M365 multi-tenant app configuration</p>
    
    <h2>Quick Test</h2>
    <p><a href="/test-consent" class="btn">Start Admin Consent Flow</a></p>
    <p><a href="/list-clients" class="btn">View Onboarded Clients</a></p>
    
    <h2>Custom Test</h2>
    <form action="/test-consent" method="GET">
        <p>
            <label>Client Identifier:</label><br>
            <input type="text" name="client_id" value="test-client-001" style="width: 300px;">
        </p>
        <p>
            <label>Client Name:</label><br>
            <input type="text" name="client_name" value="Test Client Corp" style="width: 300px;">
        </p>
        <p>
            <label>MSP Employee:</label><br>
            <input type="text" name="msp_employee" value="admin@example.com" style="width: 300px;">
        </p>
        <p><button type="submit" class="btn">Generate Consent URL</button></p>
    </form>
    
    <h2>Status</h2>
    <ul>
        <li>Server running on localhost:8080</li>
        <li>M365 credentials loaded</li>
        <li>Git storage initialized</li>
        <li>Ready for admin consent testing</li>
    </ul>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprint(w, html); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/test-consent", func(w http.ResponseWriter, r *http.Request) {
		// Get parameters
		clientIdentifier := r.URL.Query().Get("client_id")
		if clientIdentifier == "" {
			clientIdentifier = "test-client-001"
		}

		clientName := r.URL.Query().Get("client_name")
		if clientName == "" {
			clientName = "Test Client Corp"
		}

		mspEmployee := r.URL.Query().Get("msp_employee")
		if mspEmployee == "" {
			mspEmployee = "admin@example.com"
		}

		// Start consent flow
		request, adminURL, err := flow.StartAdminConsentFlow(
			ctx,
			clientIdentifier,
			clientName,
			mspEmployee,
		)

		if err != nil {
			http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
			return
		}

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Admin Consent URL Generated</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .btn { background: #0078d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
        .success { color: green; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; word-break: break-all; }
        .consent-url { font-size: 18px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🎯 Admin Consent URL Generated</h1>
    
    <div class="success">
        <h2>✅ Success!</h2>
        <p>Admin consent flow initiated for <strong>%s</strong></p>
    </div>
    
    <h2>📋 Details</h2>
    <ul>
        <li><strong>Client Identifier:</strong> %s</li>
        <li><strong>Client Name:</strong> %s</li>
        <li><strong>MSP Employee:</strong> %s</li>
        <li><strong>State:</strong> %s</li>
        <li><strong>Expires:</strong> %s</li>
    </ul>
    
    <h2>🔗 Admin Consent URL</h2>
    <p>Click this URL to test the admin consent flow:</p>
    <div class="consent-url">
        <a href="%s" target="_blank" class="btn">🚀 Open Admin Consent</a>
    </div>
    
    <h3>Raw URL (for copying):</h3>
    <pre>%s</pre>
    
    <h2>📝 Testing Instructions</h2>
    <ol>
        <li><strong>Click the consent URL above</strong> - opens Microsoft login</li>
        <li><strong>Sign in as tenant admin</strong> - use account with admin rights</li>
        <li><strong>Review permissions</strong> - Microsoft shows what the app requests</li>
        <li><strong>Click "Accept"</strong> - grants consent for your tenant</li>
        <li><strong>Get redirected back</strong> - returns to localhost:8080/admin/callback</li>
        <li><strong>See results</strong> - callback page shows success/failure</li>
    </ol>
    
    <p><a href="/">&larr; Back to main page</a></p>
</body>
</html>`,
			clientName, clientIdentifier, clientName, mspEmployee,
			request.State[:16]+"...", request.ExpiresAt.Format("2006-01-02 15:04:05"),
			adminURL, adminURL)

		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprint(w, html); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/admin/callback", func(w http.ResponseWriter, r *http.Request) {
		// Handle the callback from Microsoft
		callbackURL := fmt.Sprintf("http://localhost:8080%s", r.URL.RequestURI())

		log.Printf("Received callback: %s", callbackURL)

		result, err := flow.HandleAdminConsentCallback(ctx, callbackURL)

		var html string
		if err != nil {
			log.Printf("Callback error: %v", err)
			html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Callback Error</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .error { color: red; background: #ffe6e6; padding: 15px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>❌ Callback Error</h1>
    <div class="error">
        <h3>Error Details:</h3>
        <p>%s</p>
    </div>
    
    <h2>Possible Causes:</h2>
    <ul>
        <li>Admin consent was denied</li>
        <li>State parameter mismatch</li>
        <li>Consent request expired</li>
        <li>Network/timing issue</li>
    </ul>
    
    <p><a href="/">&larr; Back to main page</a></p>
</body>
</html>`, err.Error())
		} else if result.Success && result.ClientTenant != nil {
			client := result.ClientTenant
			html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Consent Successful!</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .success { color: green; background: #e6ffe6; padding: 15px; border-radius: 4px; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>🎉 Admin Consent Successful!</h1>
    
    <div class="success">
        <h3>✅ Client Onboarded Successfully</h3>
        <p>The client tenant has been added to your MSP and is ready for management.</p>
    </div>
    
    <h2>📊 Client Details</h2>
    <ul>
        <li><strong>Client Identifier:</strong> %s</li>
        <li><strong>Tenant ID:</strong> %s</li>
        <li><strong>Tenant Name:</strong> %s</li>
        <li><strong>Domain:</strong> %s</li>
        <li><strong>Admin Email:</strong> %s</li>
        <li><strong>Status:</strong> %s</li>
        <li><strong>Consented At:</strong> %s</li>
    </ul>
    
    <h2>🔄 Next Steps</h2>
    <p>You can now:</p>
    <ul>
        <li><a href="/test-api?tenant=%s">Test Microsoft Graph API access</a></li>
        <li><a href="/list-clients">View all onboarded clients</a></li>
        <li>Use this tenant ID in your CFGMS M365 modules</li>
    </ul>
    
    <p><a href="/">&larr; Back to main page</a></p>
</body>
</html>`,
				client.ClientIdentifier, client.TenantID, client.TenantName,
				client.DomainName, client.AdminEmail, client.Status,
				client.ConsentedAt.Format("2006-01-02 15:04:05"), client.TenantID)
		} else {
			html = `<!DOCTYPE html>
<html>
<head>
    <title>Callback Issue</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .warning { color: orange; background: #fff3cd; padding: 15px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>⚠️ Consent Flow Issue</h1>
    <div class="warning">
        <p>The callback was received but the consent result was not successful.</p>
        <p>This might be expected if consent was denied or there was an error.</p>
    </div>
    <p><a href="/">&larr; Back to main page</a></p>
</body>
</html>`
		}

		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprint(w, html); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/list-clients", func(w http.ResponseWriter, r *http.Request) {
		clients, err := clientStore.ListClientTenants(r.Context(), "")
		if err != nil {
			http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
			return
		}

		html := `<!DOCTYPE html>
<html>
<head>
    <title>Onboarded Clients</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .status-active { color: green; font-weight: bold; }
        .status-pending { color: orange; font-weight: bold; }
        .status-suspended { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>👥 Onboarded Clients</h1>`

		if len(clients) == 0 {
			html += `<p>No clients onboarded yet. <a href="/">Start admin consent flow</a></p>`
		} else {
			html += fmt.Sprintf(`<p>Found %d onboarded client(s):</p>
			<table>
				<tr>
					<th>Client ID</th>
					<th>Name</th>
					<th>Tenant ID</th>
					<th>Status</th>
					<th>Consented</th>
					<th>Actions</th>
				</tr>`, len(clients))

			for _, client := range clients {
				statusClass := fmt.Sprintf("status-%s", client.Status)
				html += fmt.Sprintf(`
				<tr>
					<td>%s</td>
					<td>%s</td>
					<td>%s</td>
					<td class="%s">%s</td>
					<td>%s</td>
					<td><a href="/test-api?tenant=%s">Test API</a></td>
				</tr>`,
					client.ClientIdentifier, client.TenantName, client.TenantID,
					statusClass, client.Status,
					client.ConsentedAt.Format("2006-01-02 15:04"),
					client.TenantID)
			}
			html += `</table>`
		}

		html += `<p><a href="/">&larr; Back to main page</a></p></body></html>`

		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprint(w, html); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	// API testing handler
	http.HandleFunc("/test-api", func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant")
		if tenantID == "" {
			http.Error(w, "tenant parameter required", http.StatusBadRequest)
			return
		}

		// Test Microsoft Graph API access
		results := testGraphAPIAccess(mspConfig, tenantID)

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Graph API Test Results</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 20px auto; padding: 20px; }
        .success { color: green; background: #e6ffe6; padding: 10px; border-radius: 4px; margin: 5px 0; }
        .error { color: red; background: #ffe6e6; padding: 10px; border-radius: 4px; margin: 5px 0; }
        .warning { color: orange; background: #fff3cd; padding: 10px; border-radius: 4px; margin: 5px 0; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; font-size: 12px; }
        .api-test { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 4px; }
        .btn { background: #0078d4; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Microsoft Graph API Test Results</h1>
    <h2>Tenant: %s</h2>
    
    %s
    
    <p><a href="/list-clients" class="btn">Back to Clients</a> | <a href="/" class="btn">Home</a></p>
</body>
</html>`, tenantID, results)

		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprint(w, html); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	// Start server
	log.Printf("CFGMS MSP Test Server starting...")
	log.Printf("Open browser: http://localhost:8080")
	log.Printf("Client ID: %s", clientID[:8]+"...")
	log.Printf("Tenant: %s", tenantID)
	log.Printf("Storage: Git-backed")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// testGraphAPIAccess tests Microsoft Graph API access for a client tenant
func testGraphAPIAccess(config *auth.MultiTenantConfig, clientTenantID string) string {
	// Get access token for client tenant
	token, err := getMSPToken(config, clientTenantID)
	if err != nil {
		return fmt.Sprintf(`<div class="error"><h3>Token Error</h3><p>%s</p></div>`, err.Error())
	}

	// Test various API endpoints
	tests := []struct {
		name     string
		endpoint string
		desc     string
	}{
		{"Organization", "https://graph.microsoft.com/v1.0/organization", "Basic tenant info"},
		{"Users", "https://graph.microsoft.com/v1.0/users?$top=5", "List users (sample)"},
		{"Groups", "https://graph.microsoft.com/v1.0/groups?$top=5", "List groups (sample)"},
		{"Applications", "https://graph.microsoft.com/v1.0/applications?$top=5", "List applications"},
	}

	var results strings.Builder
	fmt.Fprintf(&results, `<div class="success"><h3>Access Token Acquired</h3><p>Successfully obtained token for tenant %s</p></div>`, clientTenantID)

	for _, test := range tests {
		result := testAPIEndpoint(test.endpoint, token.Token, test.name, test.desc)
		results.WriteString(result)
	}

	return results.String()
}

// getMSPToken gets an access token for the specified client tenant
func getMSPToken(config *auth.MultiTenantConfig, clientTenantID string) (*auth.AccessToken, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", clientTenantID)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {config.ClientID},
		"client_secret": {config.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token request failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &auth.AccessToken{
		Token:     tokenResponse.AccessToken,
		TokenType: tokenResponse.TokenType,
		ExpiresIn: tokenResponse.ExpiresIn,
		ExpiresAt: time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
	}, nil
}

// testAPIEndpoint tests a specific Microsoft Graph API endpoint
func testAPIEndpoint(endpoint, token, name, description string) string {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Sprintf(`<div class="api-test error"><h4>%s - %s</h4><p>Request creation failed: %s</p></div>`, name, description, err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf(`<div class="api-test error"><h4>%s - %s</h4><p>Request failed: %s</p></div>`, name, description, err.Error())
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf(`<div class="api-test error"><h4>%s - %s</h4><p>Response read failed: %s</p></div>`, name, description, err.Error())
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Pretty print JSON
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err == nil {
			prettyJSON, _ := json.MarshalIndent(jsonData, "", "  ")
			return fmt.Sprintf(`<div class="api-test success"><h4>%s - %s</h4><p>Status: %d SUCCESS</p><pre>%s</pre></div>`,
				name, description, resp.StatusCode, string(prettyJSON))
		}
		return fmt.Sprintf(`<div class="api-test success"><h4>%s - %s</h4><p>Status: %d SUCCESS</p><pre>%s</pre></div>`,
			name, description, resp.StatusCode, string(body))
	} else {
		return fmt.Sprintf(`<div class="api-test error"><h4>%s - %s</h4><p>Status: %d FAILED</p><pre>%s</pre></div>`,
			name, description, resp.StatusCode, string(body))
	}
}
