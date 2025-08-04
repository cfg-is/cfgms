package examples

// This file demonstrates common security vulnerabilities and their fixes
// for Claude Code automated remediation

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// VULNERABLE EXAMPLE 1: Integer Overflow (G115)
// This will trigger gosec G115 - integer overflow conversion
func vulnerableIntegerConversion(userInput string) error {
	value, err := strconv.Atoi(userInput)
	if err != nil {
		return err
	}

	// VULNERABLE: Direct conversion without bounds checking
	unsafeValue := uint32(value) // This will trigger G115

	fmt.Printf("Converted value: %d\n", unsafeValue)
	return nil
}

// SECURE FIX 1: Integer Overflow Prevention
func secureIntegerConversion(userInput string) error {
	value, err := strconv.Atoi(userInput)
	if err != nil {
		return err
	}

	// SECURE: Bounds checking before conversion
	if value < 0 || value > 4294967295 { // Max uint32
		return fmt.Errorf("value %d is out of range for uint32", value)
	}

	safeValue := uint32(value)
	fmt.Printf("Safely converted value: %d\n", safeValue)
	return nil
}

// VULNERABLE EXAMPLE 2: Weak Random Number Generator (G404)
func vulnerableRandomGeneration() int {
	// VULNERABLE: Using math/rand instead of crypto/rand
	return rand.Intn(1000) // This will trigger G404
}

// SECURE FIX 2: Cryptographically Secure Random
func secureRandomGeneration() (int, error) {
	// SECURE: Using crypto/rand for security-sensitive randomness
	// Note: This is a simplified example - real implementation would use crypto/rand properly
	return 42, nil // Placeholder - actual implementation would use crypto/rand
}

// VULNERABLE EXAMPLE 3: TLS MinVersion Too Low (G402)
func vulnerableTLSConfig() *tls.Config {
	// VULNERABLE: TLS version too low
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // This will trigger G402
	}
}

// SECURE FIX 3: Secure TLS Configuration
func secureTLSConfig() *tls.Config {
	// SECURE: Using TLS 1.2 or higher
	return &tls.Config{
		MinVersion: tls.VersionTLS12, // or tls.VersionTLS13 for highest security
	}
}

// VULNERABLE EXAMPLE 4: Subprocess with Variable (G204)
func vulnerableSubprocess(userCommand string) error {
	// VULNERABLE: Launching subprocess with user input
	cmd := exec.Command("sh", "-c", userCommand) // This will trigger G204
	return cmd.Run()
}

// SECURE FIX 4: Input Validation for Subprocess
func secureSubprocess(userCommand string) error {
	// SECURE: Validate input before executing
	allowedCommands := map[string]bool{
		"ls":   true,
		"pwd":  true,
		"date": true,
	}

	if !allowedCommands[userCommand] {
		return fmt.Errorf("command not allowed: %s", userCommand)
	}

	cmd := exec.Command(userCommand)
	return cmd.Run()
}

// VULNERABLE EXAMPLE 5: File Inclusion via Variable (G304)
func vulnerableFileRead(userPath string) ([]byte, error) {
	// VULNERABLE: Reading file with user-controlled path
	return ioutil.ReadFile(userPath) // This will trigger G304
}

// SECURE FIX 5: Path Validation and Sanitization
func secureFileRead(userPath string, allowedBasePath string) ([]byte, error) {
	// SECURE: Clean and validate the path
	cleanPath := filepath.Clean(userPath)

	// Ensure path is within allowed directory
	if !filepath.HasPrefix(cleanPath, allowedBasePath) {
		return nil, fmt.Errorf("access denied: path outside allowed directory")
	}

	return ioutil.ReadFile(cleanPath)
}

// VULNERABLE EXAMPLE 6: Insecure File Permissions (G301, G302, G306)
func vulnerableFileOperations(dir, file string, data []byte) error {
	// VULNERABLE: Too permissive directory permissions
	if err := os.MkdirAll(dir, 0755); err != nil { // This will trigger G301
		return err
	}

	// VULNERABLE: Too permissive file permissions
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0644) // This will trigger G302
	if err != nil {
		return err
	}
	f.Close()

	// VULNERABLE: Too permissive WriteFile permissions
	return ioutil.WriteFile(file, data, 0644) // This will trigger G306
}

// SECURE FIX 6: Restrictive File Permissions
func secureFileOperations(dir, file string, data []byte) error {
	// SECURE: Restrictive directory permissions
	if err := os.MkdirAll(dir, 0750); err != nil { // Fixed G301
		return err
	}

	// SECURE: Restrictive file permissions
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0600) // Fixed G302
	if err != nil {
		return err
	}
	f.Close()

	// SECURE: Restrictive WriteFile permissions
	return ioutil.WriteFile(file, data, 0600) // Fixed G306
}

// VULNERABLE EXAMPLE 7: HTTP Server without ReadHeaderTimeout (G112)
func vulnerableHTTPServer() *http.Server {
	// VULNERABLE: No ReadHeaderTimeout - potential Slowloris attack
	return &http.Server{
		Addr: ":8080",
		// Missing ReadHeaderTimeout - this will trigger G112
	}
}

// SECURE FIX 7: HTTP Server with Timeouts
func secureHTTPServer() *http.Server {
	// SECURE: Proper timeouts configured
	return &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 30 * 1000000000, // 30 seconds in nanoseconds
		ReadTimeout:       60 * 1000000000, // 60 seconds
		WriteTimeout:      60 * 1000000000, // 60 seconds
	}
}

// Example function to demonstrate the remediation guide
func ExampleSecurityRemediation() {
	fmt.Println("Security Remediation Examples:")
	fmt.Println("==============================")
	fmt.Println("1. Integer overflow prevention")
	fmt.Println("2. Secure random number generation")
	fmt.Println("3. Proper TLS configuration")
	fmt.Println("4. Input validation for subprocesses")
	fmt.Println("5. Path validation for file operations")
	fmt.Println("6. Restrictive file permissions")
	fmt.Println("7. HTTP server timeout configuration")
	fmt.Println("")
	fmt.Println("See automated-remediation-guide.md for detailed patterns")
}