# Automated Security Remediation Guide

## Overview

This document provides structured guidance for automated security remediation using Claude Code integration. It defines the format, patterns, and examples that enable Claude Code to automatically fix common security issues detected by our security scanning tools.

**Tools Integrated:**

- **Trivy**: Filesystem vulnerability scanning
- **Nancy**: Go dependency vulnerability scanning  
- **gosec**: Go security pattern analysis
- **Staticcheck**: Advanced static analysis

## Structured Output Format

### JSON Schema for Remediation Reports

```json
{
  "timestamp": "2025-08-04T10:30:00Z",
  "project": "cfgms",
  "scanning_tools": ["trivy", "nancy", "gosec", "staticcheck"],
  "summary": {
    "total_issues": 129,
    "critical": 1,
    "high": 12,
    "medium": 89,
    "low": 27,
    "auto_fixable": 85
  },
  "remediation_suggestions": [
    {
      "tool": "trivy",
      "category": "dependency_vulnerabilities",
      "severity": "CRITICAL",
      "issues_count": 1,
      "auto_fixable": true,
      "remediation_type": "dependency_update",
      "claude_prompt": "Fix critical vulnerability in go-git dependency",
      "detailed_instructions": {
        "action": "dependency_update",
        "package": "github.com/go-git/go-git/v5",
        "current_version": "v5.12.0",
        "target_version": "v5.13.0",
        "command": "go get github.com/go-git/go-git/v5@v5.13.0",
        "cve_ids": ["CVE-2025-21613", "CVE-2025-21614"],
        "impact": "Remote code execution, DoS vulnerability"
      },
      "affected_files": ["go.mod", "go.sum"],
      "validation_command": "make security-trivy"
    }
  ]
}
```

## Common Remediation Patterns

### 1. Dependency Vulnerabilities (Trivy/Nancy)

#### Pattern: Critical/High CVE in Go Module

**Detection Pattern:**

```
CVE-YYYY-NNNNN (CRITICAL/HIGH) - Update `package-name` from vX.Y.Z → vA.B.C
```

**Automated Fix:**

```bash
# Command to execute
go get package-name@vA.B.C
go mod tidy

# Validation
make security-trivy
make security-deps
make test
```

#### Example Vulnerabilities Currently Detected

1. **go-git CVE-2025-21613 (CRITICAL)**
   - **Issue**: Argument injection via URL field
   - **Fix**: `go get github.com/go-git/go-git/v5@v5.13.0`
   - **Impact**: Remote code execution prevention

2. **go-git CVE-2025-21614 (HIGH)**
   - **Issue**: DoS via malicious Git server replies
   - **Fix**: Same dependency update as above
   - **Impact**: Service availability protection

### 2. Go Security Patterns (gosec)

#### Pattern: Integer Overflow (G115)

**Detection Pattern:**

```
G115 (HIGH): integer overflow conversion int -> uint32 at file.go:line
```

**Automated Fix:**

```go
// Before (vulnerable)
value := uint32(someInt)

// After (safe)
if someInt < 0 || someInt > math.MaxUint32 {
    return fmt.Errorf("value %d is out of range for uint32", someInt)
}
value := uint32(someInt)
```

#### Pattern: Weak Random Number Generator (G404)

**Detection Pattern:**

```
G404 (HIGH): Use of weak random number generator (math/rand instead of crypto/rand)
```

**Automated Fix:**

```go
// Before (vulnerable)
import "math/rand"
value := rand.Intn(100)

// After (secure)
import "crypto/rand"
import "math/big"

n, err := rand.Int(rand.Reader, big.NewInt(100))
if err != nil {
    return err
}
value := int(n.Int64())
```

#### Pattern: TLS MinVersion Too Low (G402)

**Detection Pattern:**

```
G402 (HIGH): TLS MinVersion too low at file.go:line
```

**Automated Fix:**

```go
// Before (vulnerable)
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS10,
}

// After (secure)
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12, // or tls.VersionTLS13 for highest security
}
```

#### Pattern: Subprocess with Variable (G204)

**Detection Pattern:**

```
G204 (MEDIUM): Subprocess launched with variable at file.go:line
```

**Automated Fix:**

```go
// Before (potentially vulnerable)
cmd := exec.Command("sh", "-c", userInput)

// After (safer with validation)
// Validate and sanitize userInput first
if !isValidCommand(userInput) {
    return fmt.Errorf("invalid command: %s", userInput)
}
cmd := exec.Command("sh", "-c", userInput)
```

#### Pattern: File Inclusion via Variable (G304)

**Detection Pattern:**

```
G304 (MEDIUM): Potential file inclusion via variable at file.go:line
```

**Automated Fix:**

```go
// Before (potentially vulnerable)
data, err := ioutil.ReadFile(userPath)

// After (safer with validation)
cleanPath := filepath.Clean(userPath)
if !strings.HasPrefix(cleanPath, allowedBasePath) {
    return fmt.Errorf("access denied: path outside allowed directory")
}
data, err := ioutil.ReadFile(cleanPath)
```

#### Pattern: Insecure File Permissions (G301, G302, G306)

**Detection Patterns:**

```
G301 (MEDIUM): Expect directory permissions to be 0750 or less
G302 (MEDIUM): Expect file permissions to be 0600 or less  
G306 (MEDIUM): Expect WriteFile permissions to be 0600 or less
```

**Automated Fix:**

```go
// Before (too permissive)
os.MkdirAll(dir, 0755)           // G301
os.OpenFile(file, flags, 0644)   // G302
ioutil.WriteFile(file, data, 0644) // G306

// After (secure)
os.MkdirAll(dir, 0750)           // G301 fix
os.OpenFile(file, flags, 0600)   // G302 fix  
ioutil.WriteFile(file, data, 0600) // G306 fix
```

### 3. Static Analysis Issues (Staticcheck)

Staticcheck issues typically require more context-specific fixes, but common patterns include:

- **Unused variables**: Remove or use the variable
- **Inefficient string concatenation**: Use strings.Builder
- **Context cancellation**: Properly handle context.Done()
- **Error handling**: Check all error returns

## Claude Code Integration Instructions

### For Dependency Vulnerabilities

When Claude Code encounters dependency vulnerability issues:

1. **Parse the JSON report** to extract package name, current version, and target version
2. **Execute the update command**: `go get package@version`
3. **Run go mod tidy** to clean up dependencies
4. **Validate the fix** by running `make security-trivy` and `make security-deps`
5. **Run tests** to ensure no breaking changes: `make test`

### For Go Security Patterns

When Claude Code encounters gosec issues:

1. **Identify the pattern** using the G-code and description
2. **Locate the specific file and line** mentioned in the report
3. **Apply the appropriate fix pattern** from this guide
4. **Add security comments** explaining the fix if appropriate
5. **Validate the fix** by running `make security-gosec`

### For Static Analysis Issues

When Claude Code encounters staticcheck issues:

1. **Read the specific error message** and location
2. **Apply context-appropriate fixes** based on the issue type
3. **Ensure the fix doesn't break functionality**
4. **Validate with** `make security-staticcheck`

## Priority Guidelines

### Auto-Fix Priority Order

1. **CRITICAL vulnerabilities** (CVEs) - Fix immediately
2. **HIGH security patterns** (G404, G402) - Fix immediately  
3. **HIGH vulnerabilities** (CVEs) - Fix in same session
4. **MEDIUM security patterns** (G204, G304) - Fix as time permits
5. **File permission issues** (G301, G302, G306) - Fix as cleanup
6. **Code quality issues** (staticcheck) - Fix as cleanup
7. **LOW issues** - Document for future cleanup

### Risk Assessment

- **Deployment Blocking**: CRITICAL and HIGH CVEs
- **Security Review Required**: All G204 (subprocess) and G304 (file inclusion) issues
- **Best Practice**: All file permission and TLS configuration issues
- **Code Quality**: Staticcheck and unused code issues

## Validation Workflow

After applying any automated fix:

1. **Run targeted security scan**: `make security-[tool]` for the specific tool
2. **Run comprehensive security scan**: `make security-scan`
3. **Run tests**: `make test`
4. **Run full validation**: `make test-with-security`

## Files That Should Not Be Auto-Modified

**Generated Files** (DO NOT MODIFY):

- `*.pb.go` (Protocol buffer generated files)
- `go.sum` (Only via `go mod tidy`)

**Test Files** (SPECIAL HANDLING):

- Files in `/test/` directories may have intentionally permissive settings
- Review test-specific security exceptions before applying fixes

**Configuration Files** (REVIEW REQUIRED):

- TLS configurations in production paths
- File permission settings that may be environment-specific

## Error Handling

If automated remediation fails:

1. **Report the failure** with specific error details
2. **Suggest manual review** for complex security issues
3. **Provide the manual fix steps** from this guide
4. **Document any patterns** that couldn't be automatically resolved

---

**Version**: 1.0  
**Last Updated**: 2025-08-04  
**Compatibility**: CFGMS v0.3.1+ Security Tools Implementation
