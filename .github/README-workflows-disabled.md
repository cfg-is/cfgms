# GitHub Actions Workflows Temporarily Disabled

## Status: DISABLED (Cost Control)

The GitHub Actions workflows in `workflows-disabled/` have been temporarily disabled to control GitHub Actions usage costs during development.

## Disabled Workflows:
- **production-gates.yml**: Production Risk Gates with cross-platform testing
- **security-scan.yml**: Security vulnerability scanning workflow  

## Local Testing Still Available:
```bash
# Full test suite
make test

# Security scanning  
make security-scan

# Combined validation
make test-with-security
```

## Re-enabling Plan:
- **Target**: v0.8.0 (Go Public milestone)
- **Reason**: GitHub Actions costs are lower/free for public OSS repositories
- **Task**: Move `workflows-disabled/` back to `workflows/` in v0.8.0

## Current Development Approach:
1. Use local testing (`make test`, `make security-scan`)
2. Manual validation for milestone releases
3. Comprehensive local development workflow continues normally
4. Re-enable CI/CD when repository becomes public OSS

---
*Disabled on: 2025-08-06*  
*Target re-enable: v0.8.0 (Go Public)*