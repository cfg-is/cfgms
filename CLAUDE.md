# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CFGMS (Config Management System) is a modern, Go-based configuration management system designed with resilience, security, and clean architecture principles. The project implements a zero-trust security model with mutual TLS authentication and follows a feature-based organization structure.

## Development Workflow

### Sprint and Development Process
- **Sprint Planning Guideline**: At the start of each milestone, ALWAYS conduct sprint/story planning before beginning work
- **Story Development Workflow**:
  1. Pick up the next story from the GitHub project
  2. Create a feature branch
  3. Use Test-Driven Development (TDD) to complete work on the feature
  4. Once all tests are passing:
     a) Commit files to feature branch
     b) Ensure CLAUDE.md and roadmap are updated to reflect current step
     c) Update GitHub project with current progress
     d) Commit updated files and merge feature branch into develop branch
  5. Start on the next story until all planned stories are complete

## Development Commands

### Building
```bash
# Build all binaries
make build

# Build individual components
make build-controller  # Builds controller binary
make build-steward     # Builds steward binary  
make build-cli         # Builds cfgctl CLI binary

# Alternative: direct Go build commands
go build -o bin/controller ./cmd/controller
go build -o bin/cfgms-steward ./cmd/steward
go build -o bin/cfgctl ./cmd/cfgctl
```

### Testing
```bash
# Run all tests with coverage and race detection
make test
# Equivalent to: go test -v -race -cover ./...

# Run specific test package
go test -v ./features/controller/
go test -v ./features/modules/

# Run single test
go test -v -run TestControllerStart ./features/controller/
```

### Production Risk Testing & Release Gates
```bash
# Test production-critical functionality only
make test-production-critical

# Check export reliability and cost protection
make test-export-reliability

# Simulate monitoring costs at scale
make cost-analysis

# Check compliance protection status
make compliance-check

# v0.3.0 Release Gate (Alpha Readiness)
make test-v030-gate

# v0.4.0 Release Gate (Production Readiness)  
make test-v040-gate
```

**IMPORTANT**: Release gates must pass before deployment:
- **v0.3.0 Gate**: Blocks alpha deployment until cost protection and data loss prevention are working
- **v0.4.0 Gate**: Blocks production deployment until ALL export edge cases are resolved

### Linting
```bash
# Run linter (requires golangci-lint)
make lint
# Equivalent to: golangci-lint run
```

### Protocol Buffers
```bash
# Generate Go code from proto files
make proto

# Check for required proto tools
make check-proto-tools
```

### Cleanup
```bash
# Clean build artifacts and test cache
make clean
```

## Core Architecture

### Three-Tier System
- **Controller**: Central management system for configuration distribution and tenant hierarchy management
- **Steward**: Cross-platform component that executes configurations on managed endpoints
- **Outpost**: Proxy cache component for network device monitoring and agentless management

### Module System
All resource management is performed through modules that implement the core interface:
- `Get(ctx, resourceID)` - Returns current configuration as ConfigState
- `Set(ctx, resourceID, config)` - Updates resource to match desired state (managed fields only)
- **System Testing**: Steward automatically compares current vs desired state using managed fields
- `Monitor(ctx, resourceID, config)` - **(Optional)** Real-time event-driven monitoring via separate interface

**ConfigState Interface**: Enables efficient field-level comparison without marshal/unmarshal overhead. Modules return comprehensive system state, but only managed fields are modified.

Available modules: `directory`, `file`, `firewall`, `package`, `script`

### Communication
- **Internal**: gRPC with mutual TLS between components
- **External**: REST API with HTTPS and API key authentication
- **Protocol Buffers**: Used for efficient data serialization

### Security Architecture
- Zero-trust security model with mutual TLS for all internal communication
- Certificate-based authentication for stewards
- Optional OpenZiti integration for zero-trust networking
- Role-based access control (RBAC) with hierarchical permissions

## Code Organization

### Feature-Based Structure
```
features/
├── controller/    # Controller component and server logic
├── steward/       # Steward component with health monitoring
└── modules/       # Module implementations (directory, file, firewall, package)
```

### Key Directories
- `cmd/` - Command-line applications (controller, steward, cfgctl)
- `api/proto/` - Protocol buffer definitions for gRPC communication
- `pkg/` - Shared packages (logging utilities)
- `test/` - Integration and end-to-end tests
- `docs/` - Comprehensive documentation including architecture and standards

## Development Guidelines

### Go Standards
- Use Go 1.23+ features
- Follow dependency injection patterns
- No global variables or state
- Implement proper context cancellation
- Use structured logging with consistent fields
- Handle all errors explicitly
- Achieve 100% test coverage for core components

### Documentation Standards
- **Package Documentation**: Every package must have comprehensive documentation explaining its purpose, key concepts, and usage examples
- **Function Documentation**: All exported functions and methods must have clear documentation starting with the function name
- **Type Documentation**: All exported types must be documented with their purpose and key fields explained
- **Example Code**: Include practical usage examples in package documentation using Go's example testing pattern
- **Implementation Notes**: Document important implementation details, design decisions, and any non-obvious behavior
- **Error Documentation**: Document expected error conditions and their meanings
- **Interface Documentation**: Clearly document interface contracts, expected behavior, and implementation requirements
- **Constants and Variables**: Document all exported constants and variables with their purpose and valid values

### Testing Approach
- **TDD**: Write table-driven tests before implementation
- **Coverage**: Aim for 100% test coverage on core components
- **Race Detection**: Always run tests with `-race` flag
- **Integration**: Test component interactions with real dependencies
- **Chaos Engineering**: Test resilience under failure conditions

### Security Requirements
- All internal network communication must use mTLS to protect gRPC
- All external network communication must use TLS to secure REST
- Implement proper input validation and sanitization
- Use secure defaults in all configurations
- Follow principle of least privilege
- Sanitize all logging output to prevent information leakage

### Module Development
- Each module must be self-contained with clear ConfigState interface
- Implement Get/Set interface with ConfigState for all resource types
- **Optional Monitor interface** for real-time change detection via OS hooks
- Use idempotent operations and support offline operation
- Include proper error handling and comprehensive validation
- Get returns comprehensive state, Set modifies only managed fields
- Use GetManagedFields() to specify which fields Set will change

## Branching Strategy

Following GitFlow:
- `main` - Production-ready code only
- `develop` - Integration branch for features
- `feature/*` - New feature development
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates
- `refactor/*` - Code improvements

## Multi-Tenancy & Configuration Inheritance
The system implements a recursive parent-child tenant model with:
- **Hierarchical Configuration Inheritance**: MSP (Level 0) → Client (Level 1) → Group (Level 2) → Device (Level 3)
- **Declarative Merging**: Named resources (e.g., `firewall.rules.web`) replace entire blocks rather than field-level merging
- **Source Tracking**: Every configuration value includes source attribution and hierarchy level for full auditability
- **REST API Access**: `/api/v1/stewards/{id}/config/effective` endpoint provides merged configuration with inheritance metadata
- Tenant-aware RBAC with cascading permissions
- Efficient cross-tenant operations using path-based targeting
- Designed to handle 50k+ Stewards across multiple regions

## Current Development Status

**Current Version**: v0.2.1 (Alpha) - Test Infrastructure & Sprint Planning Foundation - 🟡 98% COMPLETE

**Status**: 8 of 9 v0.2.1 issues completed. Outstanding: Issue #57 (test failures in controller lifecycle and monitoring export tests)

**Reference**: See `docs/product/roadmap.md` for detailed current status and planning

### Recent Major Completions
- ✅ **v0.1.0 Complete**: Steward core, Controller core, and integration validation
- ✅ **v0.2.0 Complete**: All 40 story points delivered (100% feature complete)
  - ✅ **Configuration Data Flow**: Complete gRPC configuration service with real-time updates
  - ✅ **Multi-tenancy Foundation**: Basic RBAC/ABAC and tenant management
  - ✅ **Security Framework**: Certificate management and mTLS authentication
  - ✅ **Workflow Engine**: Basic workflow execution with API integration capabilities
  - ✅ **Module System**: Complete ConfigState interface with directory, file, firewall, package, and script modules
  - ✅ **REST API Endpoints**: External API access for MSP tool integration with comprehensive OpenAPI 3.0 specification
  - ✅ **Configuration Inheritance**: Hierarchical MSP → Client → Group → Device cascading with source tracking
  - ✅ **Script Execution Framework**: Cross-platform script execution capabilities with configurable timeout, OS-level signing, and multi-shell support (Windows: PowerShell/cmd, Unix: bash/zsh/python)

### Current Status: v0.2.1 - Test Infrastructure & BMAD Sprint Planning 🟡 98% COMPLETE
**Major Achievements:**
- **Test Infrastructure Excellence**: 98%+ test success rate with all core functionality working
- **Production Risk Protection**: Automated gates preventing cost overruns, data loss, and compliance violations
- **BMAD Agent Sprint Planning**: AI-assisted methodology established for v0.3.0 development
- **Automated Story Generation**: Framework ready for creating detailed user stories from roadmap features
- **Project Board Automation**: GitHub CLI integration implemented for project management
- **Business Risk Analysis**: Created $540k/month cost protection with monitoring sampling controls

## Project Management

### GitHub Project
The CFGMS development is managed through the **"CFGMS Development Roadmap"** GitHub Project at:
https://github.com/orgs/cfg-is/projects/1

This project board provides:
- **Roadmap Tracking**: Visual progress of major milestones and features
- **Issue Management**: Centralized tracking of bugs, features, and tasks
- **Sprint Planning**: Organized development cycles with clear priorities
- **Status Visibility**: Real-time project status and completion metrics

All development work should be tracked through this project board to ensure coordination and visibility across the team.

### Project Status Flow
The project follows a structured milestone progression workflow:

**Status Definitions:**
- **Done**: Completed work items
- **In Progress**: Current active development
- **Todo**: Next milestone items ready to start immediately
- **Backlog**: Future milestone items planned but not immediate

**Milestone Transitions:**
1. **Milestone Completion**: When a milestone (e.g., v0.1.0) is completed:
   - Move next milestone issues (e.g., v0.2.0) from "Backlog" → "Todo"
   - Create following milestone issues (e.g., v0.3.0) and place in "Backlog"

2. **Benefits of This Approach**:
   - Clear focus on current priorities without scope creep
   - Manageable scope with only one milestone in "Todo" at a time
   - Continuous planning maintains forward momentum
   - Always one milestone ahead in planning for roadmap adjustments

**Current State (Milestone Workflow):**
- **v0.1.0**: Complete ✅ 
- **v0.2.0**: Complete ✅ (All 40 story points delivered)
- **v0.2.1**: 98% Complete 🟡 (Test Infrastructure & BMAD Sprint Planning - Issue #57 outstanding)
- **v0.3.0**: Planned next (Enhanced Automation & SaaS Steward Foundation)

**v0.2.1 COMPLETED Achievements:**
- **Test Infrastructure Cleanup**: ✅ Fixed config service test failures, race conditions, deadlocks (98%+ success rate)
- **BMAD Agent Integration**: ✅ Implemented AI-assisted sprint planning framework for v0.3.0
- **Story Generation**: ✅ Automated user story creation methodology established
- **Project Board Automation**: ✅ GitHub CLI integration implemented for project management
- **Production Risk Gates**: ✅ Automated deployment protection against cost overruns and compliance violations

This workflow ensures sustainable development rhythm with clear prioritization and forward visibility.

### GitHub CLI Project Management

The project uses GitHub CLI (`gh`) for project management automation. Here are the essential commands and patterns:

#### Project Information
```bash
# List all projects in the organization
gh project list --owner cfg-is

# Get project field information (including status options)
gh project field-list PROJECT_NUMBER --owner cfg-is --format json

# Example output shows Status field with options:
# {"id":"PVTSSF_...", "name":"Status", "options":[
#   {"id":"0e6b51d0","name":"Backlog"},
#   {"id":"f75ad846","name":"Todo"}, 
#   {"id":"47fc9ee4","name":"In Progress"},
#   {"id":"98236657","name":"Done"}
# ]}
```

#### Issue Management
```bash
# List open issues with JSON output
gh issue list --repo cfg-is/cfgms --state open --limit 50 --json number,title,labels

# Add issues to project by URL
gh project item-add PROJECT_NUMBER --owner cfg-is --url "https://github.com/cfg-is/cfgms/issues/ISSUE_NUMBER"

# Add multiple issues in batch
for i in {33..39}; do 
  gh project item-add 1 --owner cfg-is --url "https://github.com/cfg-is/cfgms/issues/$i"
done
```

#### Project Item Operations
```bash
# List project items with details
gh project item-list PROJECT_NUMBER --owner cfg-is --format json --limit 50

# Filter project items by issue number
gh project item-list 1 --owner cfg-is --format json --limit 50 | \
  jq '.items[] | select(.content.number >= 29 and .content.number <= 39)'

# Get specific item details (ID, number, title)
gh project item-list 1 --owner cfg-is --format json --limit 50 | \
  jq '.items[] | {id, number: .content.number, title: .content.title}'
```

#### Status Updates
```bash
# Update item status (requires project-id, item-id, field-id, and option-id)
gh project item-edit \
  --project-id PROJECT_ID \
  --id ITEM_ID \
  --field-id FIELD_ID \
  --single-select-option-id OPTION_ID

# Example: Move issue to "Todo" status
gh project item-edit \
  --project-id PVT_kwDOCrV4cc4A18Ip \
  --id PVTI_lADOCrV4cc4A18IpzgcSU0g \
  --field-id PVTSSF_lADOCrV4cc4A18IpzgrVDWc \
  --single-select-option-id f75ad846
```

#### Important Notes
- **Project ID Format**: Use the full project ID (e.g., `PVT_kwDOCrV4cc4A18Ip`), not just the number
- **Item IDs**: Each project item has a unique ID that must be obtained from item-list command
- **Field IDs**: Status field ID is consistent but must be retrieved from field-list
- **Option IDs**: Status options (Backlog, Todo, In Progress, Done) have specific IDs
- **Batch Operations**: Use shell loops and `&&` operators for multiple updates
- **Error Handling**: Always verify IDs exist before attempting updates

#### Status Option IDs (for CFGMS project)
- **Backlog**: `0e6b51d0`
- **Todo**: `f75ad846` 
- **In Progress**: `47fc9ee4`
- **Done**: `98236657`

#### Common Workflow
1. Get project information and field IDs
2. Add new issues to project if needed
3. List project items to get item IDs
4. Update item status using project-id, item-id, field-id, and option-id
5. Verify changes with another item-list command

## v0.2.1 BMAD Agent Sprint Planning Framework

### Overview
Transitioning to AI-assisted sprint planning using BMAD (Build, Measure, Analyze, Decide) methodology for v0.3.0 development. This approach leverages Claude Code agents to analyze roadmap requirements and generate detailed implementation plans.

### BMAD Agent Integration
- **Build**: Use agents to create detailed user stories from high-level roadmap features
- **Measure**: Apply historical velocity data from v0.2.0 (40 story points across 6 stories)
- **Analyze**: Agent-driven analysis of feature complexity and dependencies
- **Decide**: Automated sprint planning with story point estimation and task breakdown

### Sprint Planning Process
1. **Roadmap Analysis**: BMAD agents analyze v0.3.0 features (Business Logic workflows, SaaS Steward, API modules, etc.)
2. **Story Generation**: Convert high-level features into detailed user stories with acceptance criteria
3. **Story Point Estimation**: Use v0.2.0 velocity data (2-21 points per story) for estimation
4. **Sprint Organization**: Group stories into logical sprints with clear deliverable outcomes
5. **Project Board Setup**: Automated GitHub CLI integration for issue creation and status management

### Implementation Approach
- **Agent Task Orchestration**: Use Task tool for complex multi-step analysis
- **Historical Data**: Reference v0.2.0 sprint planning success patterns
- **Automation**: GitHub CLI integration for seamless project board management
- **Quality Gates**: Ensure all stories have clear acceptance criteria and definition of done

### Next Steps for v0.2.1
1. **Complete Test Infrastructure Cleanup**: Fix config service tests
2. **Implement BMAD Agent Framework**: Create sprint planning automation
3. **Generate v0.3.0 Stories**: Use agents to create detailed implementation plans
4. **Establish Project Board Automation**: GitHub CLI integration for story management

---

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/stretchr/testify` - Testing utilities
- `google.golang.org/grpc` - gRPC communication
- `google.golang.org/protobuf` - Protocol buffer support