# CFGMS Sprint Planning - v0.2.0 Completion

## Overview

This document outlines the agile sprint planning for completing CFGMS v0.2.0, transitioning from milestone-based development to 2-week sprint cycles.

**Sprint Capacity**: 12-15 story points per 2-week sprint (solo developer, part-time)  
**Sprint Goal**: Complete v0.2.0 features with focus on customer value delivery

## Product Backlog Status

Based on feature audit conducted July 2025:

- **✅ REST API (Issue #36)**: ~90% Complete (2 points remaining)
- **⚠️ Configuration Inheritance (Issue #37)**: ~30% Complete (10 points remaining)  
- **❌ Script Execution (Issue #39)**: 0% Complete (13+ points needed)

---

## Sprint 1 (2 weeks) - Foundation Sprint

**Sprint Goal**: "Complete REST API and implement configuration inheritance to enable MSP hierarchical management"

**Capacity**: 12 story points

### Story 1: Complete REST API Implementation
**As a** developer integrating with CFGMS  
**I want** fully functional and documented REST API endpoints  
**So that** I can integrate CFGMS with external MSP tools

**Acceptance Criteria:**
- [ ] Handler implementation completed (fix TODOs in `handleListStewards`)
- [ ] OpenAPI 3.0 specification created and validated
- [ ] API documentation auto-generated from OpenAPI spec
- [ ] Integration tests cover all major endpoints
- [ ] GitHub issue #36 closed with completion notes

**Story Points:** 2  
**Priority:** High (blocks external integrations)

---

### Story 2: Declarative Configuration Inheritance
**As an** MSP administrator  
**I want** hierarchical configuration inheritance with clear override visibility  
**So that** I can manage organization-wide policies with transparent customization

**Acceptance Criteria:**
- [ ] **Declarative Config Format**: Use structured naming to prevent duplicate conflicts
  - [ ] Evaluate curent Module naming and configuration block documentation to ensure naming supports required naming structure
  - [ ] Configuration blocks use hierarchical keys (e.g., `firewall.rules.web`, `users.admin.permissions`)
  - [ ] Merge replaces entire conflicting blocks rather than field-by-field
- [ ] **Inheritance Logic**: First valid config wins at each level (MSP → Client → Group → Device)
- [ ] **Configuration Traceability**: 
  - [ ] API returns source level for each config value (`{"value": "...", "source": "client", "level": 2}`)
  - [ ] UI shows inheritance chain with override indicators
- [ ] **Implementation**:
  - [ ] Extend existing tenant hierarchy for config storage
  - [ ] GetEffectiveConfiguration() merges configs with source tracking
  - [ ] REST API endpoint: `GET /api/v1/stewards/{id}/config/effective`

**Story Points:** 10  
**Priority:** High (core v0.2.0 feature)

---

### Story 3: Technical Debt & Testing (Optional)
**Stretch goals if Sprint 1 completes early:**
- [ ] Integration tests for completed features
- [ ] Update CLAUDE.md with current status  
- [ ] Code cleanup and documentation
- [ ] Performance profiling of configuration inheritance

**Story Points:** Flex capacity  
**Priority:** Medium

---

## Sprint 2 (2 weeks) - Script Execution Sprint

**Sprint Goal**: "Implement secure script execution with module pattern and audit capabilities"

**Capacity**: 15 story points

### Architectural Decision: Script Modules

**Chosen Approach**: Script Modules (consistent with existing module pattern)

**Rationale**:
- ✅ Maintains CFGMS architectural consistency
- ✅ Provides idempotent operations via Get/Set pattern
- ✅ Enables rollback capability through state comparison
- ✅ Better auditability and compliance tracking
- ✅ Integrates with existing module discovery and execution framework

**Script Module Structure**:
- **Get Script**: Check current state, return JSON status (required for all script modules)
- **Set Script**: Apply changes to reach desired state (optional - audit-only modules may omit)
- **Module Types**:
  - **Read/Write Modules**: Both Get and Set scripts for state management
  - **Audit-Only Modules**: Only Get script for compliance checking and reporting
- **Follow ConfigState interface**: Support managed fields comparison

---

### Story 4: Script Module Framework
**As a** system administrator  
**I want** scripts to follow the Get/Set module pattern  
**So that** script execution is consistent, auditable, and supports rollback

**Acceptance Criteria:**
- [ ] **Script Module Structure**:
  - [ ] Get script: Check current state, return JSON status (required)
  - [ ] Set script: Apply changes to reach desired state (optional for audit-only)
  - [ ] Support both read/write and audit-only script modules
  - [ ] Follow existing ConfigState interface pattern
  - [ ] Module discovery includes script modules
- [ ] **Multi-platform Support**:
  - [ ] Windows: PowerShell, CMD
  - [ ] Linux/macOS: Bash, Zsh, Python
  - [ ] Platform detection and appropriate executor selection
- [ ] **Security & Parameters**:
  - [ ] OS-level script signing validation
  - [ ] Environment variable injection for parameters
  - [ ] Command-line argument support
  - [ ] Configurable timeout (default 5 min, max 120 min)
- [ ] **Execution Features**:
  - [ ] Capture stdout/stderr and exit codes
  - [ ] Working directory configuration
  - [ ] Resource usage tracking

**Story Points:** 8  
**Priority:** High

---

### Story 5: Script Execution Audit & Management
**As a** compliance officer  
**I want** complete audit trails for all script executions  
**So that** I can track system changes and meet regulatory requirements

**Acceptance Criteria:**
- [ ] **Execution Logging**:
  - [ ] Full audit trail for every script execution
  - [ ] Log script source, parameters, execution time, results
  - [ ] Integration with existing CFGMS logging framework
- [ ] **Script Management**:
  - [ ] Script execution history per steward
  - [ ] Performance metrics and resource tracking
  - [ ] Failed execution analysis and retry capabilities
- [ ] **API Integration**:
  - [ ] REST API endpoints for script management
  - [ ] Query execution history and audit logs
  - [ ] Script status and result retrieval

**Story Points:** 5  
**Priority:** High

---

### Story 6: v0.2.0 Polish & Documentation
**As a** user adopting CFGMS v0.2.0  
**I want** comprehensive documentation and stable performance  
**So that** I can successfully deploy and operate the system

**Acceptance Criteria:**
- [ ] **Integration Testing**: End-to-end tests across all v0.2.0 features
- [ ] **Documentation Updates**: 
  - [ ] Update docs/product/roadmap.md with v0.2.0 completion
  - [ ] Script module documentation with examples
  - [ ] Configuration inheritance user guide
- [ ] **Performance Optimization**: 
  - [ ] Profile configuration inheritance performance
  - [ ] Optimize script execution resource usage
- [ ] **Release Preparation**: Update version tags and release notes

**Story Points:** 2  
**Priority:** Medium

---

## Technical Implementation Notes

### Configuration Inheritance Technical Approach

**Data Model**:
```go
type HierarchicalConfig struct {
    TenantID string
    Level    string // "msp", "client", "group", "device" 
    Config   map[string]interface{}
    Source   string // identifier for the config source
}

type EffectiveConfig struct {
    Values map[string]ConfigValue
}

type ConfigValue struct {
    Value  interface{}
    Source string // which level provided this value
    Level  int    // hierarchy level (0=msp, 1=client, 2=group, 3=device)
}
```

**Merge Strategy**:
1. Load configs from MSP → Client → Group → Device
2. Use declarative block naming to prevent conflicts
3. Replace entire blocks rather than field-level merging
4. Track source and level for each configuration value

### Script Module Technical Approach

**Module Structure**:
```
features/modules/script/
├── script.go           # Main module implementation
├── executor/
│   ├── windows.go      # PowerShell, CMD executors
│   ├── unix.go         # Bash, Zsh, Python executors
│   └── common.go       # Shared execution logic
├── security/
│   ├── signing.go      # OS-level signature validation
│   └── sandbox.go      # Execution constraints
└── audit/
    └── logger.go       # Script execution audit logging
```

**Integration Points**:
- Extend existing module discovery in `features/modules/`
- Integrate with workflow engine for script-based workflows
- Use existing steward communication for script deployment
- Leverage current RBAC system for script execution permissions

---

## Definition of Done

### Sprint-level DoD:
- [ ] All acceptance criteria met
- [ ] Unit tests written and passing
- [ ] Integration tests updated
- [ ] Code reviewed and merged
- [ ] Documentation updated
- [ ] Performance impact assessed

### Story-level DoD:
- [ ] Feature works end-to-end in development environment
- [ ] No regression in existing functionality
- [ ] Error handling implemented
- [ ] Logging and monitoring included
- [ ] Security considerations addressed

---

## Sprint Ceremonies

### Daily Standup (15 min)
- **When**: Daily at consistent time
- **Format**: What I completed, what I'm working on, any blockers
- **Tool**: Personal task tracking or todo list

### Sprint Review (1 hour)
- **When**: Last day of sprint
- **Format**: Demo completed features
- **Audience**: Stakeholders (potentially future team members)

### Sprint Retrospective (30 min)
- **When**: After sprint review
- **Format**: What went well, what could improve, action items
- **Output**: Process improvements for next sprint

### Sprint Planning (2 hours)
- **When**: First day of new sprint
- **Format**: Review backlog, estimate stories, commit to sprint
- **Output**: Sprint backlog with task breakdown

---

## Risks and Mitigation

### Sprint 1 Risks:
- **Configuration inheritance complexity**: Break into smaller tasks if needed
- **Tenant hierarchy modifications**: Leverage existing tenant system implementation

### Sprint 2 Risks:
- **Cross-platform script execution**: Start with single platform, expand gradually
- **Security implementation**: Focus on basic OS signing first, enhance later
- **Script module pattern**: Validate approach early with prototype

### General Risks:
- **Part-time development**: Adjust story points based on actual velocity
- **Solo development**: Document decisions clearly for future team members
- **Scope creep**: Stick to defined acceptance criteria

---

## Success Metrics

### Sprint 1 Success:
- Configuration inheritance working end-to-end
- REST API fully documented and tested
- Clear path to v0.2.0 completion

### Sprint 2 Success:
- Script execution works on at least one platform per OS family
- Audit logging captures all required information
- v0.2.0 ready for internal testing/validation

### v0.2.0 Success:
- All roadmap items marked complete
- System ready for broader testing
- Foundation set for v0.3.0 features

---

## Next Steps

1. **Begin Sprint 1 Planning**: Break stories into tasks
2. **Set up Sprint Board**: Visual tracking of story progress  
3. **Development Environment**: Ensure all tools ready for implementation
4. **Stakeholder Communication**: Regular updates on sprint progress

---

**Document Version**: 1.0  
**Last Updated**: July 27, 2025  
**Status**: Sprint Planning Complete - Ready for Sprint 1 Execution