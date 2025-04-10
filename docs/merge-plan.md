# Documentation Merge Plan

## Overview
This document outlines the plan for merging the contents of `cfgms-docs` into the main `cfgms` repository. The goal is to preserve valuable documentation while ensuring it reflects the current state of the project.

## 1. Documentation Evaluation

### 1.1 Architectural Documentation Review
- [x] Compare current architectural docs in both repos
- [x] Identify outdated sections in `cfgms-docs`
- [x] Note any discrepancies in:
  - Project structure
  - Component design
  - Security architecture
  - Module system
  - Multi-tenancy approach
- [x] Create list of sections that need updates
- [x] Document any architectural decisions that have changed

### 1.2 Development Guidelines Review
- [x] Compare development standards
- [x] Review style guide applicability
- [x] Evaluate getting started guide
- [x] Assess AI integration guidelines
- [x] Note any changes needed to align with current practices

### 1.3 Product Documentation Review
- [x] Review vision statement
- [x] Remove comparison document
- [x] Create new roadmap based on current versioning strategy

## 2. Migration Steps

### 2.1 Component Terminology Standardization
- [x] Create a component terminology document that clearly defines:
  - **Controller**: The control server that manages the entire system
  - **Steward**: The cross-platform agent that runs on Windows, Linux, and macOS
  - **Outpost**: The proxy cache agent that can:
    - Act as a proxy cache for Stewards on a network
    - Monitor netflow and SNMP data from network devices
    - Provide agentless monitoring of IoT devices on the network
  - **Specialized Stewards**: Components that extend core functionality to specific environments:
    - **SaaS Steward**: Manages SaaS environments (v2)
    - **Cloud Steward**: Manages cloud environments (v2)
- [x] Review all existing documentation for incorrect terminology
- [x] Create a terminology reference guide for contributors
- [x] Update diagrams to reflect correct component names
- [x] Ensure consistent terminology across all documentation
- [x] Document deployment flexibility for specialized Stewards:
  - Controller plugin (simplest deployment)
  - Standalone service
  - Serverless function
  - Containerized service

### 2.2 Directory Structure Setup
- [x] Create basic architecture directory structure
- [x] Create core principles directory structure
- [x] Create security directory structure
- [x] Create module system directory structure
- [x] Create product documentation directory structure
- [x] Create multi-tenancy directory structure
- [x] Create configuration directory structure
- [ ] Create implementation details directory structure:
```bash
docs/
├── architecture/
│   ├── components/
│   ├── core-principles/
│   ├── security/
│   ├── modules/
│   ├── multi-tenancy/
│   ├── configuration/
│   └── implementation/
├── development/
│   ├── guides/
│   └── standards/
└── product/
    ├── vision.md
    └── comparison.md
```

### 2.3 Content Migration
1. **Architecture Documentation**
   a. **Core Architecture**
      - [x] Create `docs/architecture/` directory structure
      - [x] Create `components.md`:
        - Define Controller, Steward, and Outpost roles
        - Document component interactions
        - Add current implementation details
        - Include component interaction diagrams
        - Document specialized Stewards (SaaS, Cloud) and their deployment options
      - [x] Create core principles documentation:
        - Resilience
        - Security
        - Scalability
        - Simplicity
        - Modularity
      - [x] Migrate and update `overview.md`:
        - Remove "Dark Port" references
        - Update communication flow diagrams
        - Align with current Controller-Steward-Outpost focus
        - Preserve core design principles

   b. **Security Architecture**
      - [x] Create `security/` directory structure
      - [x] Merge security documentation:
        - Keep current SDRs (001, 002, 003)
        - Update `architecture.md` with:
          - Current communication security model
          - Updated authentication flows
          - Current certificate management
          - API security implementation
        - Add sections from docs repo:
          - Pluggable security components
          - Logging and audit system
          - Compliance support framework
          - Security policy management

   c. **Module System**
      - [x] Create `modules/` directory
      - [x] Migrate module documentation:
        - Core module principles
        - Module interface definitions
        - Module lifecycle management
        - Module security requirements
        - Module testing requirements

   d. **Multi-tenancy**
      - [x] Create `multi-tenancy/` directory
      - [x] Update tenant documentation:
        - Current parent-child model
        - Configuration inheritance
        - RBAC implementation
        - Tenant isolation
        - Cross-tenant operations

   e. **Configuration Management**
      - [x] Create `configuration/` directory
      - [x] Document current approach:
        - Configuration data format
        - Configuration types
        - Configuration validation
        - Configuration storage
        - Inheritance model
        - Version control integration
        - Rollback capabilities

   f. **Implementation Details**
      - [ ] Create `implementation/` directory
      - [ ] Add current implementation specifics:
        - Directory structure
        - Package organization
        - Interface definitions
        - Error handling
        - Testing approach

   g. **Cross-references and Navigation**
      - [x] Create `README.md` in architecture directory
      - [x] Create `README.md` in core-principles directory
      - [x] Create `README.md` in security directory
      - [x] Create `README.md` in modules directory
      - [x] Create `README.md` in product directory
      - [x] Create `README.md` in multi-tenancy directory
      - [x] Create `README.md` in configuration directory
      - [ ] Create `README.md` in implementation directory
      - [ ] Add navigation links between documents
      - [ ] Ensure consistent terminology
      - [ ] Add version information
      - [ ] Include change history

   h. **Diagrams and Examples**
      - [ ] Update all diagrams to reflect current architecture
      - [ ] Add implementation examples
      - [ ] Include configuration samples
      - [ ] Add troubleshooting guides

2. **Development Guidelines**
   - [x] Migrate standards and style guides
   - [x] Update getting started guide
   - [x] Integrate AI guidelines
   - [x] Add current development workflow

3. **Product Documentation**
   - [x] Migrate vision statement
   - [x] Update comparison document
   - [x] Create new roadmap
   - [x] Add versioning strategy

### 2.4 Documentation Updates
- [ ] Update all internal references
- [ ] Ensure consistent formatting
- [ ] Add cross-references between documents
- [ ] Update any code examples
- [ ] Verify all links work

## 3. Quality Assurance

### 3.1 Technical Review
- [ ] Verify architectural accuracy
- [ ] Check code examples
- [ ] Validate configuration examples
- [ ] Review security documentation

### 3.2 Content Review
- [ ] Check for consistency in terminology
- [ ] Verify all sections are properly linked
- [ ] Ensure proper markdown formatting
- [ ] Validate all diagrams and images

### 3.3 Final Steps
- [ ] Create new roadmap in main repo
- [ ] Update README.md to reflect new documentation structure
- [ ] Add documentation contribution guidelines
- [ ] Set up documentation review process

## 4. Post-Migration

### 4.1 Cleanup
- [ ] Archive `cfgms-docs` repository
- [ ] Update any external references
- [ ] Notify contributors of the change

### 4.2 Maintenance Plan
- [ ] Establish documentation update process
- [ ] Set up regular documentation reviews
- [ ] Create documentation versioning strategy
- [ ] Define documentation ownership

## Next Steps
1. ~~Create the security architecture documentation directory and begin migrating security documentation~~ ✅ COMPLETED
2. ~~Create the module system documentation directory and begin migrating module documentation~~ ✅ COMPLETED
3. ~~Complete the Development Guidelines Review section~~ ✅ COMPLETED
4. ~~Complete the Product Documentation Review section~~ ✅ COMPLETED
5. ~~Create the multi-tenancy documentation directory and begin migrating tenant documentation~~ ✅ COMPLETED
6. ~~Create the configuration management documentation directory and begin migrating configuration documentation~~ ✅ COMPLETED
7. Create the implementation details documentation directory and begin migrating implementation documentation

## Notes
- Keep track of any decisions made during the merge
- Document any significant changes to architectural decisions
- Note any sections that need further development
- Track any technical debt in documentation
