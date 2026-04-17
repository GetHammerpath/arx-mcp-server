# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-04-17

### Added
- Initial release of ARX MCP Server
- 8 core security operations tools:
  - `run_security_scan` - Execute security scans (SAST, DAST, SCA, Container, IaC, SBOM, AppSec)
  - `execute_remediation` - Execute remediation actions for security findings
  - `check_compliance` - Check compliance against SOC2, ISO27001, HIPAA, PCI-DSS, GDPR
  - `manage_secrets` - Manage secrets with encryption and rotation
  - `request_approval` - Request human approval for sensitive operations
  - `get_audit_log` - Retrieve audit logs for compliance
  - `list_connectors` - List available security connectors
  - `manage_policies` - Create and manage security policies
- Policy enforcement on all operations
- Comprehensive audit logging
- Human approval workflows
- Integration with ARXsec.io API
- Full test suite with 15+ test cases
- Docker and docker-compose support
- Comprehensive documentation

### Features
- Structured logging with audit trails
- Async/await architecture for performance
- Full error handling and validation
- Support for 20+ security tool integrations
- Framework support: SOC2, ISO27001, HIPAA, PCI-DSS, GDPR

## [Unreleased]

### Planned
- Additional security scanners
- Enhanced approval workflows
- Integration with more platforms
- Web UI for approvals and audit logs
- Batch operation support

---

### How to Update the Changelog

When making a new release:
1. Create a new section with version and date: `## [X.Y.Z] - YYYY-MM-DD`
2. Add changes under: Added, Changed, Deprecated, Removed, Fixed, Security
3. Update version in `__init__.py` and `pyproject.toml`
4. Create a GitHub release with the changelog content

### Change Categories
- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security vulnerability fixes
