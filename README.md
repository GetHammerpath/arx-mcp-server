# arx-mcp-server

[![PyPI Version](https://img.shields.io/pypi/v/arx-mcp-server)](https://pypi.org/project/arx-mcp-server/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/GetHammerpath/arx-mcp-server/actions/workflows/test.yml/badge.svg)](https://github.com/GetHammerpath/arx-mcp-server/actions)

ARX MCP Server - Execute 100+ security operations with policy enforcement, audit logging, and human approvals

## Overview

The Arx MCP Server is a Model Context Protocol (MCP) implementation that provides comprehensive security operations management. It integrates with the ARXsec.io API to execute security scans, manage compliance, handle secrets, and more—all with built-in policy enforcement, detailed audit logging, and human approval workflows.

## Features

- **Security Scanning**: SAST, DAST, SCA, Container, IaC, SBOM, and AppSec scanning
- **Compliance Management**: Support for SOC2, ISO27001, HIPAA, PCI-DSS, and GDPR frameworks
- **Secrets Management**: Encrypted secret storage with rotation and revocation
- **Policy Enforcement**: Define and enforce security policies across operations
- **Audit Logging**: Comprehensive audit trails for compliance and investigation
- **Human Approvals**: Approval workflows for sensitive operations
- **Connector Management**: Integration with 20+ security tools and platforms
- **Remediation**: Execute automated remediation actions for security findings

## Tools Provided

### 1. run_security_scan
Execute security scans with policy enforcement

**Parameters:**
- `scan_type` (enum): sast, dast, sca, container, iac, sbom, appsec
- `target` (string): Target to scan (repository, URL, image, etc.)
- `policy_id` (string, optional): Policy ID to enforce
- `require_approval` (boolean, default: false): Require human approval

### 2. execute_remediation
Execute remediation actions for security findings

**Parameters:**
- `finding_id` (string): ID of the security finding
- `action` (string): Remediation action to execute
- `require_approval` (boolean, default: true): Require human approval

### 3. check_compliance
Check compliance status against regulations

**Parameters:**
- `framework` (enum): SOC2, ISO27001, HIPAA, PCI-DSS, GDPR
- `scope` (string, optional): Scope of compliance check

### 4. manage_secrets
Manage secrets with encryption, rotation, and audit

**Parameters:**
- `operation` (enum): create, retrieve, rotate, revoke
- `secret_name` (string): Name of the secret
- `secret_value` (string, optional): Secret value (for create operation)

### 5. request_approval
Request human approval for operations

**Parameters:**
- `operation` (string): Operation requiring approval
- `reason` (string, optional): Reason for the operation
- `priority` (enum): low, medium, high, critical

### 6. get_audit_log
Retrieve audit logs for compliance and investigation

**Parameters:**
- `filters` (object, optional): Filters for audit log
- `limit` (integer, default: 100): Maximum records to return

### 7. list_connectors
List available security connectors and integrations

**Parameters:**
- `connector_type` (string, optional): Filter by connector type

### 8. manage_policies
Create, update, or retrieve security policies

**Parameters:**
- `operation` (enum): create, retrieve, update, delete, list
- `policy_id` (string, optional): Policy ID
- `policy_definition` (object, optional): Policy rules and configuration

## Installation

### Prerequisites
- Python 3.9+
- ARXsec.io API (running or accessible)

### From PyPI (Recommended)

```bash
pip install arx-mcp-server
```

### From Source

1. Clone the repository:
```bash
git clone https://github.com/GetHammerpath/arx-mcp-server.git
cd arx-mcp-server
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install in development mode:
```bash
pip install -e .
```

4. (Optional) Install development dependencies:
```bash
pip install -e ".[dev]"
```

### Configuration

Create `.env` file with your settings:
```bash
cp .env.example .env
# Edit .env with your settings
```

Example `.env`:
```
ARXSEC_API_URL=https://api.arxsec.io
ARXSEC_API_KEY=your-api-key-here
LOG_LEVEL=INFO
```

## Usage

### Standalone Mode

```bash
python main.py
```

### Docker

```bash
docker build -t arx-mcp-server .
docker run -e ARXSEC_API_URL=http://arxsec-api:8000 arx-mcp-server
```

### Docker Compose

```bash
docker-compose up
```

## Configuration

### Environment Variables

- `ARXSEC_API_URL`: Base URL for ARXsec.io API (default: http://localhost:8000)
- `ARXSEC_API_KEY`: API key for authentication (optional)
- `LOG_LEVEL`: Logging level (default: INFO)

## Testing

Run tests with pytest:

```bash
pip install pytest pytest-asyncio
pytest
```

With coverage:

```bash
pip install pytest-cov
pytest --cov=. tests/
```

## Architecture

The server consists of:

- **ArxMCPServer**: Main server class implementing MCP protocol
- **Tool Registry**: Tool definitions and handlers
- **Audit Logger**: Tracks all operations for compliance
- **Approval Manager**: Manages human approval workflows
- **API Client**: Communicates with ARXsec.io API

### Data Flow

```
Claude/Client
    ↓
MCP Server
    ├─ Tool List
    ├─ Tool Execution
    └─ Error Handling
         ↓
Policy Enforcement & Approval Logic
         ↓
ARXsec.io API
    ├─ Security Operations
    ├─ Compliance Management
    ├─ Secrets Management
    └─ Audit Logging
         ↓
Database & Backend Services
```

## API Integration

The server communicates with the ARXsec.io API at `/v1/*` endpoints:

- `POST /v1/compliance/scan` - Execute security scan
- `POST /v1/audit/remediate` - Execute remediation
- `GET /v1/compliance/status` - Check compliance
- `POST/GET/DELETE /v1/secrets/*` - Manage secrets
- `GET /v1/audit/logs` - Retrieve audit logs
- `GET /v1/connectors` - List connectors
- `GET/POST/PUT/DELETE /v1/policies/*` - Manage policies

## Security Considerations

1. **API Key**: Store API keys securely in environment variables
2. **HTTPS**: Always use HTTPS in production
3. **Approval Workflows**: Enable approval for sensitive operations
4. **Audit Logging**: All operations are logged for compliance
5. **Policy Enforcement**: Define strict policies for security operations
6. **Secret Rotation**: Rotate secrets regularly

## Development

### Code Structure

```
arx-mcp-server/
├── main.py                 # Main server implementation
├── requirements.txt        # Python dependencies
├── setup.py               # Package configuration
├── Dockerfile             # Container configuration
├── docker-compose.yml     # Multi-container setup
├── pytest.ini             # Test configuration
├── tests/                 # Test suite
│   └── test_server.py
└── README.md
```

### Adding New Tools

To add a new tool:

1. Add tool definition to `_setup_tools()` in `ArxMCPServer`
2. Implement handler method (e.g., `async def _new_tool(self, arguments)`)
3. Register handler in `call_tool()` function
4. Add tests in `tests/test_server.py`

## Logging

The server uses structured logging with `structlog`:

```python
log.info("event_name", key="value")
```

Logs include:
- Timestamp (ISO 8601)
- Event type
- Request/Response details
- Error information
- Audit trail

## Error Handling

All tool execution errors are caught and returned as `ToolResult` with `isError=True`. Detailed error messages are logged for debugging.

## Approval Workflow

Sensitive operations can require human approval:

1. Operation is initiated with `require_approval=True`
2. Approval request is created with unique ID
3. Operation is queued pending approval
4. Human reviews and approves/rejects
5. Operation executes (if approved) or fails

## Support

For issues or questions:
- GitHub Issues: https://github.com/GetHammerpath/arx-mcp-server/issues
- Documentation: https://docs.arxsec.io
- Email: support@hammerpath.io

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Acknowledgments

- Built with [Model Context Protocol](https://modelcontextprotocol.io)
- Integrates with [ARXsec.io](https://arxsec.io)
- Security best practices from OWASP and NIST
