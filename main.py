#!/usr/bin/env python3
"""
ARX MCP Server - Execute 100+ security operations with policy enforcement, audit logging, and human approvals
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any

import httpx
import structlog
from mcp.server import Server
from mcp.types import Tool, TextContent, ToolResult

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger()

# Configuration
ARXSEC_API_URL = os.getenv("ARXSEC_API_URL", "http://localhost:8000")
ARXSEC_API_KEY = os.getenv("ARXSEC_API_KEY", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Set logging level
logging.basicConfig(level=getattr(logging, LOG_LEVEL))


class ArxMCPServer:
    def __init__(self):
        self.server = Server("arx-mcp-server")
        self.client = httpx.AsyncClient(
            base_url=ARXSEC_API_URL,
            headers={"X-API-Key": ARXSEC_API_KEY} if ARXSEC_API_KEY else {},
        )
        self.audit_log = []
        self.pending_approvals = {}

        self._setup_tools()

    def _setup_tools(self):
        """Register all available MCP tools"""

        @self.server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="run_security_scan",
                    description="Execute a security scan on specified resources with policy enforcement",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_type": {
                                "type": "string",
                                "description": "Type of scan: sast, dast, sca, container, iac, sbom, appsec",
                                "enum": ["sast", "dast", "sca", "container", "iac", "sbom", "appsec"],
                            },
                            "target": {
                                "type": "string",
                                "description": "Target to scan (repository, URL, image, etc.)",
                            },
                            "policy_id": {
                                "type": "string",
                                "description": "Policy ID to enforce during scan",
                            },
                            "require_approval": {
                                "type": "boolean",
                                "description": "Require human approval before execution",
                                "default": False,
                            },
                        },
                        "required": ["scan_type", "target"],
                    },
                ),
                Tool(
                    name="execute_remediation",
                    description="Execute remediation actions for security findings",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "finding_id": {
                                "type": "string",
                                "description": "ID of the security finding to remediate",
                            },
                            "action": {
                                "type": "string",
                                "description": "Remediation action to execute",
                            },
                            "require_approval": {
                                "type": "boolean",
                                "description": "Require human approval before execution",
                                "default": True,
                            },
                        },
                        "required": ["finding_id", "action"],
                    },
                ),
                Tool(
                    name="check_compliance",
                    description="Check compliance status against regulations and standards",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "framework": {
                                "type": "string",
                                "description": "Compliance framework: SOC2, ISO27001, HIPAA, PCI-DSS, GDPR",
                                "enum": ["SOC2", "ISO27001", "HIPAA", "PCI-DSS", "GDPR"],
                            },
                            "scope": {
                                "type": "string",
                                "description": "Scope of compliance check",
                            },
                        },
                        "required": ["framework"],
                    },
                ),
                Tool(
                    name="manage_secrets",
                    description="Manage secrets with encryption, rotation, and audit",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Operation to perform",
                                "enum": ["create", "retrieve", "rotate", "revoke"],
                            },
                            "secret_name": {
                                "type": "string",
                                "description": "Name of the secret",
                            },
                            "secret_value": {
                                "type": "string",
                                "description": "Secret value (only for create operation)",
                            },
                        },
                        "required": ["operation", "secret_name"],
                    },
                ),
                Tool(
                    name="request_approval",
                    description="Request human approval for sensitive operations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Operation requiring approval",
                            },
                            "reason": {
                                "type": "string",
                                "description": "Reason for the operation",
                            },
                            "priority": {
                                "type": "string",
                                "description": "Priority level",
                                "enum": ["low", "medium", "high", "critical"],
                                "default": "medium",
                            },
                        },
                        "required": ["operation"],
                    },
                ),
                Tool(
                    name="get_audit_log",
                    description="Retrieve audit logs for compliance and investigation",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filters": {
                                "type": "object",
                                "description": "Filters for audit log (user, action, date_range, etc.)",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of records to return",
                                "default": 100,
                            },
                        },
                    },
                ),
                Tool(
                    name="list_connectors",
                    description="List available security connectors and integrations",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "connector_type": {
                                "type": "string",
                                "description": "Filter by connector type (sast, cloud, iam, etc.)",
                            },
                        },
                    },
                ),
                Tool(
                    name="manage_policies",
                    description="Create, update, or retrieve security policies",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "description": "Operation to perform",
                                "enum": ["create", "retrieve", "update", "delete", "list"],
                            },
                            "policy_id": {
                                "type": "string",
                                "description": "Policy ID",
                            },
                            "policy_definition": {
                                "type": "object",
                                "description": "Policy rules and configuration",
                            },
                        },
                        "required": ["operation"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> ToolResult:
            """Execute requested tool"""
            try:
                if name == "run_security_scan":
                    return await self._run_security_scan(arguments)
                elif name == "execute_remediation":
                    return await self._execute_remediation(arguments)
                elif name == "check_compliance":
                    return await self._check_compliance(arguments)
                elif name == "manage_secrets":
                    return await self._manage_secrets(arguments)
                elif name == "request_approval":
                    return await self._request_approval(arguments)
                elif name == "get_audit_log":
                    return await self._get_audit_log(arguments)
                elif name == "list_connectors":
                    return await self._list_connectors(arguments)
                elif name == "manage_policies":
                    return await self._manage_policies(arguments)
                else:
                    return ToolResult(
                        content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                        isError=True,
                    )
            except Exception as e:
                log.error("tool_execution_error", tool=name, error=str(e))
                return ToolResult(
                    content=[TextContent(type="text", text=f"Error executing {name}: {str(e)}")],
                    isError=True,
                )

    async def _run_security_scan(self, arguments: dict) -> ToolResult:
        """Execute a security scan"""
        scan_type = arguments.get("scan_type")
        target = arguments.get("target")
        policy_id = arguments.get("policy_id")
        require_approval = arguments.get("require_approval", False)

        log.info(
            "security_scan_initiated",
            scan_type=scan_type,
            target=target,
            policy_id=policy_id,
        )

        # Log to audit trail
        self._log_audit(
            action="run_security_scan",
            details={
                "scan_type": scan_type,
                "target": target,
                "policy_id": policy_id,
            },
            requires_approval=require_approval,
        )

        if require_approval:
            approval_id = self._create_approval_request(
                operation=f"Security scan ({scan_type}) on {target}",
                reason="Human approval required for security scan",
                priority="high",
            )
            return ToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"Scan request pending approval. Approval ID: {approval_id}",
                    )
                ],
                isError=False,
            )

        # Forward to API
        try:
            response = await self.client.post(
                f"/v1/compliance/scan",
                json={"scan_type": scan_type, "target": target, "policy_id": policy_id},
            )
            result = response.json()
            log.info("security_scan_completed", result=result)
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("security_scan_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Scan failed: {str(e)}")],
                isError=True,
            )

    async def _execute_remediation(self, arguments: dict) -> ToolResult:
        """Execute remediation for a security finding"""
        finding_id = arguments.get("finding_id")
        action = arguments.get("action")
        require_approval = arguments.get("require_approval", True)

        log.info("remediation_initiated", finding_id=finding_id, action=action)

        self._log_audit(
            action="execute_remediation",
            details={"finding_id": finding_id, "action": action},
            requires_approval=require_approval,
        )

        if require_approval:
            approval_id = self._create_approval_request(
                operation=f"Remediation action '{action}' for finding {finding_id}",
                reason="Human approval required for remediation",
                priority="high",
            )
            return ToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"Remediation request pending approval. Approval ID: {approval_id}",
                    )
                ],
                isError=False,
            )

        try:
            response = await self.client.post(
                f"/v1/audit/remediate",
                json={"finding_id": finding_id, "action": action},
            )
            result = response.json()
            log.info("remediation_completed", result=result)
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("remediation_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Remediation failed: {str(e)}")],
                isError=True,
            )

    async def _check_compliance(self, arguments: dict) -> ToolResult:
        """Check compliance status"""
        framework = arguments.get("framework")
        scope = arguments.get("scope", "")

        log.info("compliance_check_initiated", framework=framework, scope=scope)

        self._log_audit(
            action="check_compliance",
            details={"framework": framework, "scope": scope},
        )

        try:
            response = await self.client.get(
                f"/v1/compliance/status",
                params={"framework": framework, "scope": scope},
            )
            result = response.json()
            log.info("compliance_check_completed", result=result)
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("compliance_check_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Compliance check failed: {str(e)}")],
                isError=True,
            )

    async def _manage_secrets(self, arguments: dict) -> ToolResult:
        """Manage secrets"""
        operation = arguments.get("operation")
        secret_name = arguments.get("secret_name")
        secret_value = arguments.get("secret_value")

        log.info("secret_operation", operation=operation, secret_name=secret_name)

        self._log_audit(
            action="manage_secrets",
            details={"operation": operation, "secret_name": secret_name},
        )

        try:
            if operation == "create":
                response = await self.client.post(
                    f"/v1/secrets",
                    json={"name": secret_name, "value": secret_value},
                )
            elif operation == "retrieve":
                response = await self.client.get(f"/v1/secrets/{secret_name}")
            elif operation == "rotate":
                response = await self.client.post(f"/v1/secrets/{secret_name}/rotate")
            elif operation == "revoke":
                response = await self.client.delete(f"/v1/secrets/{secret_name}")
            else:
                return ToolResult(
                    content=[TextContent(type="text", text=f"Unknown operation: {operation}")],
                    isError=True,
                )

            result = response.json()
            log.info("secret_operation_completed", operation=operation)
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("secret_operation_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Secret operation failed: {str(e)}")],
                isError=True,
            )

    async def _request_approval(self, arguments: dict) -> ToolResult:
        """Request human approval"""
        operation = arguments.get("operation")
        reason = arguments.get("reason", "")
        priority = arguments.get("priority", "medium")

        approval_id = self._create_approval_request(operation, reason, priority)

        log.info("approval_requested", approval_id=approval_id, operation=operation)

        return ToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"Approval request created. ID: {approval_id}\nOperation: {operation}\nPriority: {priority}",
                )
            ],
            isError=False,
        )

    async def _get_audit_log(self, arguments: dict) -> ToolResult:
        """Retrieve audit logs"""
        filters = arguments.get("filters", {})
        limit = arguments.get("limit", 100)

        log.info("audit_log_retrieved", filters=filters, limit=limit)

        try:
            response = await self.client.get(
                f"/v1/audit/logs",
                params={"limit": limit, **filters},
            )
            result = response.json()
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("audit_log_retrieval_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Failed to retrieve audit log: {str(e)}")],
                isError=True,
            )

    async def _list_connectors(self, arguments: dict) -> ToolResult:
        """List available connectors"""
        connector_type = arguments.get("connector_type")

        log.info("connectors_listed", connector_type=connector_type)

        try:
            response = await self.client.get(
                f"/v1/connectors",
                params={"type": connector_type} if connector_type else {},
            )
            result = response.json()
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("connectors_list_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Failed to list connectors: {str(e)}")],
                isError=True,
            )

    async def _manage_policies(self, arguments: dict) -> ToolResult:
        """Manage security policies"""
        operation = arguments.get("operation")
        policy_id = arguments.get("policy_id")
        policy_definition = arguments.get("policy_definition")

        log.info("policy_operation", operation=operation, policy_id=policy_id)

        try:
            if operation == "create":
                response = await self.client.post(
                    f"/v1/policies",
                    json=policy_definition,
                )
            elif operation == "retrieve":
                response = await self.client.get(f"/v1/policies/{policy_id}")
            elif operation == "update":
                response = await self.client.put(
                    f"/v1/policies/{policy_id}",
                    json=policy_definition,
                )
            elif operation == "delete":
                response = await self.client.delete(f"/v1/policies/{policy_id}")
            elif operation == "list":
                response = await self.client.get(f"/v1/policies")
            else:
                return ToolResult(
                    content=[TextContent(type="text", text=f"Unknown operation: {operation}")],
                    isError=True,
                )

            result = response.json()
            log.info("policy_operation_completed", operation=operation)
            return ToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))],
                isError=False,
            )
        except Exception as e:
            log.error("policy_operation_failed", error=str(e))
            return ToolResult(
                content=[TextContent(type="text", text=f"Policy operation failed: {str(e)}")],
                isError=True,
            )

    def _log_audit(self, action: str, details: dict, requires_approval: bool = False):
        """Log action to audit trail"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "details": details,
            "requires_approval": requires_approval,
        }
        self.audit_log.append(audit_entry)
        log.info("audit_logged", action=action, details=details)

    def _create_approval_request(
        self, operation: str, reason: str = "", priority: str = "medium"
    ) -> str:
        """Create a human approval request"""
        approval_id = f"apr_{datetime.utcnow().timestamp()}"
        self.pending_approvals[approval_id] = {
            "operation": operation,
            "reason": reason,
            "priority": priority,
            "created_at": datetime.utcnow().isoformat(),
            "status": "pending",
        }
        log.info("approval_request_created", approval_id=approval_id, operation=operation)
        return approval_id

    async def run(self):
        """Run the MCP server"""
        log.info("arx_mcp_server_starting")
        async with self.server:
            log.info("arx_mcp_server_running")
            await asyncio.Event().wait()


async def main():
    server = ArxMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
