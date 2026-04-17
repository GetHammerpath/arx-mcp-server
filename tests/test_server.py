import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from main import ArxMCPServer


@pytest.fixture
def server():
    """Create an ArxMCPServer instance for testing"""
    return ArxMCPServer()


@pytest.mark.asyncio
async def test_run_security_scan(server):
    """Test running a security scan"""
    arguments = {
        "scan_type": "sast",
        "target": "https://github.com/example/repo",
        "policy_id": "policy-123",
        "require_approval": False,
    }

    with patch.object(server.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value.json.return_value = {
            "scan_id": "scan-123",
            "status": "completed",
            "findings": 5,
        }

        result = await server._run_security_scan(arguments)

        assert result.isError is False
        assert "scan-123" in result.content[0].text
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_run_security_scan_with_approval(server):
    """Test security scan requiring approval"""
    arguments = {
        "scan_type": "dast",
        "target": "https://example.com",
        "require_approval": True,
    }

    result = await server._run_security_scan(arguments)

    assert result.isError is False
    assert "pending approval" in result.content[0].text
    assert len(server.pending_approvals) == 1


@pytest.mark.asyncio
async def test_execute_remediation(server):
    """Test executing remediation"""
    arguments = {
        "finding_id": "finding-123",
        "action": "update_dependency",
        "require_approval": False,
    }

    with patch.object(server.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value.json.return_value = {
            "status": "success",
            "remediated_items": 1,
        }

        result = await server._execute_remediation(arguments)

        assert result.isError is False
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_check_compliance(server):
    """Test checking compliance status"""
    arguments = {
        "framework": "SOC2",
        "scope": "production",
    }

    with patch.object(server.client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value.json.return_value = {
            "framework": "SOC2",
            "compliant": True,
            "coverage": 95,
        }

        result = await server._check_compliance(arguments)

        assert result.isError is False
        assert "compliant" in result.content[0].text


@pytest.mark.asyncio
async def test_manage_secrets_create(server):
    """Test creating a secret"""
    arguments = {
        "operation": "create",
        "secret_name": "db_password",
        "secret_value": "secret123",
    }

    with patch.object(server.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value.json.return_value = {
            "status": "created",
            "secret_id": "sec-123",
        }

        result = await server._manage_secrets(arguments)

        assert result.isError is False
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_manage_secrets_retrieve(server):
    """Test retrieving a secret"""
    arguments = {
        "operation": "retrieve",
        "secret_name": "db_password",
    }

    with patch.object(server.client, 'get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value.json.return_value = {
            "secret_name": "db_password",
            "value": "secret123",
        }

        result = await server._manage_secrets(arguments)

        assert result.isError is False
        mock_get.assert_called_once()


@pytest.mark.asyncio
async def test_request_approval(server):
    """Test requesting approval"""
    arguments = {
        "operation": "Deploy to production",
        "reason": "Release v1.0.0",
        "priority": "high",
    }

    result = await server._request_approval(arguments)

    assert result.isError is False
    assert "Approval request created" in result.content[0].text
    assert len(server.pending_approvals) == 1


def test_audit_logging(server):
    """Test audit logging"""
    server._log_audit(
        action="test_action",
        details={"key": "value"},
        requires_approval=False,
    )

    assert len(server.audit_log) == 1
    assert server.audit_log[0]["action"] == "test_action"
    assert server.audit_log[0]["details"]["key"] == "value"


def test_approval_request_creation(server):
    """Test approval request creation"""
    approval_id = server._create_approval_request(
        operation="Test operation",
        reason="Test reason",
        priority="critical",
    )

    assert approval_id in server.pending_approvals
    assert server.pending_approvals[approval_id]["status"] == "pending"
    assert server.pending_approvals[approval_id]["priority"] == "critical"


@pytest.mark.asyncio
async def test_tool_list(server):
    """Test tool listing"""
    tools = await server.server.list_tools()

    tool_names = [tool.name for tool in tools]
    assert "run_security_scan" in tool_names
    assert "execute_remediation" in tool_names
    assert "check_compliance" in tool_names
    assert "manage_secrets" in tool_names
    assert "request_approval" in tool_names
    assert "get_audit_log" in tool_names
    assert "list_connectors" in tool_names
    assert "manage_policies" in tool_names


@pytest.mark.asyncio
async def test_error_handling(server):
    """Test error handling"""
    arguments = {
        "scan_type": "sast",
        "target": "https://github.com/example/repo",
    }

    with patch.object(server.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = Exception("Connection error")

        result = await server._run_security_scan(arguments)

        assert result.isError is True
        assert "Connection error" in result.content[0].text
