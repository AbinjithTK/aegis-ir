"""Tests for require_permission FastAPI dependency.

Validates requirements:
    4.2 - RBAC permission enforcement: deny unauthorized requests and return 403
    7.1 - Audit logging of permission denial events
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from sift_defender.enterprise.auth.dependencies import (
    User,
    _resolve_permissions_from_roles,
    get_current_user,
    require_permission,
)
from sift_defender.enterprise.auth.jwt import create_access_token
from sift_defender.enterprise.auth.rbac import DEFAULT_ROLES, Permission


# Use a fixed secret for deterministic tests
TEST_SECRET = "test-jwt-secret-for-unit-tests"


@pytest.fixture(autouse=True)
def set_jwt_secret(monkeypatch):
    """Set a consistent JWT secret for all tests."""
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)


# --- Helper Permission Resolution Tests ---


class TestResolvePermissionsFromRoles:
    """Tests for the _resolve_permissions_from_roles helper."""

    def test_soc_analyst_role_resolves_permissions(self):
        """SOC analyst role should resolve to the expected permission set."""
        perms = _resolve_permissions_from_roles(["soc_analyst"])
        assert Permission.INVESTIGATE_START in perms
        assert Permission.INVESTIGATE_VIEW in perms
        assert Permission.FINDING_APPROVE in perms
        assert Permission.PLAYBOOK_VIEW in perms
        # SOC analyst should NOT have management permissions
        assert Permission.CASE_MANAGE not in perms
        assert Permission.PLAYBOOK_EDIT not in perms
        assert Permission.SETTINGS_EDIT not in perms

    def test_ir_lead_role_includes_soc_analyst_perms(self):
        """IR lead should have all SOC analyst permissions plus management."""
        perms = _resolve_permissions_from_roles(["ir_lead"])
        # Should include SOC analyst permissions
        assert Permission.INVESTIGATE_START in perms
        assert Permission.FINDING_APPROVE in perms
        # Plus management permissions
        assert Permission.CASE_MANAGE in perms
        assert Permission.PLAYBOOK_EDIT in perms
        assert Permission.SETTINGS_EDIT in perms
        assert Permission.USER_MANAGE in perms

    def test_ciso_role_has_readonly_permissions(self):
        """CISO role should have read-only and reporting permissions."""
        perms = _resolve_permissions_from_roles(["ciso"])
        assert Permission.INVESTIGATE_VIEW in perms
        assert Permission.AUDIT_VIEW in perms
        assert Permission.AUDIT_EXPORT in perms
        assert Permission.REPORT_EXECUTIVE in perms
        # CISO should NOT have write permissions
        assert Permission.INVESTIGATE_START not in perms
        assert Permission.CASE_CREATE not in perms

    def test_multiple_roles_union_permissions(self):
        """Multiple roles should produce the union of their permissions."""
        perms = _resolve_permissions_from_roles(["soc_analyst", "ciso"])
        # From soc_analyst
        assert Permission.INVESTIGATE_START in perms
        assert Permission.FINDING_APPROVE in perms
        # From ciso
        assert Permission.AUDIT_EXPORT in perms
        assert Permission.REPORT_EXECUTIVE in perms

    def test_unknown_role_returns_empty_set(self):
        """Unknown role names should be skipped, returning empty set."""
        perms = _resolve_permissions_from_roles(["unknown_role"])
        assert perms == set()

    def test_empty_roles_returns_empty_set(self):
        """Empty role list should return empty permission set."""
        perms = _resolve_permissions_from_roles([])
        assert perms == set()

    def test_mix_known_and_unknown_roles(self):
        """Known roles should resolve while unknown are silently skipped."""
        perms = _resolve_permissions_from_roles(["nonexistent", "soc_analyst"])
        assert Permission.INVESTIGATE_START in perms
        assert len(perms) == len(DEFAULT_ROLES["soc_analyst"])


# --- require_permission Dependency Tests ---


def _create_permission_test_app() -> FastAPI:
    """Create a test app with permission-protected endpoints."""
    app = FastAPI()

    @app.get("/playbooks")
    async def list_playbooks(
        user: User = Depends(require_permission(Permission.PLAYBOOK_VIEW)),
    ):
        return {"user_id": user.id, "tenant_id": user.tenant_id}

    @app.post("/playbooks")
    async def edit_playbook(
        user: User = Depends(require_permission(Permission.PLAYBOOK_EDIT)),
    ):
        return {"user_id": user.id, "action": "edit"}

    @app.get("/settings")
    async def view_settings(
        user: User = Depends(require_permission(Permission.SETTINGS_EDIT)),
    ):
        return {"user_id": user.id}

    @app.get("/reports/executive")
    async def executive_report(
        user: User = Depends(require_permission(Permission.REPORT_EXECUTIVE)),
    ):
        return {"user_id": user.id}

    return app


@pytest.fixture
def permission_app():
    """Create a test app with permission-protected routes."""
    return _create_permission_test_app()


@pytest.fixture
def permission_client(permission_app):
    """Create a test client for the permission-protected app."""
    return TestClient(permission_app)


class TestRequirePermissionGranted:
    """Tests verifying that authorized users can access endpoints."""

    def test_soc_analyst_can_view_playbooks(self, permission_client):
        """SOC analyst should access PLAYBOOK_VIEW endpoints."""
        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        response = permission_client.get(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["user_id"] == "user-1"
        assert response.json()["tenant_id"] == "tenant-1"

    def test_ir_lead_can_edit_playbooks(self, permission_client):
        """IR lead should access PLAYBOOK_EDIT endpoints."""
        token = create_access_token("user-2", "tenant-1", ["ir_lead"])
        response = permission_client.post(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["action"] == "edit"

    def test_ir_lead_can_also_view_playbooks(self, permission_client):
        """IR lead inherits SOC analyst permissions including PLAYBOOK_VIEW."""
        token = create_access_token("user-2", "tenant-1", ["ir_lead"])
        response = permission_client.get(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

    def test_ciso_can_view_executive_reports(self, permission_client):
        """CISO should access REPORT_EXECUTIVE endpoints."""
        token = create_access_token("user-3", "tenant-1", ["ciso"])
        response = permission_client.get(
            "/reports/executive", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

    def test_user_returned_on_success(self, permission_client):
        """The dependency should return the User object on success."""
        token = create_access_token("user-42", "tenant-abc", ["ir_lead"])
        response = permission_client.get(
            "/settings", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["user_id"] == "user-42"


class TestRequirePermissionDenied:
    """Tests verifying that unauthorized users are denied with 403."""

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_soc_analyst_denied_playbook_edit(self, mock_record, permission_client):
        """SOC analyst should be denied PLAYBOOK_EDIT access with 403."""
        mock_record.return_value = "event-id-1"

        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        response = permission_client.post(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_soc_analyst_denied_settings_edit(self, mock_record, permission_client):
        """SOC analyst should be denied SETTINGS_EDIT access with 403."""
        mock_record.return_value = "event-id-2"

        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        response = permission_client.get(
            "/settings", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_ciso_denied_playbook_edit(self, mock_record, permission_client):
        """CISO should be denied PLAYBOOK_EDIT access."""
        mock_record.return_value = "event-id-3"

        token = create_access_token("user-3", "tenant-1", ["ciso"])
        response = permission_client.post(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_user_with_no_roles_denied_everything(self, mock_record, permission_client):
        """User with no roles should be denied all permission-protected endpoints."""
        mock_record.return_value = "event-id-4"

        token = create_access_token("user-noroles", "tenant-1", [])
        response = permission_client.get(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403

    def test_unauthenticated_request_returns_401(self, permission_client):
        """Missing auth should return 401, not 403."""
        response = permission_client.get("/playbooks")
        assert response.status_code == 401


class TestRequirePermissionAuditLogging:
    """Tests verifying that denial events are logged to the audit log."""

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_denial_logs_audit_event(self, mock_record, permission_client):
        """Permission denial should log a PERMISSION_DENIED audit event."""
        mock_record.return_value = "audit-event-123"

        token = create_access_token("user-denied", "tenant-abc", ["soc_analyst"])
        response = permission_client.post(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403

        # Verify audit record was called
        mock_record.assert_called_once()
        # The patched method receives (self_instance, event) as positional args
        positional_args = mock_record.call_args[0]
        # Find the AuditEvent in positional args
        from sift_defender.enterprise.audit.service import AuditEvent
        audit_event = next(
            arg for arg in positional_args if isinstance(arg, AuditEvent)
        )
        assert audit_event.tenant_id == "tenant-abc"
        assert audit_event.user_id == "user-denied"
        assert audit_event.event_type.value == "permission.denied"
        assert audit_event.resource_type == "permission"
        assert audit_event.resource_id == Permission.PLAYBOOK_EDIT.value
        assert "required_permission" in audit_event.details
        assert "user_roles" in audit_event.details
        assert audit_event.details["user_roles"] == ["soc_analyst"]

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_audit_failure_does_not_prevent_403(self, mock_record, permission_client):
        """If audit logging fails, the 403 response should still be returned."""
        mock_record.side_effect = RuntimeError("DB connection failed")

        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        response = permission_client.post(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        # Still returns 403 even though audit logging failed
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    @patch("sift_defender.enterprise.audit.service.AuditLogService.record", new_callable=AsyncMock)
    def test_no_audit_event_on_granted_access(self, mock_record, permission_client):
        """Granted access should NOT trigger an audit event."""
        token = create_access_token("user-1", "tenant-1", ["soc_analyst"])
        response = permission_client.get(
            "/playbooks", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        mock_record.assert_not_called()
