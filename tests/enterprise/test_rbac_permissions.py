"""Tests for Permission enum and DEFAULT_ROLES mapping.

Validates that:
- Permission enum defines exactly 16 permissions per design specification
- All permissions follow the 'resource:action' string format
- Permission values are unique and usable as strings
- DEFAULT_ROLES maps three roles (soc_analyst, ir_lead, ciso)
- ir_lead includes ALL soc_analyst permissions plus management permissions
- ciso has a minimal read-only permission set
- Role permission sets are frozensets (immutable)

Requirements: 4.1, 4.3
"""

from __future__ import annotations

import pytest

from sift_defender.enterprise.auth.rbac import DEFAULT_ROLES, Permission


# ─── Permission Enum Definition ──────────────────────────────────────────────


class TestPermissionEnum:
    """Test the Permission enum structure and values."""

    def test_has_exactly_16_members(self):
        """Design specifies 16 permissions."""
        assert len(Permission) == 16

    def test_all_values_follow_resource_action_format(self):
        """Every permission must be 'resource:action'."""
        for perm in Permission:
            parts = perm.value.split(":")
            assert len(parts) == 2, f"{perm.name} value '{perm.value}' is not 'resource:action'"
            assert len(parts[0]) > 0, f"{perm.name} has empty resource"
            assert len(parts[1]) > 0, f"{perm.name} has empty action"

    def test_all_values_are_unique(self):
        """No two permissions should share the same string value."""
        values = [perm.value for perm in Permission]
        assert len(values) == len(set(values))

    def test_permission_is_string_subclass(self):
        """Permission extends str so it can be used directly as a string."""
        for perm in Permission:
            assert isinstance(perm, str)
            assert perm == perm.value

    def test_investigation_permissions(self):
        assert Permission.INVESTIGATE_START == "investigation:start"
        assert Permission.INVESTIGATE_VIEW == "investigation:view"

    def test_finding_permissions(self):
        assert Permission.FINDING_APPROVE == "finding:approve"
        assert Permission.FINDING_REJECT == "finding:reject"

    def test_case_permissions(self):
        assert Permission.CASE_CREATE == "case:create"
        assert Permission.CASE_MANAGE == "case:manage"
        assert Permission.CASE_ASSIGN == "case:assign"

    def test_playbook_permissions(self):
        assert Permission.PLAYBOOK_EDIT == "playbook:edit"
        assert Permission.PLAYBOOK_VIEW == "playbook:view"

    def test_settings_permissions(self):
        assert Permission.SETTINGS_VIEW == "settings:view"
        assert Permission.SETTINGS_EDIT == "settings:edit"

    def test_evidence_permission(self):
        assert Permission.EVIDENCE_ACCESS == "evidence:access"

    def test_audit_permissions(self):
        assert Permission.AUDIT_VIEW == "audit:view"
        assert Permission.AUDIT_EXPORT == "audit:export"

    def test_report_permission(self):
        assert Permission.REPORT_EXECUTIVE == "report:executive"

    def test_user_manage_permission(self):
        assert Permission.USER_MANAGE == "user:manage"

    def test_permission_usable_in_sets(self):
        """Permissions can be collected into sets for role definitions."""
        perm_set = {Permission.INVESTIGATE_START, Permission.INVESTIGATE_VIEW}
        assert Permission.INVESTIGATE_START in perm_set
        assert Permission.CASE_CREATE not in perm_set

    def test_permission_string_comparison(self):
        """Permission enum values compare equal to their string representation."""
        assert Permission.INVESTIGATE_START == "investigation:start"
        assert "investigation:start" == Permission.INVESTIGATE_START

    def test_permission_hashable(self):
        """Permissions are hashable (required for use in sets/dicts)."""
        perm_dict = {Permission.INVESTIGATE_START: True}
        assert perm_dict[Permission.INVESTIGATE_START] is True


# ─── DEFAULT_ROLES Mapping ───────────────────────────────────────────────────


class TestDefaultRoles:
    """Test the DEFAULT_ROLES mapping structure and correctness."""

    def test_contains_three_roles(self):
        assert len(DEFAULT_ROLES) == 3

    def test_role_names(self):
        assert set(DEFAULT_ROLES.keys()) == {"soc_analyst", "ir_lead", "ciso"}

    def test_role_values_are_frozensets(self):
        """Role permission sets should be immutable."""
        for role_name, perms in DEFAULT_ROLES.items():
            assert isinstance(perms, frozenset), (
                f"Role '{role_name}' permissions should be frozenset, got {type(perms)}"
            )

    def test_all_role_values_contain_permission_instances(self):
        """Every element in each role set must be a Permission enum member."""
        for role_name, perms in DEFAULT_ROLES.items():
            for perm in perms:
                assert isinstance(perm, Permission), (
                    f"Role '{role_name}' contains non-Permission value: {perm!r}"
                )


class TestSocAnalystRole:
    """Test soc_analyst role permission set."""

    def test_has_7_permissions(self):
        assert len(DEFAULT_ROLES["soc_analyst"]) == 7

    def test_contains_investigation_permissions(self):
        perms = DEFAULT_ROLES["soc_analyst"]
        assert Permission.INVESTIGATE_START in perms
        assert Permission.INVESTIGATE_VIEW in perms

    def test_contains_finding_permissions(self):
        perms = DEFAULT_ROLES["soc_analyst"]
        assert Permission.FINDING_APPROVE in perms
        assert Permission.FINDING_REJECT in perms

    def test_contains_case_create(self):
        assert Permission.CASE_CREATE in DEFAULT_ROLES["soc_analyst"]

    def test_contains_playbook_view(self):
        assert Permission.PLAYBOOK_VIEW in DEFAULT_ROLES["soc_analyst"]

    def test_contains_evidence_access(self):
        assert Permission.EVIDENCE_ACCESS in DEFAULT_ROLES["soc_analyst"]

    def test_does_not_contain_management_permissions(self):
        """SOC analysts cannot manage cases, edit playbooks, or manage users."""
        perms = DEFAULT_ROLES["soc_analyst"]
        assert Permission.CASE_MANAGE not in perms
        assert Permission.CASE_ASSIGN not in perms
        assert Permission.PLAYBOOK_EDIT not in perms
        assert Permission.SETTINGS_VIEW not in perms
        assert Permission.SETTINGS_EDIT not in perms
        assert Permission.USER_MANAGE not in perms

    def test_does_not_contain_executive_permissions(self):
        """SOC analysts cannot access audit export or executive reports."""
        perms = DEFAULT_ROLES["soc_analyst"]
        assert Permission.AUDIT_VIEW not in perms
        assert Permission.AUDIT_EXPORT not in perms
        assert Permission.REPORT_EXECUTIVE not in perms


class TestIrLeadRole:
    """Test ir_lead role permission set."""

    def test_has_14_permissions(self):
        """ir_lead has 7 (soc_analyst) + 7 (management) = 14 permissions."""
        assert len(DEFAULT_ROLES["ir_lead"]) == 14

    def test_includes_all_soc_analyst_permissions(self):
        """ir_lead MUST be a superset of soc_analyst."""
        soc_perms = DEFAULT_ROLES["soc_analyst"]
        ir_lead_perms = DEFAULT_ROLES["ir_lead"]
        assert soc_perms.issubset(ir_lead_perms), (
            f"Missing soc_analyst permissions in ir_lead: {soc_perms - ir_lead_perms}"
        )

    def test_contains_case_management_permissions(self):
        perms = DEFAULT_ROLES["ir_lead"]
        assert Permission.CASE_MANAGE in perms
        assert Permission.CASE_ASSIGN in perms

    def test_contains_playbook_edit(self):
        assert Permission.PLAYBOOK_EDIT in DEFAULT_ROLES["ir_lead"]

    def test_contains_settings_permissions(self):
        perms = DEFAULT_ROLES["ir_lead"]
        assert Permission.SETTINGS_VIEW in perms
        assert Permission.SETTINGS_EDIT in perms

    def test_contains_audit_view(self):
        assert Permission.AUDIT_VIEW in DEFAULT_ROLES["ir_lead"]

    def test_contains_user_manage(self):
        assert Permission.USER_MANAGE in DEFAULT_ROLES["ir_lead"]

    def test_does_not_contain_audit_export(self):
        """ir_lead can view audit logs but not export them."""
        assert Permission.AUDIT_EXPORT not in DEFAULT_ROLES["ir_lead"]

    def test_does_not_contain_report_executive(self):
        """Executive reporting is CISO-only."""
        assert Permission.REPORT_EXECUTIVE not in DEFAULT_ROLES["ir_lead"]


class TestCisoRole:
    """Test ciso role permission set."""

    def test_has_4_permissions(self):
        assert len(DEFAULT_ROLES["ciso"]) == 4

    def test_contains_investigation_view(self):
        """CISO can view investigations (read-only)."""
        assert Permission.INVESTIGATE_VIEW in DEFAULT_ROLES["ciso"]

    def test_contains_audit_permissions(self):
        perms = DEFAULT_ROLES["ciso"]
        assert Permission.AUDIT_VIEW in perms
        assert Permission.AUDIT_EXPORT in perms

    def test_contains_report_executive(self):
        assert Permission.REPORT_EXECUTIVE in DEFAULT_ROLES["ciso"]

    def test_is_read_only_role(self):
        """CISO cannot start investigations, manage cases, edit playbooks, or manage users."""
        perms = DEFAULT_ROLES["ciso"]
        write_permissions = {
            Permission.INVESTIGATE_START,
            Permission.FINDING_APPROVE,
            Permission.FINDING_REJECT,
            Permission.CASE_CREATE,
            Permission.CASE_MANAGE,
            Permission.CASE_ASSIGN,
            Permission.PLAYBOOK_EDIT,
            Permission.SETTINGS_EDIT,
            Permission.USER_MANAGE,
        }
        assert perms.isdisjoint(write_permissions), (
            f"CISO has write permissions: {perms & write_permissions}"
        )


# ─── Cross-Role Invariants ───────────────────────────────────────────────────


class TestCrossRoleInvariants:
    """Test relationships and invariants across roles."""

    def test_soc_analyst_is_strict_subset_of_ir_lead(self):
        """soc_analyst permissions are a proper subset of ir_lead."""
        soc = DEFAULT_ROLES["soc_analyst"]
        ir_lead = DEFAULT_ROLES["ir_lead"]
        assert soc < ir_lead  # strict subset

    def test_ciso_is_not_subset_of_soc_analyst(self):
        """CISO has unique permissions not shared with SOC analyst."""
        ciso = DEFAULT_ROLES["ciso"]
        soc = DEFAULT_ROLES["soc_analyst"]
        assert not ciso.issubset(soc)

    def test_all_16_permissions_covered_by_at_least_one_role(self):
        """Every defined permission appears in at least one default role."""
        all_assigned = set()
        for perms in DEFAULT_ROLES.values():
            all_assigned.update(perms)
        all_permissions = set(Permission)
        assert all_permissions == all_assigned, (
            f"Unassigned permissions: {all_permissions - all_assigned}"
        )

    def test_no_role_is_empty(self):
        """Every role must have at least one permission."""
        for role_name, perms in DEFAULT_ROLES.items():
            assert len(perms) > 0, f"Role '{role_name}' has no permissions"

    def test_permission_strings_match_migration_values(self):
        """Permission enum values must align with the migration's string literals."""
        # These are the permission strings from 002_seed_default_roles migration
        migration_soc_analyst = {
            "investigation:start",
            "investigation:view",
            "finding:approve",
            "finding:reject",
            "case:create",
            "playbook:view",
            "evidence:access",
        }
        rbac_soc_analyst = {p.value for p in DEFAULT_ROLES["soc_analyst"]}
        assert rbac_soc_analyst == migration_soc_analyst

        migration_ir_lead = {
            "investigation:start",
            "investigation:view",
            "finding:approve",
            "finding:reject",
            "case:create",
            "case:manage",
            "case:assign",
            "playbook:view",
            "playbook:edit",
            "settings:view",
            "settings:edit",
            "audit:view",
            "evidence:access",
            "user:manage",
        }
        rbac_ir_lead = {p.value for p in DEFAULT_ROLES["ir_lead"]}
        assert rbac_ir_lead == migration_ir_lead

        migration_ciso = {
            "investigation:view",
            "audit:view",
            "audit:export",
            "report:executive",
        }
        rbac_ciso = {p.value for p in DEFAULT_ROLES["ciso"]}
        assert rbac_ciso == migration_ciso
