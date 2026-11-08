"""
Comprehensive Security and Functional Test Suite for the Active Directory LDAPS Proxy.
Tests authentication, RBAC authorization, parameter sanitization, privilege escalation defense,
SIEM export formats, and extensible command registry.
"""

import json
import os
import sys
import unittest

# Ensure root path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ad_proxy.commands import escape_ldap_filter, registry
from ad_proxy.models import (
    AuditOutcome,
    AuthMode,
    CommandRiskLevel,
    ProxyRequest,
    SecretProvider,
    SiemFormat,
)
from ad_proxy.proxy_engine import AdProxyEngine
from ad_proxy.yaml_loader import build_proxy_config, load_yaml_raw


class TestActiveDirectoryProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load test configuration
        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ad_proxy", "config.yaml"))
        raw_dict = load_yaml_raw(config_path)
        cls.config = build_proxy_config(raw_dict)
        cls.engine = AdProxyEngine(cls.config)

    def test_01_config_loading(self):
        """Validates that YAML configuration loads cleanly into typed dataclasses."""
        self.assertEqual(self.config.active_directory.domain_name, "corp.acme.internal")
        self.assertEqual(self.config.active_directory.base_dn, "DC=corp,DC=acme,DC=internal")
        self.assertIn("ai-triage-agent", self.config.allowed_service_accounts)
        self.assertIn("svc-it-helpdesk-agent", self.config.allowed_service_accounts)

    def test_02_ldap_filter_escaping(self):
        """Verifies RFC 4515 LDAP injection filter sanitization."""
        malicious = "admin*)(|(userPassword=*))"
        escaped = escape_ldap_filter(malicious)
        self.assertNotIn("*(", escaped)
        self.assertIn("\\2a", escaped)
        self.assertIn("\\28", escaped)
        self.assertIn("\\29", escaped)

    def test_03_authentication_success(self):
        """Verifies valid agent credentials successfully bind against Active Directory."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="get_domain_info",
            parameters={},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success, f"Expected success but got: {res.message}")
        self.assertEqual(res.status_code, "SUCCESS")
        self.assertIsNotNone(res.data)
        self.assertIn("defaultNamingContext", res.data)

    def test_04_authentication_failure(self):
        """Verifies invalid password triggers authentication failure and terminates connection."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="WrongPassword123!",
            command="get_domain_info",
            parameters={},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "AUTHENTICATION_FAILED")
        self.assertIn("Invalid Active Directory credentials", res.message)

    def test_05_unauthorized_account_blocked(self):
        """Verifies account not present in allowlist is blocked with FORBIDDEN."""
        req = ProxyRequest(
            caller_account="unauthorized-agent",
            caller_password="WrongPassword999!", # non-registered account
            command="get_domain_info",
            parameters={},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        # Auth will fail or caller check will fail
        self.assertIn(res.status_code, ("AUTHENTICATION_FAILED", "FORBIDDEN"))

    def test_06_rbac_blacklisted_command_blocked(self):
        """Verifies explicitly denied command in account policy is blocked immediately."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="reset_password",  # Explicitly in ai-triage-agent's denied_commands
            parameters={"user_identifier": "alex.rivera", "new_password": "NewSecretPassword2026!"},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "FORBIDDEN")
        self.assertIn("explicitly denied", res.message)

    def test_07_protected_group_escalation_defense(self):
        """Verifies attempting to target 'Domain Admins' or privileged groups is blocked."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "alex.rivera",
                "group_name": "Domain Admins",  # Protected Tier-0 group
                "ticket_id": "CHG-9901",
            },
            ticket_id="CHG-9901",
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "FORBIDDEN")
        self.assertIn("protected Tier-0", res.message)

    def test_08_rbac_missing_approval_ticket_blocked(self):
        """Verifies actions requiring an IT approval ticket fail if ticket_id is missing."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "alex.rivera",
                "group_name": "VPN-Users",
                # Omit ticket_id
            },
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "FORBIDDEN")
        self.assertIn("requires an IT approval ticket ID", res.message)

    def test_09_rbac_allowed_group_with_ticket_succeeds(self):
        """Verifies permitted write action with valid ticket succeeds."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "sarah.chen",
                "group_name": "VPN-Users",
                "ticket_id": "INC-88129",
            },
            ticket_id="INC-88129",
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success, f"Expected success: {res.message}")
        self.assertEqual(res.status_code, "SUCCESS")

    def test_10_read_group_members(self):
        """Verifies reading group members returns sanitized list of users."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="list_group_members",
            parameters={"group_name": "VPN-Users"},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        self.assertIsInstance(res.data, list)
        self.assertTrue(len(res.data) >= 1)
        # Ensure password hash is not exposed
        first_user = res.data[0]
        self.assertNotIn("password", first_user)
        self.assertNotIn("unicodepwd", first_user)

    def test_11_siem_event_emission(self):
        """Verifies SIEM auditing records events in both ECS JSON and CEF formats."""
        recent = self.engine.siem.get_recent_events(limit=5)
        self.assertTrue(len(recent) > 0)
        latest = recent[0]
        self.assertIn("caller_account", latest)
        self.assertIn("outcome", latest)
        self.assertIn("duration_ms", latest)

        # Test CEF format generator
        from ad_proxy.models import AuditEvent, AuditOutcome
        sample_event = AuditEvent(
            event_id="test-evt-1",
            timestamp="2026-11-08T08:30:00Z",
            caller_account="ai-triage-agent",
            client_ip="10.0.4.15",
            command="list_group_members",
            target_dn="CN=VPN-Users,OU=Groups,DC=corp,DC=acme,DC=internal",
            filter_string="(&(objectCategory=group)(cn=VPN-Users))",
            outcome=AuditOutcome.SUCCESS,
            status_code="SUCCESS",
            message="Executed successfully",
            duration_ms=12.4,
            domain="corp.acme.internal",
        )
        cef_str = self.engine.siem._format_cef(sample_event)
        self.assertTrue(cef_str.startswith("CEF:0|EnterpriseSecurity|ActiveDirectoryProxy|1.0|SUCCESS|list_group_members|3|"))
        self.assertIn("suser=ai-triage-agent", cef_str)

        # Test ECS format generator
        ecs_str = self.engine.siem._format_ecs(sample_event)
        ecs_data = json.loads(ecs_str)
        self.assertEqual(ecs_data["user"]["name"], "ai-triage-agent")
        self.assertEqual(ecs_data["active_directory"]["command"], "list_group_members")
        self.assertEqual(ecs_data["event"]["outcome"], "success")

    def test_12_extensible_command_registry(self):
        """Verifies that new custom AD commands can be registered and executed seamlessly."""
        # Register custom command
        @registry.register(
            name="custom_ping_ou",
            description="Test custom registered AD command",
            category="system",
            risk_level=CommandRiskLevel.LOW,
            required_params=["ou_name"],
        )
        def handle_custom_ping(client, base_dn, params):
            return {"ou_name": params["ou_name"], "status": "active_replica"}

        # Temporarily permit for ai-triage-agent
        acc = self.engine.rbac.get_service_account("ai-triage-agent")
        acc.permitted_commands.append("custom_ping_ou")

        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="custom_ping_ou",
            parameters={"ou_name": "OU=Users"},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        self.assertEqual(res.data["ou_name"], "OU=Users")

        # Cleanup
        acc.permitted_commands.remove("custom_ping_ou")
        registry.remove_command("custom_ping_ou")


def run_all_tests() -> bool:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestActiveDirectoryProxy)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
