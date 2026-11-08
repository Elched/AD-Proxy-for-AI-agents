"""
Functional Tests for High-Severity Rogue & Hallucinating Agent Detection.
Verifies detection of unsanctioned operations targeting critical groups (Domain Administrators)
and administrator password change attempts.
"""

import json
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ad_proxy.models import AuditOutcome, ProxyRequest, SiemFormat
from ad_proxy.proxy_engine import AdProxyEngine
from ad_proxy.yaml_loader import build_proxy_config, load_yaml_raw


class RogueAgentAlertFunctionalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ad_proxy", "config.yaml"))
        raw_dict = load_yaml_raw(config_path)
        cls.config = build_proxy_config(raw_dict)
        cls.engine = AdProxyEngine(cls.config)

    def test_01_admin_password_reset_attempt_triggers_high_severity_alert(self):
        """Verifies an agent attempting to reset Administrator password triggers high-severity alert."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="reset_password",
            parameters={
                "user_identifier": "administrator",
                "new_password": "HackedAdminPassword2026!",
            },
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "CRITICAL_SECURITY_ALERT")
        self.assertIn("protected Active Directory administrator", res.message)

        recent = self.engine.siem.get_recent_events(limit=1)[0]
        self.assertTrue(recent.get("is_high_severity_alert"))
        self.assertEqual(recent.get("severity"), 10)
        self.assertEqual(recent.get("outcome"), "SECURITY_ALERT_ROGUE_AGENT")
        self.assertEqual(recent.get("alert_rule"), "ROGUE_AGENT_ADMIN_PASSWORD_RESET_ATTEMPT")

    def test_02_domain_administrators_group_modification_triggers_high_severity_alert(self):
        """Verifies an agent attempting to add users to Domain Administrators triggers high-severity alert."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "alex.rivera",
                "group_name": "Domain Administrators",
                "ticket_id": "CHG-9999",
            },
            ticket_id="CHG-9999",
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "CRITICAL_SECURITY_ALERT")
        self.assertIn("Tier-0", res.message)

        recent = self.engine.siem.get_recent_events(limit=1)[0]
        self.assertTrue(recent.get("is_high_severity_alert"))
        self.assertEqual(recent.get("severity"), 10)
        self.assertEqual(recent.get("alert_rule"), "ROGUE_AGENT_CRITICAL_GROUP_TARGET")

    def test_03_enterprise_admins_tampering_triggers_high_severity_alert(self):
        """Verifies attempting to remove members or alter Enterprise Admins triggers high-severity alert."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="remove_user_from_group",
            parameters={
                "user_identifier": "some.admin",
                "group_name": "Enterprise Admins",
                "ticket_id": "CHG-8888",
            },
            ticket_id="CHG-8888",
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "CRITICAL_SECURITY_ALERT")

        recent = self.engine.siem.get_recent_events(limit=1)[0]
        self.assertTrue(recent.get("is_high_severity_alert"))
        self.assertEqual(recent.get("severity"), 10)

    def test_04_admin_account_disabling_tampering_triggers_high_severity_alert(self):
        """Verifies attempting to disable Administrator account triggers high-severity alert."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="disable_account",
            parameters={"user_identifier": "administrator", "ticket_id": "INC-001"},
            ticket_id="INC-001",
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "CRITICAL_SECURITY_ALERT")
        self.assertIn("protected administrator account", res.message)

        recent = self.engine.siem.get_recent_events(limit=1)[0]
        self.assertTrue(recent.get("is_high_severity_alert"))
        self.assertEqual(recent.get("alert_rule"), "ROGUE_AGENT_ADMIN_ACCOUNT_TAMPERING")

    def test_05_cef_format_reflects_maximum_severity_and_threat_extension(self):
        """Verifies CEF export string reflects severity 10 and threat metadata."""
        from ad_proxy.models import AuditEvent
        alert_event = AuditEvent(
            event_id="alert-evt-001",
            timestamp="2026-11-08T09:00:00Z",
            caller_account="ai-triage-agent",
            client_ip="10.0.0.99",
            command="reset_password",
            target_dn="administrator",
            filter_string=None,
            outcome=AuditOutcome.SECURITY_ALERT_ROGUE_AGENT,
            status_code="CRITICAL_SECURITY_ALERT",
            message="Target user administrator is a protected Active Directory administrator",
            duration_ms=0.45,
            domain="corp.acme.internal",
            severity=10,
            is_high_severity_alert=True,
            alert_rule="ROGUE_AGENT_ADMIN_PASSWORD_RESET_ATTEMPT",
        )
        cef = self.engine.siem._format_cef(alert_event)
        self.assertIn("|CRITICAL_SECURITY_ALERT|reset_password|10|", cef)
        self.assertIn("cat=Threat/RogueAgent", cef)
        self.assertIn("act=BLOCKED_CRITICAL_SECURITY_ALERT", cef)
        self.assertIn("cs5Label=AlertRule cs5=ROGUE_AGENT_ADMIN_PASSWORD_RESET_ATTEMPT", cef)

    def test_06_ecs_json_format_contains_threat_block(self):
        """Verifies ECS JSON contains threat.indicator and severity 10."""
        from ad_proxy.models import AuditEvent
        alert_event = AuditEvent(
            event_id="alert-evt-002",
            timestamp="2026-11-08T09:00:00Z",
            caller_account="svc-it-helpdesk-agent",
            client_ip="10.0.0.99",
            command="add_user_to_group",
            target_dn="Domain Administrators",
            filter_string=None,
            outcome=AuditOutcome.SECURITY_ALERT_ROGUE_AGENT,
            status_code="CRITICAL_SECURITY_ALERT",
            message="Target group Domain Administrators is protected",
            duration_ms=0.52,
            domain="corp.acme.internal",
            severity=10,
            is_high_severity_alert=True,
            alert_rule="ROGUE_AGENT_CRITICAL_GROUP_TARGET",
        )
        ecs_str = self.engine.siem._format_ecs(alert_event)
        ecs_data = json.loads(ecs_str)
        self.assertEqual(ecs_data["event"]["severity"], 10)
        self.assertIn("threat", ecs_data["event"]["category"])
        self.assertIn("threat", ecs_data)
        self.assertEqual(ecs_data["threat"]["indicator"], "ROGUE_OR_HALLUCINATING_AGENT_DETECTED")
        self.assertEqual(ecs_data["threat"]["rule"], "ROGUE_AGENT_CRITICAL_GROUP_TARGET")

    def test_07_regression_check_normal_allowed_requests_have_normal_severity(self):
        """Regression verification: normal sanctioned requests remain severity 3 with no threat alert."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="list_group_members",
            parameters={"group_name": "VPN-Users"},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        self.assertEqual(res.status_code, "SUCCESS")

        recent = self.engine.siem.get_recent_events(limit=1)[0]
        self.assertFalse(recent.get("is_high_severity_alert"))
        self.assertEqual(recent.get("severity"), 3)
        self.assertEqual(recent.get("outcome"), "SUCCESS")


def run_rogue_agent_tests() -> bool:
    suite = unittest.TestLoader().loadTestsFromTestCase(RogueAgentAlertFunctionalTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_rogue_agent_tests()
    sys.exit(0 if success else 1)
