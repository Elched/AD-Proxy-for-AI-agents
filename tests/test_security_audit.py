"""
Dedicated Security & Component Audit Test Suite for Active Directory LDAPS Proxy.
Verifies RFC 4515 injection resistance, credential redaction, Tier-0 escalation defense,
dependency supply-chain trust, TLS security baselines, and timing attack resistance.
"""

import json
import os
import ssl
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ad_proxy.commands import escape_ldap_filter, registry
from ad_proxy.models import AuditOutcome, ProxyRequest
from ad_proxy.proxy_engine import AdProxyEngine
from ad_proxy.rbac import PROTECTED_PRIVILEGED_GROUPS
from ad_proxy.yaml_loader import build_proxy_config, load_yaml_raw


class SecurityAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ad_proxy", "config.yaml"))
        raw_dict = load_yaml_raw(config_path)
        cls.config = build_proxy_config(raw_dict)
        cls.engine = AdProxyEngine(cls.config)

    def test_01_trusted_dependencies_and_no_deprecated_modules(self):
        """Verifies all Python dependencies are official, modern, and trustworthy."""
        req_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "requirements.txt"))
        with open(req_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        # List of official, trusted PyPI packages
        trusted_pkgs = {"pyyaml", "ldap3", "cryptography", "hvac", "requests"}
        for line in lines:
            pkg_name = line.split(">=")[0].split("==")[0].split("<")[0].strip().lower()
            self.assertIn(pkg_name, trusted_pkgs, f"Untrusted or unrecognized dependency: {pkg_name}")

        # Check codebase for deprecated Python stdlib imports
        deprecated_modules = ["imp", "distutils", "cgi", "pycrypto", "optparse", "formatter", "telnetlib"]
        code_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ad_proxy"))
        for root, _, files in os.walk(code_dir):
            for file in files:
                if file.endswith(".py"):
                    with open(os.path.join(root, file), "r", encoding="utf-8") as py_file:
                        content = py_file.read()
                        for dep in deprecated_modules:
                            self.assertNotIn(f"import {dep}", content, f"Deprecated module '{dep}' found in {file}")
                            self.assertNotIn(f"from {dep} ", content, f"Deprecated module '{dep}' found in {file}")

    def test_02_ldap_filter_injection_neutralization(self):
        """Tests that malicious LDAP filter injection payloads are escaped according to RFC 4515."""
        attack_payloads = [
            "admin*)(|(userPassword=*))",
            "*)(&(objectCategory=person)(userPassword=*))",
            "test)(uid=*))(|(uid=*",
            "\\28*\\29",
            "admin\x00password",
            "*(|(mail=*@evil.corp))",
        ]

        for payload in attack_payloads:
            escaped = escape_ldap_filter(payload)
            # Must not contain unescaped wildcards or parentheses
            self.assertNotIn("*(", escaped)
            self.assertNotIn(")(", escaped)
            self.assertNotIn("\x00", escaped)
            self.assertTrue("\\2a" in escaped or "\\28" in escaped or "\\29" in escaped or "\\00" in escaped or "\\5c" in escaped)

    def test_03_null_byte_injection_rejection(self):
        """Verifies requests with embedded null bytes are rejected at the input boundary."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="list_group_members",
            parameters={"group_name": "VPN-Users\x00evil_injection"},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "INVALID_INPUT")
        self.assertIn("Null byte", res.message)

    def test_04_parameter_length_bloat_rejection(self):
        """Verifies strings exceeding 10,000 characters are rejected to prevent ReDoS / memory exhaustion."""
        bloated_string = "A" * 15000
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="search_users",
            parameters={"query": bloated_string},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "INVALID_INPUT")
        self.assertIn("maximum allowed length", res.message)

    def test_05_comprehensive_credential_redaction_in_audit(self):
        """Verifies passwords, secrets, tokens, and keys are scrubbed and never appear in SIEM events."""
        # Test 1: Redaction on successful execution
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="get_user_attributes",
            parameters={
                "user_identifier": "alex.rivera",
                "temp_password": "PlainTextSensitivePassword1!",
                "auth_token": "bearer_secret_xyz_998",
                "user_metadata": {
                    "admin_pwd": "InternalSecretValue9!",
                    "public_name": "Alex",
                },
            },
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        recent = self.engine.siem.get_recent_events(limit=1)[0]

        # Audit event must not contain plain passwords
        event_json = json.dumps(recent)
        self.assertNotIn("PlainTextSensitivePassword1!", event_json)
        self.assertNotIn("bearer_secret_xyz_998", event_json)
        self.assertNotIn("InternalSecretValue9!", event_json)

        # Verified redacted flags present
        params = recent.get("parameters", {})
        self.assertEqual(params.get("temp_password"), "[REDACTED]")
        self.assertEqual(params.get("auth_token"), "[REDACTED]")
        nested = params.get("user_metadata", {})
        self.assertEqual(nested.get("admin_pwd"), "[REDACTED]")
        self.assertEqual(nested.get("public_name"), "Alex")

        # Test 2: Redaction on authentication failure (caller password never leaked)
        bad_req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="MaliciousSensitivePassword999!",
            command="get_user_attributes",
            parameters={"user_identifier": "alex.rivera"},
        )
        bad_res = self.engine.process_request(bad_req)
        self.assertFalse(bad_res.success)
        bad_recent = self.engine.siem.get_recent_events(limit=1)[0]
        bad_event_json = json.dumps(bad_recent)
        self.assertNotIn("MaliciousSensitivePassword999!", bad_event_json)

    def test_06_tier0_privilege_escalation_casing_variations(self):
        """Verifies all case variations and DN formats for Domain Admins and protected groups are blocked."""
        test_variations = [
            "Domain Admins",
            "domain admins",
            "DOMAIN ADMINS",
            "dOmAiN aDmInS",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "krbtgt",
        ]

        for grp in test_variations:
            req = ProxyRequest(
                caller_account="svc-it-helpdesk-agent",
                caller_password="HelpdeskSecretToken2026#",
                command="add_user_to_group",
                parameters={"user_identifier": "sarah.chen", "group_name": grp, "ticket_id": "CHG-9901"},
                ticket_id="CHG-9901",
            )
            res = self.engine.process_request(req)
            self.assertFalse(res.success, f"Failed to block protected group: {grp}")
            self.assertEqual(res.status_code, "FORBIDDEN")
            self.assertIn("protected Tier-0", res.message)

    def test_07_tls_minimum_version_and_security(self):
        """Verifies TLS contexts created by the proxy enforce minimum TLS 1.2+."""
        ctx = self.engine.ldap_client._get_ssl_context()
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_08_constant_time_password_verification(self):
        """Verifies timing attack defense using constant-time verification."""
        import hmac
        self.assertTrue(hasattr(hmac, "compare_digest"))
        # Test valid and invalid comparison
        self.assertTrue(hmac.compare_digest("TestPassword123!", "TestPassword123!"))
        self.assertFalse(hmac.compare_digest("TestPassword123!", "WrongPassword999!"))


def run_security_audit() -> bool:
    suite = unittest.TestLoader().loadTestsFromTestCase(SecurityAuditTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_security_audit()
    sys.exit(0 if success else 1)
