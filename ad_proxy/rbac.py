"""
Granular Role-Based Access Control (RBAC) Engine.
Evaluates service account authorizations, command permissions, parameter constraints,
and protected group/OU boundaries.
"""

import logging
from typing import Any, Dict, Optional, Tuple
from .models import AllowedServiceAccount, PermittedRequestRule, ProxyConfig

logger = logging.getLogger("ad_proxy.rbac")

# Universal protected Active Directory groups that must never be altered or targeted by proxy callers
PROTECTED_PRIVILEGED_GROUPS = {
    "domain admins",
    "domain administrators",
    "enterprise admins",
    "enterprise administrators",
    "schema admins",
    "schema administrators",
    "administrators",
    "builtin\\administrators",
    "account operators",
    "backup operators",
    "server operators",
    "cert publishers",
    "group policy creator owners",
    "dnsadmins",
    "key admins",
    "enterprise key admins",
    "domain controllers",
    "read-only domain controllers",
    "enterprise read-only domain controllers",
    "krbtgt",
}

# Protected administrative accounts that cannot have passwords reset or status modified by proxy callers
PROTECTED_PRIVILEGED_ACCOUNTS = {
    "administrator",
    "admin",
    "domain administrator",
    "krbtgt",
    "root",
}

# Highly sensitive Active Directory commands
CRITICAL_PRIVILEGED_COMMANDS = {
    "reset_password",
    "add_user_to_group",
    "remove_user_from_group",
    "disable_account",
    "unlock_account",
    "create_user",
}


class RbacEngine:
    """Enforces least-privilege access control on all incoming LDAPS proxy requests."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self._accounts = config.allowed_service_accounts

    def normalize_account(self, identifier: str) -> str:
        """Normalizes account identifier (case-insensitive, strips whitespace/domain prefixes)."""
        if not identifier:
            return ""
        ident = identifier.strip().lower()
        # Handle DOMAIN\account or account@domain or CN=account,...
        if ident.startswith("cn="):
            ident = ident.split(",")[0].replace("cn=", "").strip()
        if "\\" in ident:
            ident = ident.split("\\")[-1]
        elif "@" in ident:
            ident = ident.split("@")[0]
        return ident

    def get_service_account(self, caller: str) -> Optional[AllowedServiceAccount]:
        """Looks up service account policy matching sAMAccountName, UPN, or exact DN."""
        normalized = self.normalize_account(caller)
        for key, acc in self._accounts.items():
            if self.normalize_account(key) == normalized or self.normalize_account(acc.account_identifier) == normalized:
                return acc
        return None

    def evaluate_permission(
        self,
        caller: str,
        command_name: str,
        parameters: Dict[str, Any],
        ticket_id: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]], bool, Optional[str]]:
        """
        Evaluates whether caller is authorized to execute command_name with parameters.
        Detects rogue or hallucinating agent attempts on sensitive targets.
        Returns: (is_allowed, reason, sanitized_parameters, is_high_severity_alert, alert_rule)
        """
        cmd_lower = command_name.lower().strip()
        target_group = parameters.get("group_name")
        target_user = parameters.get("user_identifier")
        norm_group = self.normalize_account(str(target_group)) if target_group else ""
        norm_user = self.normalize_account(str(target_user)) if target_user else ""

        # ----------------------------------------------------------------------
        # DETECT CRITICAL ATTACKS ON SENSITIVE TARGETS (ROGUE / HALLUCINATING AGENT)
        # ----------------------------------------------------------------------

        # Check A: Attempting to reset or modify an Administrator password
        if cmd_lower == "reset_password":
            if norm_user in PROTECTED_PRIVILEGED_ACCOUNTS or "admin" in norm_user:
                logger.error(
                    "SECURITY ALERT [ROGUE AGENT]: Account '%s' attempted to change administrator password for '%s'.",
                    caller, target_user
                )
                return False, f"Target user '{target_user}' is a protected Active Directory administrator. Password reset attempts are strictly forbidden.", None, True, "ROGUE_AGENT_ADMIN_PASSWORD_RESET_ATTEMPT"

        # Check B: Operations targeting Critical Groups (Domain Administrators, Enterprise Admins, etc.)
        if norm_group and norm_group in PROTECTED_PRIVILEGED_GROUPS:
            logger.error(
                "SECURITY ALERT [ROGUE AGENT]: Account '%s' attempted unsanctioned operation '%s' on critical Tier-0 group '%s'.",
                caller, command_name, target_group
            )
            return False, f"Target group '{target_group}' is a protected Tier-0 Active Directory group. Operations are strictly forbidden.", None, True, "ROGUE_AGENT_CRITICAL_GROUP_TARGET"

        # Check C: Tampering with protected administrator accounts (disable, unlock, attribute update)
        if norm_user and norm_user in PROTECTED_PRIVILEGED_ACCOUNTS:
            if cmd_lower in ("disable_account", "unlock_account", "update_user_attribute"):
                logger.error(
                    "SECURITY ALERT [ROGUE AGENT]: Account '%s' attempted tampering action '%s' on protected admin account '%s'.",
                    caller, command_name, target_user
                )
                return False, f"Target account '{target_user}' is a protected administrator account. Modifications are strictly forbidden.", None, True, "ROGUE_AGENT_ADMIN_ACCOUNT_TAMPERING"

        # ----------------------------------------------------------------------
        # SERVICE ACCOUNT ALLOWLIST VERIFICATION
        # ----------------------------------------------------------------------
        account_policy = self.get_service_account(caller)
        if not account_policy:
            is_sensitive_cmd = cmd_lower in CRITICAL_PRIVILEGED_COMMANDS
            logger.warning("Access Denied: Service account '%s' is not registered in allowlist.", caller)
            alert_rule = "ROGUE_AGENT_UNREGISTERED_PRIVILEGED_ACTION" if is_sensitive_cmd else None
            return False, f"Service account '{caller}' is not authorized to use the Active Directory proxy.", None, is_sensitive_cmd, alert_rule

        # ----------------------------------------------------------------------
        # EXPLICIT COMMAND BLACKLISTS
        # ----------------------------------------------------------------------
        denied_cmds = [c.lower() for c in account_policy.denied_commands]
        if cmd_lower in denied_cmds:
            is_critical = cmd_lower in CRITICAL_PRIVILEGED_COMMANDS
            logger.warning("Access Denied: Command '%s' explicitly blacklisted for account '%s'.", command_name, caller)
            alert_rule = "ROGUE_AGENT_BLACKLISTED_CRITICAL_ACTION" if is_critical else None
            return False, f"Command '{command_name}' is explicitly denied for service account '{caller}'.", None, is_critical, alert_rule

        # ----------------------------------------------------------------------
        # PERMITTED COMMANDS WHITELIST
        # ----------------------------------------------------------------------
        permitted_cmds = [c.lower() for c in account_policy.permitted_commands]
        wildcard_allowed = "*" in permitted_cmds

        if not wildcard_allowed and cmd_lower not in permitted_cmds:
            is_critical = cmd_lower in CRITICAL_PRIVILEGED_COMMANDS
            logger.warning("Access Denied: Command '%s' not in permitted list for '%s'.", command_name, caller)
            alert_rule = "ROGUE_AGENT_UNSANCTIONED_CRITICAL_ACTION" if is_critical else None
            return False, f"Command '{command_name}' is not permitted for service account '{caller}'. Allowed: {', '.join(account_policy.permitted_commands)}", None, is_critical, alert_rule

        # ----------------------------------------------------------------------
        # GRANULAR RULE CONSTRAINTS & PARAMETER BOUNDARIES
        # ----------------------------------------------------------------------
        matching_rule: Optional[PermittedRequestRule] = None
        for rule in account_policy.rules:
            if rule.command.lower() in (cmd_lower, "*"):
                matching_rule = rule
                break

        sanitized_params = dict(parameters)

        if matching_rule:
            # Check required ticket
            if matching_rule.require_approval_ticket and not ticket_id and not parameters.get("ticket_id"):
                return False, f"Command '{command_name}' requires an IT approval ticket ID.", None, False, None

            # Check allowed groups
            if matching_rule.allowed_groups and target_group:
                allowed_normalized = [self.normalize_account(g) for g in matching_rule.allowed_groups]
                if norm_group not in allowed_normalized:
                    return False, f"Group '{target_group}' is not within permitted groups list for '{caller}'.", None, False, None

            # Check restricted groups
            if matching_rule.restricted_groups and target_group:
                restricted_normalized = [self.normalize_account(g) for g in matching_rule.restricted_groups]
                if norm_group in restricted_normalized:
                    logger.warning("Access Denied: Group '%s' is restricted for caller '%s'.", target_group, caller)
                    return False, f"Group '{target_group}' is specifically restricted for '{caller}'.", None, True, "ROGUE_AGENT_RESTRICTED_GROUP_VIOLATION"

            # Check allowed OUs
            target_ou = parameters.get("ou_scope") or parameters.get("search_base") or parameters.get("parent_ou")
            if matching_rule.allowed_ous and target_ou:
                ou_matched = any(str(target_ou).lower().endswith(ou.lower()) for ou in matching_rule.allowed_ous)
                if not ou_matched:
                    return False, f"Target OU '{target_ou}' is outside allowed organizational unit scopes.", None, False, None

            # Check allowed attributes
            if matching_rule.allowed_attributes and "attributes" in parameters:
                requested_attrs = parameters["attributes"]
                if isinstance(requested_attrs, list):
                    filtered = [a for a in requested_attrs if a.lower() in [x.lower() for x in matching_rule.allowed_attributes]]
                    sanitized_params["attributes"] = filtered

            # Enforce max search results
            if "limit" in sanitized_params:
                sanitized_params["limit"] = min(int(sanitized_params["limit"]), matching_rule.max_search_results)
            else:
                sanitized_params["limit"] = matching_rule.max_search_results

        logger.info("Access Granted: Account '%s' authorized for command '%s'.", caller, command_name)
        return True, "Authorized", sanitized_params, False, None
