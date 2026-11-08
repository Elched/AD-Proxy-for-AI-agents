"""
Granular Role-Based Access Control (RBAC) Engine.
Evaluates service account authorizations, command permissions, parameter constraints,
and protected group/OU boundaries.
"""

import logging
from typing import Any, Dict, Optional, Tuple
from .models import AllowedServiceAccount, PermittedRequestRule, ProxyConfig

logger = logging.getLogger("ad_proxy.rbac")

# Universal protected Active Directory groups that must never be altered by proxy callers
PROTECTED_PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "cert publishers",
    "group policy creator owners",
    "krbtgt",
}


class RbacEngine:
    """Enforces least-privilege access control on all incoming LDAPS proxy requests."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self._accounts = config.allowed_service_accounts

    def normalize_account(self, identifier: str) -> str:
        """Normalizes account identifier (case-insensitive, strips whitespace/domain prefixes)."""
        ident = identifier.strip().lower()
        # Handle DOMAIN\account or account@domain
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
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Evaluates whether caller is authorized to execute command_name with parameters.
        Returns: (is_allowed, reason, sanitized_parameters)
        """
        account_policy = self.get_service_account(caller)
        if not account_policy:
            logger.warning("Access Denied: Service account '%s' is not registered in allowlist.", caller)
            return False, f"Service account '{caller}' is not authorized to use the Active Directory proxy.", None

        # 1. Check explicit blacklists
        denied_cmds = [c.lower() for c in account_policy.denied_commands]
        if command_name.lower() in denied_cmds:
            logger.warning("Access Denied: Command '%s' explicitly blacklisted for account '%s'.", command_name, caller)
            return False, f"Command '{command_name}' is explicitly denied for service account '{caller}'.", None

        # 2. Check permitted commands
        permitted_cmds = [c.lower() for c in account_policy.permitted_commands]
        wildcard_allowed = "*" in permitted_cmds

        if not wildcard_allowed and command_name.lower() not in permitted_cmds:
            logger.warning("Access Denied: Command '%s' not in permitted list for '%s'.", command_name, caller)
            return False, f"Command '{command_name}' is not permitted for service account '{caller}'. Allowed: {', '.join(account_policy.permitted_commands)}", None

        # 3. Find matching granular rule (if defined)
        matching_rule: Optional[PermittedRequestRule] = None
        for rule in account_policy.rules:
            if rule.command.lower() in (command_name.lower(), "*"):
                matching_rule = rule
                break

        sanitized_params = dict(parameters)

        # 4. Check Protected Active Directory Groups (Privilege Escalation Defense)
        target_group = parameters.get("group_name")
        if target_group:
            normalized_group = self.normalize_account(str(target_group))
            if normalized_group in PROTECTED_PRIVILEGED_GROUPS:
                logger.error("Security Violation: Attempted modification or target of protected group '%s' by '%s'.", target_group, caller)
                return False, f"Target group '{target_group}' is a protected Tier-0 Active Directory group. Operations are strictly forbidden.", None

        # 5. Check Granular Rule Constraints
        if matching_rule:
            # Check required ticket
            if matching_rule.require_approval_ticket and not ticket_id and not parameters.get("ticket_id"):
                return False, f"Command '{command_name}' requires an IT approval ticket ID.", None

            # Check allowed groups
            if matching_rule.allowed_groups and target_group:
                allowed_normalized = [self.normalize_account(g) for g in matching_rule.allowed_groups]
                if self.normalize_account(str(target_group)) not in allowed_normalized:
                    return False, f"Group '{target_group}' is not within permitted groups list for '{caller}'.", None

            # Check restricted groups
            if matching_rule.restricted_groups and target_group:
                restricted_normalized = [self.normalize_account(g) for g in matching_rule.restricted_groups]
                if self.normalize_account(str(target_group)) in restricted_normalized:
                    return False, f"Group '{target_group}' is specifically restricted for '{caller}'.", None

            # Check allowed OUs
            target_ou = parameters.get("ou_scope") or parameters.get("search_base") or parameters.get("parent_ou")
            if matching_rule.allowed_ous and target_ou:
                ou_matched = any(str(target_ou).lower().endswith(ou.lower()) for ou in matching_rule.allowed_ous)
                if not ou_matched:
                    return False, f"Target OU '{target_ou}' is outside allowed organizational unit scopes.", None

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
        return True, "Authorized", sanitized_params
