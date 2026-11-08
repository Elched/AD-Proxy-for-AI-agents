"""
Active Directory LDAPS Command Catalog & Extensible Registry.
Encompasses standard Active Directory operations for service accounts with strict input validation,
LDAP injection prevention (RFC 4515), and parameter constraints.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Dict, List, Optional
from .models import CommandRiskLevel


def escape_ldap_filter(val: str) -> str:
    """
    Escapes special LDAP filter characters according to RFC 4515:
    * -> \\2a, ( -> \\28, ) -> \\29, \\ -> \\5c, NUL -> \\00
    """
    if not isinstance(val, str):
        val = str(val)
    escaped = (
        val.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )
    return escaped


def escape_ldap_dn(val: str) -> str:
    """
    Escapes characters in LDAP Distinguished Names according to RFC 4514:
    , + " \\ < > ; # = and leading/trailing spaces.
    """
    if not isinstance(val, str):
        val = str(val)
    # Basic safe escaping for DN components
    return re.sub(r'([,+="\\<>;#])', r"\\\1", val)


@dataclass
class CommandDefinition:
    name: str
    description: str
    category: str  # read | write | admin | system
    risk_level: CommandRiskLevel
    required_params: List[str]
    optional_params: List[str] = field(default_factory=list)
    handler: Optional[Callable] = None


class CommandRegistry:
    """Central registry of all permissible Active Directory LDAPS commands."""

    def __init__(self):
        self._commands: Dict[str, CommandDefinition] = {}

    def register(
        self,
        name: str,
        description: str,
        category: str,
        risk_level: CommandRiskLevel,
        required_params: List[str],
        optional_params: Optional[List[str]] = None,
    ):
        """Decorator or method to register an AD LDAPS command."""
        def decorator(func: Callable):
            cmd_def = CommandDefinition(
                name=name,
                description=description,
                category=category,
                risk_level=risk_level,
                required_params=required_params,
                optional_params=optional_params or [],
                handler=func,
            )
            self._commands[name] = cmd_def
            return func

        return decorator

    def get_command(self, name: str) -> Optional[CommandDefinition]:
        return self._commands.get(name)

    def list_commands(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered commands."""
        return [
            {
                "name": cmd.name,
                "description": cmd.description,
                "category": cmd.category,
                "risk_level": cmd.risk_level.value,
                "required_params": cmd.required_params,
                "optional_params": cmd.optional_params,
            }
            for cmd in self._commands.values()
        ]

    def remove_command(self, name: str) -> bool:
        """Removes a command from the registry."""
        if name in self._commands:
            del self._commands[name]
            return True
        return False

    def validate_request(self, name: str, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Ensures all required parameters exist and no dangerous injections are present."""
        cmd = self.get_command(name)
        if not cmd:
            return False, f"Unknown Active Directory command: '{name}'"

        for req in cmd.required_params:
            if req not in params or params[req] is None or params[req] == "":
                return False, f"Missing required parameter '{req}' for command '{name}'"

        # Check for dangerous characters in strings
        for k, v in params.items():
            if isinstance(v, str):
                if "\x00" in v:
                    return False, f"Null byte detected in parameter '{k}'"
                if len(v) > 10000:
                    return False, f"Parameter '{k}' exceeds maximum allowed length of 10,000 characters"
                # Reject unbalanced parentheses in filter inputs if custom search
                if k in ("filter_string", "search_filter") and (v.count("(") != v.count(")")):
                    return False, f"Mismatched parentheses in LDAP filter for '{k}'"

        return True, None


# Instantiate singleton command registry
registry = CommandRegistry()


# ==============================================================================
# STANDARD ACTIVE DIRECTORY COMMAND IMPLEMENTATIONS
# ==============================================================================

@registry.register(
    name="get_domain_info",
    description="Query RootDSE and domain partition information (functional level, forest name, DC hostname)",
    category="system",
    risk_level=CommandRiskLevel.LOW,
    required_params=[],
    optional_params=["attributes"],
)
def handle_get_domain_info(client, base_dn: str, params: Dict[str, Any]):
    return client.get_root_dse(attributes=params.get("attributes"))


@registry.register(
    name="search_users",
    description="Search user accounts in Active Directory with safe attribute filters",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=[],
    optional_params=["query", "department", "enabled_only", "ou_scope", "attributes", "limit"],
)
def handle_search_users(client, base_dn: str, params: Dict[str, Any]):
    query = params.get("query", "")
    dept = params.get("department")
    enabled_only = params.get("enabled_only", False)
    ou_scope = params.get("ou_scope") or base_dn
    limit = min(int(params.get("limit", 50)), 500)
    attributes = params.get("attributes") or [
        "sAMAccountName", "userPrincipalName", "displayName", "mail",
        "department", "title", "telephoneNumber", "userAccountControl", "whenCreated"
    ]

    filter_parts = ["(&(objectCategory=person)(objectClass=user)"]
    if query:
        escaped = escape_ldap_filter(query)
        filter_parts.append(f"(|(sAMAccountName=*{escaped}*)(displayName=*{escaped}*)(mail=*{escaped}*))")
    if dept:
        filter_parts.append(f"(department={escape_ldap_filter(dept)})")
    if enabled_only:
        filter_parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
    filter_parts.append(")")
    ldap_filter = "".join(filter_parts)

    return client.search(
        search_base=ou_scope,
        search_filter=ldap_filter,
        attributes=attributes,
        size_limit=limit,
    )


@registry.register(
    name="get_user_attributes",
    description="Retrieve all or specific LDAP attributes for an identified user",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=["user_identifier"],
    optional_params=["attributes"],
)
def handle_get_user_attributes(client, base_dn: str, params: Dict[str, Any]):
    ident = escape_ldap_filter(params["user_identifier"])
    attributes = params.get("attributes") or [
        "sAMAccountName", "userPrincipalName", "displayName", "mail",
        "title", "department", "company", "manager", "memberOf",
        "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "lockoutTime"
    ]
    ldap_filter = f"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={ident})(userPrincipalName={ident})(distinguishedName={ident})))"
    return client.search(search_base=base_dn, search_filter=ldap_filter, attributes=attributes, size_limit=1)


@registry.register(
    name="list_group_members",
    description="List all members of a security or distribution group with optional recursive resolution",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=["group_name"],
    optional_params=["recursive", "attributes"],
)
def handle_list_group_members(client, base_dn: str, params: Dict[str, Any]):
    group_name = params["group_name"]
    recursive = bool(params.get("recursive", False))
    attributes = params.get("attributes") or ["sAMAccountName", "displayName", "mail", "distinguishedName"]
    return client.get_group_members(group_name=group_name, recursive=recursive, attributes=attributes, base_dn=base_dn)


@registry.register(
    name="check_user_membership",
    description="Check whether a user is an active or nested member of a specific Active Directory group",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=["user_identifier", "group_name"],
    optional_params=["check_nested"],
)
def handle_check_user_membership(client, base_dn: str, params: Dict[str, Any]):
    user = params["user_identifier"]
    group = params["group_name"]
    check_nested = bool(params.get("check_nested", True))
    return client.check_membership(user=user, group=group, check_nested=check_nested, base_dn=base_dn)


@registry.register(
    name="search_groups",
    description="Search security and distribution groups by name or purpose",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=[],
    optional_params=["query", "group_type", "limit"],
)
def handle_search_groups(client, base_dn: str, params: Dict[str, Any]):
    query = params.get("query", "")
    limit = min(int(params.get("limit", 50)), 200)
    filter_parts = ["(&(objectCategory=group)"]
    if query:
        escaped = escape_ldap_filter(query)
        filter_parts.append(f"(|(cn=*{escaped}*)(sAMAccountName=*{escaped}*)(description=*{escaped}*))")
    filter_parts.append(")")
    ldap_filter = "".join(filter_parts)
    return client.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        attributes=["cn", "sAMAccountName", "description", "groupType", "managedBy", "member"],
        size_limit=limit,
    )


@registry.register(
    name="get_group_details",
    description="Get metadata, owner, and membership count for a group",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=["group_name"],
    optional_params=[],
)
def handle_get_group_details(client, base_dn: str, params: Dict[str, Any]):
    grp = escape_ldap_filter(params["group_name"])
    ldap_filter = f"(&(objectCategory=group)(|(cn={grp})(sAMAccountName={grp})))"
    return client.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        attributes=["cn", "sAMAccountName", "description", "groupType", "managedBy", "mail", "distinguishedName"],
        size_limit=1,
    )


@registry.register(
    name="search_computers",
    description="Search domain-joined computer accounts, OS version, and DNS hostnames",
    category="read",
    risk_level=CommandRiskLevel.MEDIUM,
    required_params=[],
    optional_params=["query", "operating_system", "limit"],
)
def handle_search_computers(client, base_dn: str, params: Dict[str, Any]):
    query = params.get("query", "")
    os_filter = params.get("operating_system")
    limit = min(int(params.get("limit", 50)), 200)
    filter_parts = ["(&(objectCategory=computer)"]
    if query:
        escaped = escape_ldap_filter(query)
        filter_parts.append(f"(|(cn=*{escaped}*)(dNSHostName=*{escaped}*))")
    if os_filter:
        filter_parts.append(f"(operatingSystem=*{escape_ldap_filter(os_filter)}*)")
    filter_parts.append(")")
    ldap_filter = "".join(filter_parts)
    return client.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        attributes=["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp"],
        size_limit=limit,
    )


@registry.register(
    name="get_organizational_units",
    description="Enumerate Organizational Units (OUs) to navigate Active Directory hierarchy",
    category="read",
    risk_level=CommandRiskLevel.LOW,
    required_params=[],
    optional_params=["parent_ou"],
)
def handle_get_organizational_units(client, base_dn: str, params: Dict[str, Any]):
    search_base = params.get("parent_ou") or base_dn
    return client.search(
        search_base=search_base,
        search_filter="(objectCategory=organizationalUnit)",
        attributes=["ou", "name", "description", "distinguishedName"],
        size_limit=100,
    )


@registry.register(
    name="add_user_to_group",
    description="Add a user account to a designated security group",
    category="write",
    risk_level=CommandRiskLevel.HIGH,
    required_params=["user_identifier", "group_name"],
    optional_params=["justification", "ticket_id"],
)
def handle_add_user_to_group(client, base_dn: str, params: Dict[str, Any]):
    return client.modify_group_member(
        action="add",
        user_ident=params["user_identifier"],
        group_name=params["group_name"],
        base_dn=base_dn,
    )


@registry.register(
    name="remove_user_from_group",
    description="Remove a user account from a security group",
    category="write",
    risk_level=CommandRiskLevel.HIGH,
    required_params=["user_identifier", "group_name"],
    optional_params=["justification", "ticket_id"],
)
def handle_remove_user_from_group(client, base_dn: str, params: Dict[str, Any]):
    return client.modify_group_member(
        action="remove",
        user_ident=params["user_identifier"],
        group_name=params["group_name"],
        base_dn=base_dn,
    )


@registry.register(
    name="enable_account",
    description="Enable a disabled Active Directory user account",
    category="write",
    risk_level=CommandRiskLevel.HIGH,
    required_params=["user_identifier"],
    optional_params=["ticket_id"],
)
def handle_enable_account(client, base_dn: str, params: Dict[str, Any]):
    return client.set_account_state(user_ident=params["user_identifier"], enabled=True, base_dn=base_dn)


@registry.register(
    name="disable_account",
    description="Disable an Active Directory user account (incident response or deprovisioning)",
    category="write",
    risk_level=CommandRiskLevel.HIGH,
    required_params=["user_identifier"],
    optional_params=["ticket_id", "reason"],
)
def handle_disable_account(client, base_dn: str, params: Dict[str, Any]):
    return client.set_account_state(user_ident=params["user_identifier"], enabled=False, base_dn=base_dn)


@registry.register(
    name="unlock_account",
    description="Clear account lockout flag for a user locked out by failed password attempts",
    category="write",
    risk_level=CommandRiskLevel.HIGH,
    required_params=["user_identifier"],
    optional_params=["ticket_id"],
)
def handle_unlock_account(client, base_dn: str, params: Dict[str, Any]):
    return client.unlock_user_account(user_ident=params["user_identifier"], base_dn=base_dn)


@registry.register(
    name="reset_password",
    description="Perform secure password reset over LDAPS for non-privileged user",
    category="admin",
    risk_level=CommandRiskLevel.CRITICAL,
    required_params=["user_identifier", "new_password"],
    optional_params=["force_change_next_logon", "ticket_id"],
)
def handle_reset_password(client, base_dn: str, params: Dict[str, Any]):
    return client.reset_user_password(
        user_ident=params["user_identifier"],
        new_password=params["new_password"],
        force_change=bool(params.get("force_change_next_logon", True)),
        base_dn=base_dn,
    )


@registry.register(
    name="update_user_attribute",
    description="Update non-critical user profile attribute (e.g. telephone, department, title)",
    category="write",
    risk_level=CommandRiskLevel.MEDIUM,
    required_params=["user_identifier", "attribute_name", "attribute_value"],
    optional_params=["ticket_id"],
)
def handle_update_user_attribute(client, base_dn: str, params: Dict[str, Any]):
    safe_attrs = {"telephonenumber", "department", "title", "company", "physicaldeliveryofficename", "streetaddress"}
    attr = params["attribute_name"].lower()
    if attr not in safe_attrs:
        raise ValueError(f"Attribute '{params['attribute_name']}' is restricted or not modifiable via proxy.")
    return client.update_attribute(
        user_ident=params["user_identifier"],
        attribute=attr,
        value=params["attribute_value"],
        base_dn=base_dn,
    )


@registry.register(
    name="custom_search_filter",
    description="Execute an advanced LDAP search filter with safety validation and strict scope limits",
    category="read",
    risk_level=CommandRiskLevel.MEDIUM,
    required_params=["search_filter"],
    optional_params=["search_base", "attributes", "limit"],
)
def handle_custom_search_filter(client, base_dn: str, params: Dict[str, Any]):
    raw_filter = params["search_filter"]
    # Check for disallowed filters that could attempt denial of service or credential dumping
    lowered = raw_filter.lower()
    blocked_keywords = ["unicodepwd", "userpassword", "samaccounthash", "supplementalcredentials", "ms-mcs-admpwd"]
    for keyword in blocked_keywords:
        if keyword in lowered:
            raise PermissionError(f"Filter references forbidden sensitive attribute: '{keyword}'")

    search_base = params.get("search_base") or base_dn
    limit = min(int(params.get("limit", 100)), 200)
    attributes = params.get("attributes") or ["sAMAccountName", "displayName", "mail", "objectClass", "distinguishedName"]

    return client.search(
        search_base=search_base,
        search_filter=raw_filter,
        attributes=attributes,
        size_limit=limit,
    )
