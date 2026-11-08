"""
Data models and type definitions for the Active Directory LDAPS Proxy.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import time
import uuid


class AuthMode(str, Enum):
    GMSA = "gmsa"
    SERVICE_ACCOUNT = "service_account"


class SecretProvider(str, Enum):
    ENV = "env"
    OPENBAO = "openbao"
    VAULT = "vault"
    DIRECT = "direct"


class SiemFormat(str, Enum):
    CEF = "cef"
    ECS = "ecs"
    SYSLOG = "syslog_rfc5424"


class AuditOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    AUTH_FAILED = "AUTH_FAILED"
    FORBIDDEN_CALLER = "FORBIDDEN_CALLER"
    FORBIDDEN_COMMAND = "FORBIDDEN_COMMAND"
    RESTRICTED_TARGET = "RESTRICTED_TARGET"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class CommandRiskLevel(str, Enum):
    LOW = "LOW"          # Read-only lookups (e.g., get_domain_info, get_user_attributes)
    MEDIUM = "MEDIUM"    # Broad directory searches, computer enumeration
    HIGH = "HIGH"        # Account enablement, group membership modifications
    CRITICAL = "CRITICAL"# Password reset, account creation, deletion


@dataclass
class DomainConfig:
    domain_name: str
    base_dn: str
    domain_controllers: List[str]
    ldaps_port: int = 636
    timeout_seconds: int = 10
    connect_retries: int = 3
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None


@dataclass
class TlsSettings:
    min_version: str = "TLSv1.2"
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    verify_client: bool = False
    cipher_suites: Optional[List[str]] = None


@dataclass
class OpenBaoConfig:
    address: str = "https://vault.corp.internal:8200"
    auth_method: str = "approle"  # approle | token
    role_id: Optional[str] = None
    secret_id: Optional[str] = None
    token: Optional[str] = None
    secret_path: str = "secret/data/ad-proxy"
    secret_key: str = "service_account_password"
    tls_ca_cert: Optional[str] = None
    cache_ttl_seconds: int = 300


@dataclass
class UpstreamAuthConfig:
    mode: AuthMode = AuthMode.SERVICE_ACCOUNT
    # If GMSA:
    gmsa_name: Optional[str] = None  # e.g., "svc-adproxy$"
    # If standard service account:
    username: Optional[str] = None
    secret_provider: SecretProvider = SecretProvider.ENV
    password: Optional[str] = None
    openbao: Optional[OpenBaoConfig] = None


@dataclass
class PermittedRequestRule:
    command: str
    allowed_groups: Optional[List[str]] = None       # Allowed group DNs/names for group ops
    restricted_groups: Optional[List[str]] = None    # Denied group DNs (e.g. Domain Admins)
    allowed_ous: Optional[List[str]] = None          # Allowed OU subtree scope
    allowed_attributes: Optional[List[str]] = None   # Whitelisted attributes for reads
    max_search_results: int = 200                    # Safety limit on search results
    require_approval_ticket: bool = False            # Whether an IT ticket ID is mandatory


@dataclass
class AllowedServiceAccount:
    account_identifier: str  # sAMAccountName, UPN, or DN
    description: str
    permitted_commands: List[str] = field(default_factory=list)
    rules: List[PermittedRequestRule] = field(default_factory=list)
    denied_commands: List[str] = field(default_factory=list)


@dataclass
class SiemConfig:
    enabled: bool = True
    format: SiemFormat = SiemFormat.ECS
    destinations: List[str] = field(default_factory=lambda: ["file", "stdout"])
    log_file_path: str = "/var/log/ad-proxy/audit.log"
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    syslog_protocol: str = "UDP"  # UDP | TCP | TLS
    webhook_url: Optional[str] = None
    webhook_token: Optional[str] = None
    log_all_queries: bool = True


@dataclass
class ProxyConfig:
    active_directory: DomainConfig
    ldaps: TlsSettings
    upstream_auth: UpstreamAuthConfig
    allowed_service_accounts: Dict[str, AllowedServiceAccount]
    siem: SiemConfig
    listen_host: str = "0.0.0.0"
    listen_port: int = 10636
    max_concurrent_connections: int = 100


@dataclass
class ProxyRequest:
    caller_account: str               # Service account initiating the request
    caller_password: str              # Credentials to validate against Active Directory
    command: str                      # Registered AD command name
    parameters: Dict[str, Any] = field(default_factory=dict)
    client_ip: str = "127.0.0.1"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ticket_id: Optional[str] = None   # Optional change/ticket reference for auditing


@dataclass
class ProxyResponse:
    success: bool
    status_code: str                  # e.g., "SUCCESS", "UNAUTHORIZED", "FORBIDDEN", "ERROR"
    message: str
    data: Optional[Any] = None
    request_id: str = ""
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    caller_account: str
    client_ip: str
    command: str
    target_dn: Optional[str]
    filter_string: Optional[str]
    outcome: AuditOutcome
    status_code: str
    message: str
    duration_ms: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    domain: str = ""
