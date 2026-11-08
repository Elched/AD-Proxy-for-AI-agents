"""
Core AD-Proxy Orchestration Engine.
Coordinates the complete zero-trust verification pipeline:
  1. Input Validation & RFC 4515 Injection Check
  2. LDAPS Credential Verification against DC
  3. RBAC Policy & Boundary Evaluation
  4. Upstream LDAPS Command Execution
  5. Structured SIEM Auditing (CEF/ECS/Syslog)
"""

from datetime import datetime, timezone
import logging
import time
import traceback
from typing import Any, Dict
from .authenticator import AgentAuthenticator
from .commands import registry
from .ldap_client import ActiveDirectoryLdapClient
from .models import (
    AuditEvent,
    AuditOutcome,
    ProxyConfig,
    ProxyRequest,
    ProxyResponse,
)
from .rbac import RbacEngine
from .secret_manager import SecretManager
from .siem_logger import SiemAuditLogger

logger = logging.getLogger("ad_proxy.engine")


class AdProxyEngine:
    """Enterprise Active Directory LDAPS Proxy Engine."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.secrets = SecretManager(config.upstream_auth)
        self.ldap_client = ActiveDirectoryLdapClient(config.active_directory, self.secrets)
        self.authenticator = AgentAuthenticator(self.ldap_client)
        self.rbac = RbacEngine(config)
        self.siem = SiemAuditLogger(config.siem)
        self.registry = registry

    def process_request(self, request: ProxyRequest) -> ProxyResponse:
        """
        Executes the secure LDAPS proxy pipeline for an incoming AI Agent or service account request.
        """
        start_time = time.time()
        caller = request.caller_account
        cmd_name = request.command
        params = request.parameters
        client_ip = request.client_ip
        req_id = request.request_id

        # ----------------------------------------------------------------------
        # STAGE 1: Schema & Parameter Input Validation
        # ----------------------------------------------------------------------
        is_valid, val_err = self.registry.validate_request(cmd_name, params)
        if not is_valid:
            duration_ms = (time.time() - start_time) * 1000.0
            self._audit(
                event_id=req_id,
                caller=caller,
                client_ip=client_ip,
                command=cmd_name,
                target_dn=params.get("group_name") or params.get("user_identifier") or params.get("search_base"),
                filter_str=params.get("search_filter"),
                outcome=AuditOutcome.VALIDATION_ERROR,
                status_code="INVALID_INPUT",
                message=val_err or "Invalid input parameters.",
                duration_ms=duration_ms,
                parameters=params,
            )
            return ProxyResponse(
                success=False,
                status_code="INVALID_INPUT",
                message=val_err or "Parameter validation failed.",
                request_id=req_id,
                duration_ms=duration_ms,
            )

        # ----------------------------------------------------------------------
        # STAGE 2: AI Agent LDAPS Credential Bind against Domain Controller
        # ----------------------------------------------------------------------
        auth_success, auth_msg = self.authenticator.authenticate_agent(
            username=caller,
            password=request.caller_password,
        )
        if not auth_success:
            duration_ms = (time.time() - start_time) * 1000.0
            self._audit(
                event_id=req_id,
                caller=caller,
                client_ip=client_ip,
                command=cmd_name,
                target_dn=None,
                filter_str=None,
                outcome=AuditOutcome.AUTH_FAILED,
                status_code="AUTHENTICATION_FAILED",
                message=f"Agent credential bind to Active Directory failed: {auth_msg}",
                duration_ms=duration_ms,
                parameters={"caller": caller},
            )
            return ProxyResponse(
                success=False,
                status_code="AUTHENTICATION_FAILED",
                message=f"Access Denied: Invalid Active Directory credentials for '{caller}'. Connection terminated.",
                request_id=req_id,
                duration_ms=duration_ms,
            )

        # ----------------------------------------------------------------------
        # STAGE 3: RBAC Authorization & Policy Enforcement
        # ----------------------------------------------------------------------
        is_allowed, authz_msg, sanitized_params = self.rbac.evaluate_permission(
            caller=caller,
            command_name=cmd_name,
            parameters=params,
            ticket_id=request.ticket_id,
        )
        if not is_allowed:
            duration_ms = (time.time() - start_time) * 1000.0
            outcome = (
                AuditOutcome.RESTRICTED_TARGET
                if "protected" in authz_msg.lower() or "restricted" in authz_msg.lower()
                else (AuditOutcome.FORBIDDEN_CALLER if "not authorized" in authz_msg.lower() else AuditOutcome.FORBIDDEN_COMMAND)
            )
            self._audit(
                event_id=req_id,
                caller=caller,
                client_ip=client_ip,
                command=cmd_name,
                target_dn=params.get("group_name") or params.get("user_identifier") or params.get("search_base"),
                filter_str=params.get("search_filter"),
                outcome=outcome,
                status_code="FORBIDDEN",
                message=authz_msg,
                duration_ms=duration_ms,
                parameters=params,
            )
            return ProxyResponse(
                success=False,
                status_code="FORBIDDEN",
                message=f"Access Denied: {authz_msg}",
                request_id=req_id,
                duration_ms=duration_ms,
            )

        # ----------------------------------------------------------------------
        # STAGE 4: Execute Upstream LDAPS Query on Domain Controllers
        # ----------------------------------------------------------------------
        cmd_def = self.registry.get_command(cmd_name)
        if not cmd_def or not cmd_def.handler:
            duration_ms = (time.time() - start_time) * 1000.0
            return ProxyResponse(
                success=False,
                status_code="INTERNAL_ERROR",
                message=f"Command '{cmd_name}' handler not found.",
                request_id=req_id,
                duration_ms=duration_ms,
            )

        try:
            query_result = cmd_def.handler(
                client=self.ldap_client,
                base_dn=self.config.active_directory.base_dn,
                params=sanitized_params or params,
            )
            duration_ms = (time.time() - start_time) * 1000.0

            # ------------------------------------------------------------------
            # STAGE 5: SIEM Auditing & Response Return
            # ------------------------------------------------------------------
            self._audit(
                event_id=req_id,
                caller=caller,
                client_ip=client_ip,
                command=cmd_name,
                target_dn=params.get("group_name") or params.get("user_identifier") or params.get("search_base"),
                filter_str=params.get("search_filter"),
                outcome=AuditOutcome.SUCCESS,
                status_code="SUCCESS",
                message=f"Executed Active Directory LDAPS command '{cmd_name}' successfully.",
                duration_ms=duration_ms,
                parameters=sanitized_params or params,
                details={"result_count": len(query_result) if isinstance(query_result, list) else 1},
            )

            return ProxyResponse(
                success=True,
                status_code="SUCCESS",
                message="LDAPS request executed successfully.",
                data=query_result,
                request_id=req_id,
                duration_ms=duration_ms,
            )

        except Exception as ex:
            duration_ms = (time.time() - start_time) * 1000.0
            error_details = str(ex)
            logger.error("Error executing LDAPS query for '%s': %s", cmd_name, traceback.format_exc())
            self._audit(
                event_id=req_id,
                caller=caller,
                client_ip=client_ip,
                command=cmd_name,
                target_dn=params.get("group_name") or params.get("user_identifier"),
                filter_str=params.get("search_filter"),
                outcome=AuditOutcome.UPSTREAM_ERROR,
                status_code="UPSTREAM_ERROR",
                message=f"Domain Controller LDAPS query error: {error_details}",
                duration_ms=duration_ms,
                parameters=params,
            )
            return ProxyResponse(
                success=False,
                status_code="UPSTREAM_ERROR",
                message=f"Active Directory operation failed: {error_details}",
                request_id=req_id,
                duration_ms=duration_ms,
            )

    @staticmethod
    def scrub_sensitive_dict(data: Any) -> Any:
        """Recursively redacts passwords, tokens, and secrets from audit payloads."""
        if isinstance(data, dict):
            sensitive_keywords = {"password", "pwd", "secret", "token", "credential", "private_key", "auth"}
            scrubbed = {}
            for k, v in data.items():
                lowered = str(k).lower()
                if any(kw in lowered for kw in sensitive_keywords):
                    scrubbed[k] = "[REDACTED]"
                elif isinstance(v, (dict, list)):
                    scrubbed[k] = AdProxyEngine.scrub_sensitive_dict(v)
                else:
                    scrubbed[k] = v
            return scrubbed
        elif isinstance(data, list):
            return [AdProxyEngine.scrub_sensitive_dict(item) for item in data]
        return data

    def _audit(
        self,
        event_id: str,
        caller: str,
        client_ip: str,
        command: str,
        target_dn: Any,
        filter_str: Any,
        outcome: AuditOutcome,
        status_code: str,
        message: str,
        duration_ms: float,
        parameters: Dict[str, Any],
        details: Dict[str, Any] = None,
    ):
        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            caller_account=caller,
            client_ip=client_ip,
            command=command,
            target_dn=str(target_dn) if target_dn else None,
            filter_string=str(filter_str) if filter_str else None,
            outcome=outcome,
            status_code=status_code,
            message=message,
            duration_ms=duration_ms,
            parameters=self.scrub_sensitive_dict(parameters or {}),
            details=self.scrub_sensitive_dict(details or {}),
            domain=self.config.active_directory.domain_name,
        )
        self.siem.log(event)
