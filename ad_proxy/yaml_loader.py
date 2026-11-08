"""
YAML configuration loader with environment variable substitution and schema validation.
Supports both PyYAML (if installed) and a built-in pure-Python YAML reader.
"""

import os
import re
from typing import Any, Dict, List, Optional
from .models import (
    AuthMode,
    AllowedServiceAccount,
    DomainConfig,
    OpenBaoConfig,
    PermittedRequestRule,
    ProxyConfig,
    SecretProvider,
    SiemConfig,
    SiemFormat,
    TlsSettings,
    UpstreamAuthConfig,
)


def interpolate_env_vars(val: Any) -> Any:
    """Recursively replaces ${VAR} or ${VAR:-default} with environment variables."""
    if isinstance(val, str):
        pattern = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")

        def repl(match: re.Match) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return pattern.sub(repl, val)
    elif isinstance(val, dict):
        return {k: interpolate_env_vars(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [interpolate_env_vars(item) for item in val]
    return val


def parse_primitive(val_str: str) -> Any:
    """Parses a YAML scalar value to python bool, int, float, or unquoted string."""
    val_str = val_str.strip()
    if not val_str:
        return ""
    if val_str.startswith('"') and val_str.endswith('"') and len(val_str) >= 2:
        return val_str[1:-1]
    if val_str.startswith("'") and val_str.endswith("'") and len(val_str) >= 2:
        return val_str[1:-1]
    if val_str.lower() in ("true", "yes", "on"):
        return True
    if val_str.lower() in ("false", "no", "off"):
        return False
    if val_str.lower() in ("null", "none", "~"):
        return None
    try:
        if "." in val_str:
            return float(val_str)
        return int(val_str)
    except ValueError:
        return val_str


class PurePythonYamlParser:
    """A clean, robust line-by-line YAML parser for nested dictionaries and lists."""

    @classmethod
    def load(cls, text: str) -> Dict[str, Any]:
        lines = text.splitlines()
        clean_lines: List[tuple[int, str]] = []
        for raw_line in lines:
            line = raw_line.rstrip()
            if not line:
                continue
            # Strip comments that are not inside quotes
            comment_idx = line.find("#")
            if comment_idx != -1:
                # Basic check if '#' is inside a quoted string
                prefix = line[:comment_idx]
                if prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
                    line = prefix.rstrip()
            if not line:
                continue
            indent = len(line) - len(line.lstrip(" "))
            clean_lines.append((indent, line.strip()))

        if not clean_lines:
            return {}

        idx = 0

        def parse_block(expected_indent: int) -> Any:
            nonlocal idx
            if idx >= len(clean_lines):
                return {}

            first_indent, first_content = clean_lines[idx]
            is_list = first_content.startswith("- ") or first_content == "-"

            if is_list:
                result_list: List[Any] = []
                while idx < len(clean_lines):
                    cur_indent, cur_content = clean_lines[idx]
                    if cur_indent < expected_indent:
                        break
                    if not (cur_content.startswith("- ") or cur_content == "-"):
                        break

                    item_str = cur_content[2:].strip() if cur_content.startswith("- ") else ""
                    idx += 1

                    if not item_str:
                        # nested list item or dictionary below
                        if idx < len(clean_lines) and clean_lines[idx][0] > cur_indent:
                            result_list.append(parse_block(clean_lines[idx][0]))
                        else:
                            result_list.append(None)
                    elif ":" in item_str and not (item_str.startswith('"') or item_str.startswith("'")):
                        # inline key-value starting a map inside a list item
                        k, v = item_str.split(":", 1)
                        k = k.strip()
                        v = v.strip()
                        item_map: Dict[str, Any] = {}
                        if v:
                            item_map[k] = parse_primitive(v)
                        else:
                            if idx < len(clean_lines) and clean_lines[idx][0] > cur_indent:
                                item_map[k] = parse_block(clean_lines[idx][0])
                            else:
                                item_map[k] = {}

                        # check for subsequent keys with indent > cur_indent
                        while idx < len(clean_lines):
                            next_indent, next_content = clean_lines[idx]
                            if next_indent <= cur_indent or next_content.startswith("-"):
                                break
                            if ":" in next_content:
                                nk, nv = next_content.split(":", 1)
                                nk = nk.strip()
                                nv = nv.strip()
                                idx += 1
                                if nv:
                                    item_map[nk] = parse_primitive(nv)
                                else:
                                    if idx < len(clean_lines) and clean_lines[idx][0] > next_indent:
                                        item_map[nk] = parse_block(clean_lines[idx][0])
                                    else:
                                        item_map[nk] = {}
                            else:
                                break
                        result_list.append(item_map)
                    else:
                        result_list.append(parse_primitive(item_str))
                return result_list
            else:
                result_map: Dict[str, Any] = {}
                while idx < len(clean_lines):
                    cur_indent, cur_content = clean_lines[idx]
                    if cur_indent < expected_indent:
                        break

                    if ":" not in cur_content:
                        idx += 1
                        continue

                    colon_idx = cur_content.find(":")
                    key = cur_content[:colon_idx].strip()
                    val_str = cur_content[colon_idx + 1:].strip()
                    idx += 1

                    if val_str:
                        # inline list check like [a, b, c]
                        if val_str.startswith("[") and val_str.endswith("]"):
                            inner = val_str[1:-1].strip()
                            if inner:
                                items = [parse_primitive(x.strip()) for x in inner.split(",")]
                                result_map[key] = items
                            else:
                                result_map[key] = []
                        else:
                            result_map[key] = parse_primitive(val_str)
                    else:
                        # nested block
                        if idx < len(clean_lines) and clean_lines[idx][0] > cur_indent:
                            result_map[key] = parse_block(clean_lines[idx][0])
                        else:
                            result_map[key] = {}
                return result_map

        return parse_block(0) or {}


def load_yaml_raw(file_path_or_text: str) -> Dict[str, Any]:
    """Loads a YAML file or raw string using PyYAML if present, or fallback."""
    content: str
    if os.path.exists(file_path_or_text):
        with open(file_path_or_text, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = file_path_or_text

    try:
        import yaml  # type: ignore
        raw_dict = yaml.safe_load(content) or {}
    except ImportError:
        raw_dict = PurePythonYamlParser.load(content)

    return interpolate_env_vars(raw_dict)


def build_proxy_config(raw: Dict[str, Any]) -> ProxyConfig:
    """Validates and instantiates the typed ProxyConfig object."""
    ad_raw = raw.get("active_directory", {})
    domain_config = DomainConfig(
        domain_name=ad_raw.get("domain_name", "corp.example.com"),
        base_dn=ad_raw.get("base_dn", "DC=corp,DC=example,DC=com"),
        domain_controllers=ad_raw.get("domain_controllers", ["dc01.corp.example.com"]),
        ldaps_port=int(ad_raw.get("ldaps_port", 636)),
        timeout_seconds=int(ad_raw.get("timeout_seconds", 10)),
        connect_retries=int(ad_raw.get("connect_retries", 3)),
        verify_ssl=bool(ad_raw.get("verify_ssl", True)),
        ca_cert_path=ad_raw.get("ca_cert_path"),
    )

    tls_raw = raw.get("ldaps", {})
    tls_settings = TlsSettings(
        min_version=tls_raw.get("min_version", "TLSv1.2"),
        cert_file=tls_raw.get("cert_file"),
        key_file=tls_raw.get("key_file"),
        ca_file=tls_raw.get("ca_file"),
        verify_client=bool(tls_raw.get("verify_client", False)),
        cipher_suites=tls_raw.get("cipher_suites"),
    )

    up_raw = raw.get("upstream_auth", {})
    mode_str = up_raw.get("mode", "service_account").lower()
    auth_mode = AuthMode.GMSA if mode_str == "gmsa" else AuthMode.SERVICE_ACCOUNT

    bao_raw = up_raw.get("openbao")
    openbao_config = None
    if bao_raw:
        openbao_config = OpenBaoConfig(
            address=bao_raw.get("address", "https://vault.corp.internal:8200"),
            auth_method=bao_raw.get("auth_method", "approle"),
            role_id=bao_raw.get("role_id"),
            secret_id=bao_raw.get("secret_id"),
            token=bao_raw.get("token"),
            secret_path=bao_raw.get("secret_path", "secret/data/ad-proxy"),
            secret_key=bao_raw.get("secret_key", "service_account_password"),
            tls_ca_cert=bao_raw.get("tls_ca_cert"),
            cache_ttl_seconds=int(bao_raw.get("cache_ttl_seconds", 300)),
        )

    provider_str = up_raw.get("secret_provider", "env").lower()
    if provider_str in ("openbao", "vault"):
        secret_provider = SecretProvider.OPENBAO
    elif provider_str == "direct":
        secret_provider = SecretProvider.DIRECT
    else:
        secret_provider = SecretProvider.ENV

    upstream_auth = UpstreamAuthConfig(
        mode=auth_mode,
        gmsa_name=up_raw.get("gmsa_name"),
        username=up_raw.get("username"),
        secret_provider=secret_provider,
        password=up_raw.get("password"),
        openbao=openbao_config,
    )

    allowed_accounts: Dict[str, AllowedServiceAccount] = {}
    accounts_raw = raw.get("allowed_service_accounts", [])
    if isinstance(accounts_raw, list):
        for acc in accounts_raw:
            ident = acc.get("account_identifier", "").lower()
            if not ident:
                continue
            rules: List[PermittedRequestRule] = []
            for r in acc.get("rules", []):
                rules.append(
                    PermittedRequestRule(
                        command=r.get("command", ""),
                        allowed_groups=r.get("allowed_groups"),
                        restricted_groups=r.get("restricted_groups"),
                        allowed_ous=r.get("allowed_ous"),
                        allowed_attributes=r.get("allowed_attributes"),
                        max_search_results=int(r.get("max_search_results", 200)),
                        require_approval_ticket=bool(r.get("require_approval_ticket", False)),
                    )
                )
            allowed_accounts[ident] = AllowedServiceAccount(
                account_identifier=acc.get("account_identifier", ""),
                description=acc.get("description", ""),
                permitted_commands=acc.get("permitted_commands", []),
                rules=rules,
                denied_commands=acc.get("denied_commands", []),
            )

    siem_raw = raw.get("siem", {})
    fmt_str = siem_raw.get("format", "ecs").lower()
    if fmt_str == "cef":
        siem_format = SiemFormat.CEF
    elif fmt_str in ("syslog", "syslog_rfc5424"):
        siem_format = SiemFormat.SYSLOG
    else:
        siem_format = SiemFormat.ECS

    siem_config = SiemConfig(
        enabled=bool(siem_raw.get("enabled", True)),
        format=siem_format,
        destinations=siem_raw.get("destinations", ["file", "stdout"]),
        log_file_path=siem_raw.get("log_file_path", "/var/log/ad-proxy/audit.log"),
        syslog_host=siem_raw.get("syslog_host"),
        syslog_port=int(siem_raw.get("syslog_port", 514)),
        syslog_protocol=siem_raw.get("syslog_protocol", "UDP").upper(),
        webhook_url=siem_raw.get("webhook_url"),
        webhook_token=siem_raw.get("webhook_token"),
        log_all_queries=bool(siem_raw.get("log_all_queries", True)),
    )

    return ProxyConfig(
        active_directory=domain_config,
        ldaps=tls_settings,
        upstream_auth=upstream_auth,
        allowed_service_accounts=allowed_accounts,
        siem=siem_config,
        listen_host=raw.get("listen_host", "0.0.0.0"),
        listen_port=int(raw.get("listen_port", 10636)),
        max_concurrent_connections=int(raw.get("max_concurrent_connections", 100)),
    )
