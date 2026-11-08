"""
Enterprise Secret Manager with support for OpenBao (Vault-compatible),
Environment Variables, and gMSA (Group Managed Service Accounts).
"""

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional
from .models import AuthMode, OpenBaoConfig, SecretProvider, UpstreamAuthConfig

logger = logging.getLogger("ad_proxy.secrets")


class SecretManager:
    """Resolves Active Directory upstream credentials at runtime without storing plaintext secrets on disk."""

    def __init__(self, config: UpstreamAuthConfig):
        self.config = config
        self._cached_secret: Optional[str] = None
        self._cache_expiry: float = 0.0

    def get_credentials(self) -> tuple[str, Optional[str]]:
        """
        Returns (username, password_or_gmsa_token).
        For gMSA, returns (gmsa_name, None) with SASL/GSSAPI indicator.
        """
        if self.config.mode == AuthMode.GMSA:
            gmsa_name = self.config.gmsa_name or "svc-adproxy$"
            logger.info("Using Group Managed Service Account (gMSA): %s", gmsa_name)
            return gmsa_name, None

        # Standard Service Account
        username = self.config.username or "CN=svc-ad-proxy,OU=ServiceAccounts,DC=corp,DC=example,DC=com"

        # Check in-memory cache
        now = time.time()
        if self._cached_secret and now < self._cache_expiry:
            return username, self._cached_secret

        secret: Optional[str] = None

        if self.config.secret_provider == SecretProvider.OPENBAO:
            secret = self._resolve_from_openbao(self.config.openbao)
            ttl = self.config.openbao.cache_ttl_seconds if self.config.openbao else 300
            self._cached_secret = secret
            self._cache_expiry = now + ttl
        elif self.config.secret_provider == SecretProvider.ENV:
            env_var_name = self.config.password or "AD_PROXY_SVC_PASSWORD"
            # If the password starts with $ or env:, strip it
            if env_var_name.startswith("env:"):
                env_var_name = env_var_name[4:]
            elif env_var_name.startswith("$"):
                env_var_name = env_var_name[1:]
            secret = os.environ.get(env_var_name, self.config.password or "")
            if not secret:
                logger.warning("Secret environment variable '%s' not set; using fallback if configured.", env_var_name)
        elif self.config.secret_provider == SecretProvider.DIRECT:
            secret = self.config.password
        else:
            secret = os.environ.get("AD_PROXY_SVC_PASSWORD", self.config.password or "")

        return username, secret

    def _resolve_from_openbao(self, bao_cfg: Optional[OpenBaoConfig]) -> str:
        """
        Interacts with OpenBao / HashiCorp Vault via native HTTPS REST API.
        Does not require external SDK dependencies, ensuring zero-trust reliability.
        """
        if not bao_cfg:
            raise ValueError("OpenBao configuration block is missing.")

        logger.info("Injecting AD credential from OpenBao at: %s", bao_cfg.address)

        # Setup TLS Context
        ctx = ssl.create_default_context()
        if bao_cfg.tls_ca_cert and os.path.exists(bao_cfg.tls_ca_cert):
            ctx.load_verify_locations(bao_cfg.tls_ca_cert)
        else:
            # If internal self-signed without explicit cert in test environment
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        token = bao_cfg.token

        # AppRole Authentication
        if not token and bao_cfg.auth_method == "approle":
            if not bao_cfg.role_id or not bao_cfg.secret_id:
                raise ValueError("OpenBao AppRole authentication requires role_id and secret_id.")

            login_url = f"{bao_cfg.address.rstrip('/')}/v1/auth/approle/login"
            payload = json.dumps({"role_id": bao_cfg.role_id, "secret_id": bao_cfg.secret_id}).encode("utf-8")
            req = urllib.request.Request(
                login_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    token = resp_data.get("auth", {}).get("client_token")
            except Exception as e:
                logger.error("OpenBao AppRole authentication failed: %s", e)
                # If OpenBao is unreachable during testing/dev, fall back to environment variable if present
                fallback = os.environ.get("AD_PROXY_SVC_PASSWORD")
                if fallback:
                    logger.warning("Falling back to local AD_PROXY_SVC_PASSWORD environment secret.")
                    return fallback
                raise RuntimeError(f"OpenBao AppRole authentication error: {e}") from e

        if not token:
            fallback = os.environ.get("AD_PROXY_SVC_PASSWORD")
            if fallback:
                return fallback
            raise ValueError("Could not acquire OpenBao client token.")

        # Read Secret (KV v2 path /v1/secret/data/<path> or direct KV v1)
        secret_url = f"{bao_cfg.address.rstrip('/')}/v1/{bao_cfg.secret_path.lstrip('/')}"
        req = urllib.request.Request(
            secret_url,
            headers={"X-Vault-Token": token, "Accept": "application/json"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # KV v2 stores in data.data.<key>; KV v1 stores in data.<key>
                secret_data = data.get("data", {})
                if "data" in secret_data and isinstance(secret_data["data"], dict):
                    secret_data = secret_data["data"]

                val = secret_data.get(bao_cfg.secret_key)
                if not val:
                    raise KeyError(f"Key '{bao_cfg.secret_key}' not found in secret data at {bao_cfg.secret_path}")
                return str(val)
        except Exception as e:
            logger.error("OpenBao secret lookup failed: %s", e)
            fallback = os.environ.get("AD_PROXY_SVC_PASSWORD")
            if fallback:
                logger.warning("Using environment variable fallback for AD secret.")
                return fallback
            raise RuntimeError(f"Failed to fetch secret from OpenBao: {e}") from e
