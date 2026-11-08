"""
AI Agent & Service Account Authenticator.
Verifies credentials against upstream Active Directory Domain Controllers via secure LDAPS simple bind.
"""

import logging
from typing import Tuple
from .ldap_client import ActiveDirectoryLdapClient

logger = logging.getLogger("ad_proxy.auth")


class AgentAuthenticator:
    """Validates AI agent and service account credentials over LDAPS."""

    def __init__(self, ldap_client: ActiveDirectoryLdapClient):
        self.ldap_client = ldap_client

    def authenticate_agent(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Validates the calling agent's AD identity against the Domain Controller.
        Returns: (is_authenticated, message)
        """
        if not username:
            return False, "Authentication failed: Missing service account username."
        if not password:
            return False, "Authentication failed: Missing service account password."

        logger.info("Authenticating service account '%s' against Domain Controllers over LDAPS...", username)
        success, reason = self.ldap_client.authenticate_credentials(username=username, password=password)

        if success:
            logger.info("Authentication succeeded for '%s'.", username)
        else:
            logger.warning("Authentication failed for '%s': %s", username, reason)

        return success, reason
