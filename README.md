# Active Directory Secure LDAPS Proxy

An enterprise-grade, zero-trust Active Directory LDAPS Proxy designed specifically for **AI Agents**, autonomous workflows, and service accounts.

Instead of granting AI agents direct network access or broad administrative credentials to Active Directory Domain Controllers, all directory queries are routed through this proxy. The proxy verifies the calling agent's credentials over **strict LDAPS**, evaluates granular **Role-Based Access Control (RBAC)** rules against an internal configuration matrix, enforces strict parameter sanitization to prevent **LDAP injection**, forwards authorized requests to the Domain Controllers, and emits comprehensive **SIEM audit logs** (CEF, ECS JSON, RFC 5424 Syslog) for 100% compliance traceability.

---

## Architecture & Verification Workflow

```
+--------------------------------------------------------------------------------------------------------+
|                                    ACTIVE DIRECTORY SECURE LDAPS PROXY                                  |
+--------------------------------------------------------------------------------------------------------+

      +-------------------+
      |     AI Agent      | (e.g. LangChain, AutoGen, CrewAI, SOC Bot, Helpdesk Assistant)
      | (Service Account) |
      +---------+---------+
                |
                | [1] LDAPS Mutual TLS Handshake (Port 636 / 10636 / TLS REST Gateway)
                |     Payload: AD Credentials (Username + Password) + Command + Parameters
                v
      +-------------------+
      |   AD-Proxy Core   |
      +---------+---------+
                |
                | [2] Credential Verification (LDAPS Simple Bind to Domain Controller)
                v
      +-------------------+
      | Domain Controller |
      +---------+---------+
                |
      +---------+---------+
      | Auth OK?          |
      +----+---------+----+
           |         |
      No   |         | Yes
           v         v
     [Access Denied]  [3] RBAC Authorization Matrix Check (ad_proxy/config.yaml)
     [Emit High-Sev]      - Is service account registered in allowlist?
     [SIEM Audit   ]      - Is requested command in caller's permitted_commands?
     [Terminate    ]      - Does it touch protected Tier-0 groups (e.g. Domain Admins)?
                          - Are OU scope, attributes, and approval tickets satisfied?
                               |
                     +---------+---------+
                     | Allowed?          |
                     +----+---------+----+
                          |         |
                     No   |         | Yes
                          v         v
                    [Access Denied]  [4] Forward Query to Domain Controllers
                    [Emit SIEM    ]      - Executed over strict LDAPS (TLS 1.2 / 1.3)
                    [Terminate    ]      - Uses gMSA or OpenBao-injected credentials
                                         - Response sanitization (no hash leakage)
                                              |
                                              v
                                     [5] Emit SIEM Transaction Audit Event
                                         - Format: ECS JSON / CEF / RFC 5424 Syslog
                                         - Caller, Client IP, Target DN, Duration, Filter
                                              |
                                              v
                                     [Deliver Sanitized Result to AI Agent]
```

---

## Key Security Features

1. **Strict LDAPS Everywhere (Zero Plain-Text LDAP)**:
   - All communications (Agent -> Proxy and Proxy -> Domain Controllers) use TLS (TLSv1.2 or TLSv1.3).
   - Plain-text LDAP (port 389) is strictly prohibited across all endpoints.
2. **AI Agent Authentication**:
   - The calling agent provides its Active Directory credentials.
   - The proxy performs a real-time LDAPS bind against the Domain Controller pool to ensure the account is active, non-locked, and authenticated.
3. **Granular RBAC & Command Segmentation**:
   - Each service account is bound to a finite list of permissible Active Directory commands.
   - Fine-grained parameter boundaries (allowed groups, allowed OUs, whitelisted attributes, and max search results).
4. **Tier-0 Privilege Escalation Defense**:
   - Universal protection for privileged Active Directory objects: `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Account Operators`, `Backup Operators`, `Server Operators`, and `krbtgt`.
   - Modifying or targeting these groups via the proxy triggers an immediate block and high-severity SIEM alert.
5. **RFC 4515 LDAP Injection Prevention**:
   - All user-supplied inputs and search parameters are automatically escaped using standard RFC 4515 / RFC 4514 sanitization.
6. **gMSA & OpenBao / HashiCorp Vault Secret Injection**:
   - Upstream credentials to Domain Controllers can be backed by a **Group Managed Service Account (gMSA)** or dynamically retrieved at runtime from **OpenBao / HashiCorp Vault** via AppRole or Token authentication.
   - No plaintext passwords ever stored in configuration files or disk.
7. **Comprehensive SIEM Auditing**:
   - Every single attempt (allowed, unauthorized caller, forbidden command, invalid parameters, or authentication failure) is audited.
   - Formats supported: **CEF (Common Event Format)**, **ECS (Elastic Common Schema JSON)**, and **RFC 5424 Syslog**.
   - Configurable export to local audit log files, standard output, remote Syslog (UDP/TCP/TLS), and HTTP Webhook (e.g. Splunk HEC, Microsoft Sentinel).

---

## Directory Structure

```
.
├── ad_proxy/
│   ├── __init__.py           # Package initialization
│   ├── config.yaml           # Active YAML configuration file
│   ├── config.example.yaml   # Documented production template
│   ├── models.py             # Data classes for requests, responses, configs, audit events
│   ├── yaml_loader.py        # YAML parser with env var substitution & schema validation
│   ├── secret_manager.py     # OpenBao (Vault) & gMSA secret resolver
│   ├── rbac.py               # RBAC engine, parameter rules, and Tier-0 protection
│   ├── commands.py           # Extensible Active Directory command catalog
│   ├── ldap_client.py        # Secure LDAPS client with DC failover & TLS contexts
│   ├── authenticator.py      # Agent credential bind validator
│   ├── proxy_engine.py       # Core 5-stage verification orchestration engine
│   ├── server.py             # TLS/HTTPS REST & LDAPS gateway
│   └── cli.py                # Command-line interface
├── tests/
│   ├── __init__.py
│   └── test_proxy.py         # Full unit and security test suite
├── certs/                    # SSL/TLS certificates and CA bundles
├── requirements.txt          # Python dependencies
└── README.md                 # This documentation
```

---

## Installation & Quickstart

### Prerequisites
- Python 3.10+
- Network connectivity to Active Directory Domain Controllers on port 636 (LDAPS).

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Note: If running in a minimal environment without pip, the AD-Proxy includes a built-in pure-Python YAML parser and fallback engine so core operations and CLI commands run out-of-the-box with standard Python 3.10).*

### 2. Validate Configuration
```bash
python3 -m ad_proxy.cli --check-config
```

### 3. Run the Security & Functional Test Suite
```bash
python3 -m ad_proxy.cli --run-tests
# or
python3 tests/test_proxy.py
```

### 4. Test Domain Controller Connectivity
```bash
python3 -m ad_proxy.cli --test-dc
```

### 5. Simulate an AI Agent Query
```bash
python3 -m ad_proxy.cli --simulate-agent \
  --agent ai-triage-agent \
  --password "AgentSecurePassword2026!" \
  --command list_group_members \
  --param group_name=VPN-Users
```

### 6. Start the AD-Proxy Service
```bash
python3 -m ad_proxy.cli --run --config ad_proxy/config.yaml
```

---

## Configuration Guide (`ad_proxy/config.yaml`)

### 1. Active Directory Domain Settings
```yaml
active_directory:
  domain_name: "corp.acme.internal"
  base_dn: "DC=corp,DC=acme,DC=internal"
  domain_controllers:
    - "dc01.corp.acme.internal"
    - "dc02.corp.acme.internal"
  ldaps_port: 636
  timeout_seconds: 10
  connect_retries: 3
  verify_ssl: true
  ca_cert_path: "/etc/ssl/certs/ad_root_ca.crt"
```

### 2. LDAPS Server Settings (Incoming Client / Agent Connections)
```yaml
ldaps:
  min_version: "TLSv1.2"
  cert_file: "/etc/ad-proxy/certs/server.crt"
  key_file: "/etc/ad-proxy/certs/server.key"
  ca_file: "/etc/ssl/certs/ad_root_ca.crt"
  verify_client: false
  cipher_suites:
    - "ECDHE-ECDSA-AES256-GCM-SHA384"
    - "ECDHE-RSA-AES256-GCM-SHA384"
```

### 3. Upstream Service Account Authentication

#### Option A: Group Managed Service Account (gMSA)
```yaml
upstream_auth:
  mode: "gmsa"
  gmsa_name: "svc-adproxy$"
```

#### Option B: Standard Service Account with OpenBao / Vault Secret Injection
```yaml
upstream_auth:
  mode: "service_account"
  username: "CN=svc-ad-proxy,OU=ServiceAccounts,DC=corp,DC=acme,DC=internal"
  secret_provider: "openbao" # or "vault"
  openbao:
    address: "https://vault.corp.acme.internal:8200"
    auth_method: "approle" # "approle" or "token"
    role_id: "${OPENBAO_ROLE_ID}"
    secret_id: "${OPENBAO_SECRET_ID}"
    secret_path: "secret/data/ad-proxy"
    secret_key: "service_account_password"
    tls_ca_cert: "/etc/ssl/certs/vault_ca.crt"
    cache_ttl_seconds: 300
```

#### Option C: Standard Service Account with Environment Variable
```yaml
upstream_auth:
  mode: "service_account"
  username: "CN=svc-ad-proxy,OU=ServiceAccounts,DC=corp,DC=acme,DC=internal"
  secret_provider: "env"
  password: "${AD_PROXY_SVC_PASSWORD}"
```

### 4. Granular RBAC Matrix
```yaml
allowed_service_accounts:
  - account_identifier: "ai-triage-agent"
    description: "Automated SOC & Triage AI Agent with read access and quarantine abilities"
    permitted_commands:
      - "get_domain_info"
      - "search_users"
      - "get_user_attributes"
      - "check_user_membership"
      - "list_group_members"
      - "search_groups"
      - "get_group_details"
      - "search_computers"
      - "disable_account"
    denied_commands:
      - "reset_password"
      - "add_user_to_group"
    rules:
      - command: "disable_account"
        require_approval_ticket: true
      - command: "search_users"
        max_search_results: 100
        allowed_attributes:
          - "sAMAccountName"
          - "displayName"
          - "mail"
          - "department"
          - "title"

  - account_identifier: "svc-it-helpdesk-agent"
    description: "AI Helpdesk Bot allowed to unlock accounts and manage specific VPN/Dev groups"
    permitted_commands:
      - "get_domain_info"
      - "search_users"
      - "get_user_attributes"
      - "check_user_membership"
      - "list_group_members"
      - "add_user_to_group"
      - "remove_user_from_group"
      - "unlock_account"
      - "enable_account"
    rules:
      - command: "add_user_to_group"
        allowed_groups:
          - "VPN-Users"
          - "Developers"
        restricted_groups:
          - "Domain Admins"
          - "Enterprise Admins"
        require_approval_ticket: true
```

### 5. SIEM Auditing Configuration
```yaml
siem:
  enabled: true
  format: "ecs" # "ecs" (Elastic Common Schema JSON) | "cef" (ArcSight/Splunk) | "syslog_rfc5424"
  destinations:
    - "file"
    - "stdout"
    - "syslog"
    - "webhook"
  log_file_path: "/var/log/ad-proxy/audit.log"
  syslog_host: "siem-collector.corp.acme.internal"
  syslog_port: 514
  syslog_protocol: "TCP" # UDP | TCP | TLS
  webhook_url: "https://splunk-hec.corp.acme.internal:8088/services/collector/raw"
  webhook_token: "${SPLUNK_HEC_TOKEN}"
  log_all_queries: true
```

---

## Active Directory LDAPS Command Catalog

The proxy includes a comprehensive set of standard Active Directory commands that service accounts perform.

| Command Name | Category | Risk Level | Description | Required Parameters | Optional Parameters |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `get_domain_info` | `system` | **LOW** | Query RootDSE and domain partition information | *None* | `attributes` |
| `search_users` | `read` | **LOW** | Search user accounts with attribute filters | *None* | `query`, `department`, `enabled_only`, `ou_scope`, `attributes`, `limit` |
| `get_user_attributes` | `read` | **LOW** | Retrieve all attributes for a specific user | `user_identifier` | `attributes` |
| `check_user_membership` | `read` | **LOW** | Check if user is a direct or nested member of a group | `user_identifier`, `group_name` | `check_nested` |
| `list_group_members` | `read` | **LOW** | List members in a security group | `group_name` | `recursive`, `attributes` |
| `search_groups` | `read` | **LOW** | Search security & distribution groups | *None* | `query`, `group_type`, `limit` |
| `get_group_details` | `read` | **LOW** | Retrieve group type, scope, manager, and description | `group_name` | *None* |
| `search_computers` | `read` | **MEDIUM** | Enumerate domain workstations and servers | *None* | `query`, `operating_system`, `limit` |
| `get_organizational_units` | `read` | **LOW** | Enumerate Organizational Unit (OU) tree | *None* | `parent_ou` |
| `add_user_to_group` | `write` | **HIGH** | Add a user to an authorized security group | `user_identifier`, `group_name` | `justification`, `ticket_id` |
| `remove_user_from_group`| `write` | **HIGH** | Remove a user from a security group | `user_identifier`, `group_name` | `justification`, `ticket_id` |
| `enable_account` | `write` | **HIGH** | Enable a disabled Active Directory account | `user_identifier` | `ticket_id` |
| `disable_account` | `write` | **HIGH** | Disable an account (incident response quarantine) | `user_identifier` | `ticket_id`, `reason` |
| `unlock_account` | `write` | **HIGH** | Clear account lockout for locked user | `user_identifier` | `ticket_id` |
| `reset_password` | `admin` | **CRITICAL** | Perform secure password reset over LDAPS | `user_identifier`, `new_password` | `force_change_next_logon`, `ticket_id` |
| `update_user_attribute` | `write` | **MEDIUM** | Update non-critical user profile attribute (phone, department) | `user_identifier`, `attribute_name`, `attribute_value` | `ticket_id` |
| `custom_search_filter` | `read` | **MEDIUM** | Execute an advanced LDAP search filter with safety checks | `search_filter` | `search_base`, `attributes`, `limit` |

---

## Adding & Removing Commands (Extensible Command Registry)

Adding a new custom Active Directory LDAPS command is as simple as registering a handler function in `ad_proxy/commands.py` using the `@registry.register` decorator:

### Example: Adding a Custom BitLocker Recovery Key Lookup Command
```python
from ad_proxy.commands import registry, escape_ldap_filter
from ad_proxy.models import CommandRiskLevel

@registry.register(
    name="get_bitlocker_recovery_keys",
    description="Query msFVE-RecoveryInformation objects for a computer",
    category="admin",
    risk_level=CommandRiskLevel.CRITICAL,
    required_params=["computer_name"],
    optional_params=["ticket_id"],
)
def handle_get_bitlocker_keys(client, base_dn: str, params: dict):
    comp = escape_ldap_filter(params["computer_name"])
    ldap_filter = f"(&(objectClass=msFVE-RecoveryInformation)(distinguishedName=*CN={comp}*))"
    return client.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        attributes=["msFVE-RecoveryPassword", "whenCreated"],
        size_limit=5,
    )
```

To remove a command programmatically:
```python
registry.remove_command("get_bitlocker_recovery_keys")
```

---

## AI Agent Integration Examples

### 1. Python AI Agent (Standard Script / Requests)
```python
import requests

PROXIED_URL = "https://ad-proxy.corp.acme.internal:10636/v1/ldaps/query"

headers = {
    "Content-Type": "application/json",
    "X-IT-Ticket-ID": "INC-2026-8819", # Mandatory for write actions
}

payload = {
    "caller_account": "ai-triage-agent",
    "caller_password": "AgentSecurePassword2026!",
    "command": "list_group_members",
    "parameters": {
        "group_name": "VPN-Users",
        "recursive": False
    }
}

response = requests.post(PROXIED_URL, json=payload, headers=headers, verify="/etc/ssl/certs/ad_root_ca.crt")
result = response.json()

if result["success"]:
    print(f"Retrieved {len(result['data'])} group members.")
else:
    print(f"Proxy Blocked Request: {result['message']} (Code: {result['status_code']})")
```

### 2. LangChain Custom Active Directory Tool
```python
from langchain.tools import BaseTool
import requests

class ActiveDirectoryProxyTool(BaseTool):
    name = "active_directory_query"
    description = "Execute a secure, audited Active Directory command through the enterprise LDAPS proxy."

    def _run(self, command: str, parameters: dict, ticket_id: str = None) -> dict:
        url = "https://ad-proxy.corp.acme.internal:10636/v1/ldaps/query"
        payload = {
            "caller_account": "ai-triage-agent",
            "caller_password": os.environ["AGENT_AD_PASSWORD"],
            "command": command,
            "parameters": parameters,
            "ticket_id": ticket_id
        }
        res = requests.post(url, json=payload, timeout=10)
        return res.json()
```

### 3. cURL CLI Example
```bash
curl -k -X POST https://127.0.0.1:10636/v1/ldaps/query \
  -H "Content-Type: application/json" \
  -d '{
    "caller_account": "ai-triage-agent",
    "caller_password": "AgentSecurePassword2026!",
    "command": "search_users",
    "parameters": {
      "query": "Rivera",
      "department": "Engineering"
    }
  }'
```

---

## SIEM Formats & Integration Examples

### 1. Elastic Common Schema (ECS) Format
```json
{
  "@timestamp": "2026-11-08T08:39:29.619814+00:00",
  "event": {
    "id": "e9c9b323-f1c6-492c-828f-a4e513c598f3",
    "category": ["iam", "network"],
    "type": ["access", "protocol"],
    "action": "ad_proxy.list_group_members",
    "outcome": "success",
    "duration": 444889,
    "reason": "Executed Active Directory LDAPS command 'list_group_members' successfully."
  },
  "source": { "ip": "10.0.4.15" },
  "user": {
    "name": "ai-triage-agent",
    "domain": "corp.acme.internal"
  },
  "active_directory": {
    "command": "list_group_members",
    "status_code": "SUCCESS",
    "target_dn": "VPN-Users",
    "filter": null,
    "parameters": { "group_name": "VPN-Users" }
  },
  "service": {
    "name": "ad-ldaps-proxy",
    "version": "1.0.0"
  }
}
```

### 2. Common Event Format (CEF) Format (Splunk / ArcSight / QRadar)
```
CEF:0|EnterpriseSecurity|ActiveDirectoryProxy|1.0|SUCCESS|list_group_members|3|src=10.0.4.15 suser=ai-triage-agent cs1Label=Command cs1=list_group_members outcome=SUCCESS cn1Label=DurationMs cn1=12 msg=Executed Active Directory LDAPS command 'list_group_members' successfully. cs2Label=TargetDN cs2=VPN-Users cs4Label=Domain cs4=corp.acme.internal
```

---

## License & Compliance
This software is designed for enterprise Active Directory environments following NIST SP 800-53 (AC-6 Least Privilege, AU-2 Event Logging) and CIS Active Directory Benchmarks.
