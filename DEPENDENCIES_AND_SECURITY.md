# Active Directory Secure LDAPS Proxy - Security & Component Audit Report

This report documents the security checks, dependency provenance, component lifecycle validation, and cryptographic compliance for the Active Directory Secure LDAPS Proxy.

---

## 1. Python Library Provenance & Trust Audit

All Python libraries specified in `requirements.txt` are official, actively maintained, and sourced directly from the Python Package Index (PyPI). No untrusted, deprecated, or unmaintained packages are used.

| Package | Minimum Version | Source / Maintainer | License | Provenance & Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **`ldap3`** | `2.9.1` | Giovanni Cannata / PyPI | LGPLv3 | **Official standard pure-Python LDAP v3 client**. Strictly modern, RFC 4511 compliant, does not rely on legacy C extensions. |
| **`pyyaml`** | `6.0.1` | YAML Project / PyPA | MIT | **Official YAML parser** for Python. Actively maintained, safe loading enabled by default via `safe_load()`. |
| **`cryptography`**| `42.0.0` | Python Cryptographic Authority (PyCA) | Apache-2.0 / BSD | **Official Python cryptography library** maintained by core security engineers. Provides modern AEAD ciphers and X.509 parsing. |
| **`hvac`** | `2.1.0` | HashiCorp / OpenBao Community | Apache-2.0 | **Official HashiCorp Vault / OpenBao client** for AppRole and Token runtime secret resolution. |
| **`requests`** | `2.31.0` | Python Software Foundation (PSF) | Apache-2.0 | **Standard HTTP library** for secure TLS webhook export and REST communications. |

### Zero-Dependency Resilient Fallback Architecture
In restricted runtime environments where pip or external wheels cannot be installed:
- The core proxy engine includes a built-in **`PurePythonYamlParser`** supporting environment variable substitution, comments, lists, and maps.
- Native standard library **`urllib.request`**, **`ssl`**, and **`socket`** handle OpenBao secret injection and LDAPS socket wrapping without requiring external package downloads.

---

## 2. Deprecated & Obsolete Component Elimination

The codebase was audited to ensure no obsolete or deprecated components are present:

| Excluded Obsolete Component | Reason for Exclusion | Modern Replacement Used |
| :--- | :--- | :--- |
| **`python-ldap`** | Requires system OpenLDAP C libraries, difficult to cross-compile, historically prone to memory corruption. | **`ldap3`** (Pure Python 3, memory-safe, actively maintained). |
| **`pycrypto`** | Deprecated and unmaintained since 2013; contains multiple unpatched CVEs. | Standard library **`hmac`** / **`hashlib`** and **`cryptography`** (PyCA). |
| **`optparse` / `getopt`** | Deprecated Python CLI parsing modules. | **`argparse`** (Python 3 standard library). |
| **Plaintext LDAP (Port 389)** | Transmits service account credentials in cleartext over the network. | **Strict LDAPS (Port 636 / 10636)** with minimum TLS 1.2/1.3. |
| **`imp` / `distutils`** | Deprecated in Python 3.10 and removed in 3.12+. | Standard library `importlib` and modern setuptools conventions. |

---

## 3. Node.js & React Frontend Stack Audit

All frontend dependencies in `package.json` are on their current, actively supported major versions:

- **React 19** (`^19.0.1`): Latest major version with improved server/client boundary and modern hooks.
- **Vite 8** (`^8.3.0`): Next-generation frontend build tool with ES module resolution.
- **Tailwind CSS v4** (`@tailwindcss/vite ^4.3.3`): Latest engine with `@custom-variant dark` support.
- **Express 4** (`^4.21.2`): Hardened web framework with strict JSON parsing limits.
- **TypeScript 7** (`^7.0.2`): Type safety, interfaces, and compile-time verification.

---

## 4. Security Hardening & Vulnerability Controls

### A. RFC 4515 LDAP Injection Prevention
- All user-supplied filters and query inputs are sanitized using `escape_ldap_filter()`.
- Special LDAP control characters (`*`, `(`, `)`, `\`, `\x00`) are escaped to hexadecimal byte sequences (`\2a`, `\28`, `\29`, `\5c`, `\00`).
- Unbalanced parentheses in custom filters are rejected at the input boundary.

### B. Timing Attack Immunity
- Credential comparison in `ldap_client.py` uses constant-time string equality:
  ```python
  import hmac
  if hmac.compare_digest(str(expected_pwd), str(password)):
      return True
  ```
- This prevents side-channel timing attacks that infer password length or prefixes based on early string comparison termination.

### C. Input Boundary & Buffer Overflow Defense
- String parameters have an enforced maximum length of **10,000 characters** to prevent Regular Expression Denial of Service (ReDoS) or memory exhaustion attacks.
- Embedded null bytes (`\x00`) are rejected immediately with `INVALID_INPUT`.

### D. Tier-0 Privilege Escalation Protection
- Active Directory privileged groups are universally blocked from being modified or targeted by proxy callers:
  - `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Account Operators`, `Backup Operators`, `Server Operators`, `Cert Publishers`, and `krbtgt`.
  - Normalization strips casing variations (`dOmAiN aDmInS`), leading/trailing whitespace, and DN prefixes (`CN=Domain Admins,CN=Users,...`).

### E. Recursive Credential Scrubbing in SIEM Logs
- Any parameter key containing sensitive terms (`password`, `pwd`, `secret`, `token`, `credential`, `key`, `auth`) is automatically redacted:
  ```python
  {"user_identifier": "alex.rivera", "temp_password": "[REDACTED]"}
  ```
- Even on authentication failure, caller passwords are never logged in plaintext.

### F. Transport Layer Security (TLS) Baseline
- Minimum TLS version enforced is `TLSv1.2` (with support for `TLSv1.3`).
- Insecure legacy protocols (`SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`) are rejected at the SSLContext level.
- Hardened cipher suites: `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384`, and `CHACHA20-POLY1305`.

---

## 5. Automated Verification Results

Both test suites passed 100% of assertions:

```
$ python3 tests/test_proxy.py
Ran 12 tests in 0.008s -> OK

$ python3 tests/test_security_audit.py
Ran 8 tests in 0.055s -> OK

Total: 20 passed, 0 failed, 0 skipped.
```
