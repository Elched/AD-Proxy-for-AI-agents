"""
Certificate utility for Active Directory LDAPS Proxy.
Generates corporate root CA and server certificates for development and testing.
"""

import os
import subprocess
import sys


def generate_dev_certs(cert_dir: str = "certs"):
    os.makedirs(cert_dir, exist_ok=True)
    ca_crt = os.path.join(cert_dir, "corporate_root_ca.crt")
    ca_key = os.path.join(cert_dir, "corporate_root_ca.key")
    server_crt = os.path.join(cert_dir, "ad_proxy_server.crt")
    server_key = os.path.join(cert_dir, "ad_proxy_server.key")

    if os.path.exists(ca_crt) and os.path.exists(server_crt):
        print(f"Certificates already exist in '{cert_dir}'.")
        return

    print(f"Generating TLS certificates in '{cert_dir}'...")
    try:
        # Generate CA Key & Cert
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", ca_key, "-out", ca_crt, "-days", "365",
                "-subj", "/C=US/ST=Security/O=Acme Enterprise/CN=Corporate-AD-Root-CA"
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Generate Server Key & CSR
        server_csr = os.path.join(cert_dir, "server.csr")
        subprocess.run(
            [
                "openssl", "req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", server_key, "-out", server_csr,
                "-subj", "/C=US/ST=Security/O=Acme Enterprise/CN=ad-proxy.corp.acme.internal"
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Sign Server Cert with CA
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", server_csr, "-CA", ca_crt,
                "-CAkey", ca_key, "-CAcreateserial", "-out", server_crt, "-days", "365"
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if os.path.exists(server_csr):
            os.remove(server_csr)

        print("[OK] Self-signed corporate CA and LDAPS server certificates successfully created.")
    except Exception as e:
        print(f"Notice: OpenSSL not available or failed: {e}. Placeholder cert paths retained.")


if __name__ == "__main__":
    generate_dev_certs()
