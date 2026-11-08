"""
Secure AD-Proxy Server & LDAPS Gateway.
Runs TLS/HTTPS and LDAPS socket interfaces for AI agents and service accounts.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
import ssl
from typing import Optional
from .models import ProxyConfig, ProxyRequest
from .proxy_engine import AdProxyEngine

logger = logging.getLogger("ad_proxy.server")


class AdProxyHttpHandler(BaseHTTPRequestHandler):
    """Secure TLS/HTTPS gateway handler for AI Agents executing AD LDAPS queries."""

    engine: AdProxyEngine

    def do_POST(self):
        client_ip = self.client_address[0]
        if self.path in ("/v1/ldaps/query", "/query"):
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0 or content_length > 1_000_000:
                self._send_json(400, {"success": False, "message": "Invalid request body size."})
                return

            try:
                body = self.rfile.read(content_length).decode("utf-8")
                payload = json.loads(body)
            except Exception as e:
                self._send_json(400, {"success": False, "message": f"Malformed JSON: {e}"})
                return

            caller = payload.get("caller_account") or self.headers.get("X-AD-Service-Account")
            password = payload.get("caller_password") or self.headers.get("X-AD-Service-Password")
            command = payload.get("command")
            parameters = payload.get("parameters", {})
            ticket_id = payload.get("ticket_id") or self.headers.get("X-IT-Ticket-ID")

            req = ProxyRequest(
                caller_account=caller or "",
                caller_password=password or "",
                command=command or "",
                parameters=parameters,
                client_ip=client_ip,
                ticket_id=ticket_id,
            )

            res = self.engine.process_request(req)
            status_code = 200 if res.success else (401 if res.status_code == "AUTHENTICATION_FAILED" else (403 if res.status_code == "FORBIDDEN" else 400))

            self._send_json(status_code, {
                "success": res.success,
                "status_code": res.status_code,
                "message": res.message,
                "data": res.data,
                "request_id": res.request_id,
                "duration_ms": res.duration_ms,
            })

        elif self.path in ("/v1/auth/verify", "/auth/verify"):
            # Endpoint to test service account credentials without running an operation
            content_length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8")) if content_length > 0 else {}
            caller = payload.get("caller_account")
            password = payload.get("caller_password")
            ok, msg = self.engine.authenticator.authenticate_agent(caller, password)
            self._send_json(200 if ok else 401, {"authenticated": ok, "message": msg})

        else:
            self._send_json(404, {"success": False, "message": f"Unknown endpoint: {self.path}"})

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self._send_json(200, {
                "status": "UP",
                "service": "Active Directory Secure LDAPS Proxy",
                "domain": self.engine.config.active_directory.domain_name,
                "ldaps_enforced": True,
                "dc_pool": self.engine.config.active_directory.domain_controllers,
            })
        elif self.path in ("/v1/commands", "/commands"):
            cmds = self.engine.registry.list_commands()
            self._send_json(200, {"commands": cmds, "count": len(cmds)})
        elif self.path in ("/v1/siem/recent", "/siem/recent"):
            events = self.engine.siem.get_recent_events(limit=50)
            self._send_json(200, {"events": events, "count": len(events)})
        else:
            self._send_json(404, {"success": False, "message": "Not Found"})

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Route HTTP access logs through standard logger
        logger.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)


class AdProxyServer:
    """Manages the lifecycle of the AD Proxy server."""

    def __init__(self, config: ProxyConfig, engine: Optional[AdProxyEngine] = None):
        self.config = config
        self.engine = engine or AdProxyEngine(config)
        self._httpd: Optional[HTTPServer] = None

    def start(self, use_tls: bool = True):
        """Starts the server with TLS encryption."""
        server_address = (self.config.listen_host, self.config.listen_port)

        class BoundHandler(AdProxyHttpHandler):
            engine = self.engine

        self._httpd = HTTPServer(server_address, BoundHandler)

        cert_file = self.config.ldaps.cert_file
        key_file = self.config.ldaps.key_file

        if use_tls and cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
            logger.info("AD-Proxy listening on https://%s:%d with TLS 1.2+ encryption.", self.config.listen_host, self.config.listen_port)
        else:
            logger.info("AD-Proxy listening on http://%s:%d (Dev/Local mode).", self.config.listen_host, self.config.listen_port)

        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self._httpd:
            logger.info("Stopping AD-Proxy server...")
            self._httpd.shutdown()
            self._httpd.server_close()
