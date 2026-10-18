#!/usr/bin/env python3
"""A deliberately broken service whose configuration is repaired through SSHGate."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        enabled = Path("/home/user/health.conf").read_text() == "enabled=1\n"
        body = b"ok\n" if enabled else b"disabled: enabled=0\n"
        self.send_response(200 if enabled else 503)
        self.end_headers()
        self.wfile.write(body)
        print("healthy: enabled=1" if enabled else "unhealthy: enabled=0", flush=True)

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", 8080), Health).serve_forever()
