#!/usr/bin/env python3
"""Classical Cryptography Toolkit - web application (standard library only).

Run:   python app.py            then open  http://127.0.0.1:8000
Options: --port 9000  --host 127.0.0.1  --no-browser
Optional password: set TOOLKIT_PASSWORD before starting.
"""
import argparse
import hmac
import json
import mimetypes
import os
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import service
from ciphers import CipherError

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_BODY = 3 * 1024 * 1024
TOKENS = set()


def password():
    return os.environ.get("TOOLKIT_PASSWORD") or None


class Handler(BaseHTTPRequestHandler):
    server_version = "CryptoToolkit/1.0"

    # ---- helpers -------------------------------------------------------
    def log_message(self, fmt, *args):
        if "--verbose" in sys.argv:
            super().log_message(fmt, *args)

    def send_json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        return password() is None or self.headers.get("X-Token", "") in TOKENS

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise CipherError("Invalid request.")
        if length > MAX_BODY:
            raise CipherError("Request too large (limit 3 MB).")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            raise CipherError("Invalid JSON.")
        if not isinstance(data, dict):
            raise CipherError("Invalid request.")
        return data

    # ---- routing -------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/status":
            return self.send_json(200, {"locked": password() is not None, "authed": self.authorized()})
        if path == "/api/ciphers":
            if not self.authorized():
                return self.send_json(401, {"error": "Login required."})
            return self.send_json(200, {"ciphers": service.list_ciphers()})
        if path.startswith("/api/"):
            return self.send_json(404, {"error": "Not found."})
        self.serve_static(path)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.read_json()
            if path == "/api/login":
                pw = password()
                if pw is None:
                    return self.send_json(200, {"token": ""})
                if hmac.compare_digest(str(data.get("password", "")), pw):
                    token = secrets.token_hex(16)
                    TOKENS.add(token)
                    return self.send_json(200, {"token": token})
                return self.send_json(401, {"error": "Wrong password."})
            if not self.authorized():
                return self.send_json(401, {"error": "Login required."})
            if path == "/api/run":
                return self.send_json(200, service.run(
                    data.get("cipher"), data.get("text"), data.get("key"), data.get("mode")))
            if path == "/api/random-key":
                return self.send_json(200, {"key": service.random_key(data.get("cipher"), data.get("text", ""))})
            if path == "/api/compare":
                return self.send_json(200, {"rows": service.compare(data.get("text"))})
            return self.send_json(404, {"error": "Not found."})
        except CipherError as e:
            self.send_json(400, {"error": str(e)})
        except Exception:  # never leak a traceback to the browser
            self.send_json(500, {"error": "Internal server error."})

    def serve_static(self, path):
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        full = os.path.realpath(os.path.join(WEB_DIR, rel))
        if not full.startswith(os.path.realpath(WEB_DIR) + os.sep) or not os.path.isfile(full):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"404 Not found")
            return
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") or "javascript" in ctype else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


def make_server(host="127.0.0.1", port=8000):
    return ThreadingHTTPServer((host, port), Handler)


def main():
    ap = argparse.ArgumentParser(description="Classical Cryptography Toolkit web app")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--verbose", action="store_true", help="log every request")
    args = ap.parse_args()

    server = None
    for port in range(args.port, args.port + 10):
        try:
            server = make_server(args.host, port)
            break
        except OSError:
            print(f"Port {port} is busy, trying the next one...")
    if server is None:
        print("Could not find a free port. Use --port <number>.")
        return 1

    url = f"http://{args.host}:{server.server_address[1]}"
    print("=" * 50)
    print("  CLASSICAL CRYPTOGRAPHY TOOLKIT - Web App")
    print("=" * 50)
    print(f"  Open in your browser: {url}")
    print("  Password protection : " + ("ON" if password() else "off (set TOOLKIT_PASSWORD to enable)"))
    print("  Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
