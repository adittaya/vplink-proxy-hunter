#!/usr/bin/env python3
"""VPLINK Proxy API — REST API for proxy rotation.

Zero-dependency HTTP server that exposes the Supabase proxy database
as a simple REST API. Just an API key to integrate into any codebase.

Usage:
    python3 proxy_api.py --port 8080
    # or via CLI:
    vplink-hunter --serve --port 8080

Endpoints:
    GET /api/proxy?key=xxx          → random working proxy
    GET /api/proxy/rotate?key=xxx   → round-robin rotation
    GET /api/proxies?key=xxx        → list working proxies
    GET /api/stats?key=xxx          → database statistics
    GET /api/key/reset?key=xxx      → regenerate API key
    GET /api/health                 → health check (no key needed)

Client example:
    curl "http://localhost:8080/api/proxy?key=YOUR_API_KEY"
    # returns: {"ip":"1.2.3.4","port":8080,"url":"http://1.2.3.4:8080",...}

Requirements:
    pip install supabase  (already installed with vplink-hunter)
"""

import json
import os
import secrets
import sys
import time
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vplink_hunter import config as cfg
from vplink_hunter import supabase_client as sb

API_KEY = ""
ROTATION_INDEX = 0


def _format(p: dict) -> dict:
    return {
        "ip": p["ip"],
        "port": p["port"],
        "url": f"http://{p['ip']}:{p['port']}",
        "latency_ms": p.get("latency_ms"),
        "type": p.get("type"),
        "country": p.get("country"),
        "city": p.get("city"),
        "region": p.get("region"),
        "isp": p.get("isp"),
        "vplink_ok": p.get("vplink_ok"),
    }


class ProxyAPIHandler(BaseHTTPRequestHandler):

    def _auth(self, params: dict, headers: dict) -> bool:
        key = params.get("key", [None])[0]
        if not key:
            key = headers.get("x-api-key", headers.get("X-API-Key", ""))
        return key == API_KEY

    def _json(self, data, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _error(self, msg: str, status: int = 400):
        self._json({"error": msg}, status)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)
        headers = {k.lower(): v for k, v in self.headers.items()}

        if path == "/api/health":
            return self._json({"status": "ok", "time": time.time()})

        if not self._auth(params, headers):
            return self._json({
                "error": "unauthorized",
                "message": "Pass ?key=YOUR_API_KEY or X-API-Key header",
            }, 401)

        routes = {
            "/api/proxy": self._random_proxy,
            "/api/proxy/rotate": self._rotate_proxy,
            "/api/proxies": self._list_proxies,
            "/api/stats": self._stats,
            "/api/key/reset": self._reset_key,
        }

        handler = routes.get(path)
        if handler:
            handler(params)
        else:
            self._json({
                "error": "not_found",
                "endpoints": list(routes.keys()) + ["/api/health"],
            }, 404)

    def _random_proxy(self, params=None):
        proxies = sb.list_proxies(vplink_only=False, limit=1000)
        if not proxies:
            return self._error("no_proxies_available", 404)
        p = random.choice(proxies)
        self._json(_format(p))

    def _rotate_proxy(self, params=None):
        global ROTATION_INDEX
        proxies = sb.list_proxies(vplink_only=False, limit=1000)
        if not proxies:
            return self._error("no_proxies_available", 404)
        p = proxies[ROTATION_INDEX % len(proxies)]
        ROTATION_INDEX += 1
        self._json(_format(p))

    def _list_proxies(self, params):
        type_filter = params.get("type", [None])[0]
        vplink = params.get("vplink", ["false"])[0].lower() == "true"
        limit = int(params.get("limit", ["50"])[0])
        proxies = sb.list_proxies(
            type_filter=type_filter, vplink_only=vplink, limit=limit
        )
        self._json({"count": len(proxies), "proxies": [_format(p) for p in proxies]})

    def _stats(self, params=None):
        s = sb.get_stats()
        self._json(s if s else {"error": "no_stats"})

    def _reset_key(self, params=None):
        global API_KEY
        API_KEY = secrets.token_urlsafe(24)
        conf = cfg.get()
        conf["api_key"] = API_KEY
        cfg.save(conf)
        self._json({"key": API_KEY, "message": "API key regenerated"})

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[api] {args[0]} {args[1]} {args[2]}\n")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        self.end_headers()


def serve(port: int = 8080, host: str = "0.0.0.0"):
    global API_KEY

    conf = cfg.get()
    sb.init(conf["supabase_url"], conf["service_key"])

    API_KEY = conf.get("api_key", "")
    if not API_KEY:
        API_KEY = secrets.token_urlhex(24) if hasattr(secrets, 'token_urlhex') else secrets.token_urlsafe(24)
        conf["api_key"] = API_KEY
        cfg.save(conf)
        print(f"  [i] Generated new API key")

    server = HTTPServer((host, port), ProxyAPIHandler)
    print(f"")
    print(f"  ╔══════════════════════════════════════════╗")
    print(f"  ║     PROXY API SERVER                     ║")
    print(f"  ╚══════════════════════════════════════════╝")
    print(f"")
    print(f"  URL:  http://{host}:{port}")
    if host == "0.0.0.0":
        import socket
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
            print(f"  LAN:  http://{local_ip}:{port}")
        except Exception:
            pass
    print(f"  Key:  {API_KEY}")
    print(f"")
    print(f"  Try:")
    print(f"    curl 'http://localhost:{port}/api/proxy?key={API_KEY}'")
    print(f"    curl 'http://localhost:{port}/api/proxy/rotate?key={API_KEY}'")
    print(f"    curl 'http://localhost:{port}/api/stats?key={API_KEY}'")
    print(f"")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  ⏹  Stopped.")
        server.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VPLINK Proxy API Server")
    parser.add_argument("--port", type=int, default=8080, help="Listen port (default: 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()
    serve(port=args.port, host=args.host)
