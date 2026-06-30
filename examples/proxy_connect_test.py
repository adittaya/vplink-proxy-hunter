#!/usr/bin/env python3
"""Example: Pull 5 working proxies from Supabase and test connections through each.

Demonstrates:
  1. Querying the database for verified working proxies
  2. Making HTTP requests through each proxy
  3. Measuring response times and success rates

Usage:
  python3 examples/proxy_connect_test.py
  python3 examples/proxy_connect_test.py --type residential --count 10
"""

import argparse
import json
import os
import subprocess
import sys
import time
from supabase import create_client

CONFIG_PATH = os.path.expanduser("~/.config/vplink-hunter/config.json")
TEST_URLS = [
    "https://httpbin.org/ip",
    "https://httpbin.org/headers",
    "https://httpbin.org/user-agent",
    "https://httpbin.org/get",
    "https://api.ipify.org?format=json",
]


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def test_proxy(ip, port, proto="http", timeout=10):
    proxy_url = f"{proto}://{ip}:{port}"
    results = []
    for url in TEST_URLS:
        cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{time_total}:%{size_download}",
            "--connect-timeout", "5", "--max-time", str(timeout),
            "-x", proxy_url, url,
        ]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 2)
            code, t, size = out.decode().strip().split(":")
            results.append({
                "url": url.split("/")[2],
                "http_code": code,
                "time_s": round(float(t), 3),
                "size_bytes": int(size),
                "ok": code.startswith("2"),
            })
        except Exception:
            results.append({
                "url": url.split("/")[2],
                "http_code": "000",
                "time_s": 0,
                "size_bytes": 0,
                "ok": False,
            })
    return results


def main():
    parser = argparse.ArgumentParser(description="Test proxy connections from database")
    parser.add_argument("--type", choices=["residential", "datacenter"], default="residential")
    parser.add_argument("--count", type=int, default=5, help="Number of proxies to test")
    parser.add_argument("--vplink", action="store_true", default=False, help="Only VPLINK-verified")
    args = parser.parse_args()

    config = load_config()
    if not config.get("supabase_url") or not config.get("service_key"):
        print("  [!] No Supabase config found.")
        sys.exit(1)

    client = create_client(config["supabase_url"], config["service_key"])
    q = client.table("proxy_results").select("*").eq("type", args.type)
    if args.vplink:
        q = q.eq("vplink_ok", True)
    resp = q.order("last_seen", desc=True).range(0, args.count - 1).execute()

    proxies = resp.data
    if not proxies:
        print(f"  No {args.type} proxies found.")
        sys.exit(1)

    proxies = proxies[:args.count]
    print(f"\n  Testing {len(proxies)} proxies against {len(TEST_URLS)} URLs each...\n")

    all_ok = 0
    all_total = 0

    for i, p in enumerate(proxies, 1):
        ip, port, proto = p["ip"], p["port"], p.get("proto", "http")
        tag = "🏠" if p.get("type") == "residential" else "🏢"
        print(f"  {i}. {tag} {ip}:{port} ({p.get('country','?')}/{p.get('city','?')})")

        results = test_proxy(ip, port, proto)
        ok_count = sum(1 for r in results if r["ok"])

        for r in results:
            icon = "✅" if r["ok"] else "❌"
            t = f"{r['time_s']:.2f}s" if r["ok"] else "timeout"
            print(f"       {icon} {r['url']:<20} HTTP {r['http_code']}  {t}")

        all_ok += ok_count
        all_total += len(results)
        print()

    pct = (all_ok / all_total * 100) if all_total else 0
    status = "✅ ALL PASSED" if pct == 100 else "⚠️  PARTIAL" if pct > 50 else "❌ MOST FAILED"
    print(f"  {status}  {all_ok}/{all_total} requests succeeded ({pct:.0f}%)\n")


if __name__ == "__main__":
    main()
