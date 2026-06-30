#!/usr/bin/env python3
"""Pull working proxy IP details from Supabase database.

Usage:
  python3 proxy_pull.py                          # last 10 working proxies
  python3 proxy_pull.py --type residential        # only residential
  python3 proxy_pull.py --vplink                  # only VPLINK-verified
  python3 proxy_pull.py --limit 5 --random        # 5 random proxies
  python3 proxy_pull.py --test --count 3          # pull + test 3 proxies
  python3 proxy_pull.py --export json             # export as JSON
  python3 proxy_pull.py --ip 1.2.3.4             # lookup by IP
  python3 proxy_pull.py --stats                   # database summary

Requires: pip install supabase
Config: reads ~/.config/vplink-hunter/config.json or env vars:
  SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
from supabase import create_client

CONFIG_PATH = os.path.expanduser("~/.config/vplink-hunter/config.json")


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {
        "supabase_url": os.environ.get("SUPABASE_URL", ""),
        "service_key": os.environ.get("SUPABASE_SERVICE_KEY", ""),
    }


def fmt(ms):
    if ms is None:
        return "?"
    ms = int(ms)
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms/1000:.1f}s"


def test_proxy(ip, port, proto="http", timeout=10):
    proxy_url = f"{proto}://{ip}:{port}"
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{time_total}",
        "--connect-timeout", "5", "--max-time", str(timeout),
        "-x", proxy_url, "https://httpbin.org/ip",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 2)
        code, t = out.decode().strip().split(":")
        return {"ok": code.startswith("2"), "http_code": code, "time": round(float(t), 3)}
    except Exception:
        return {"ok": False, "http_code": "000", "time": 0}


def main():
    parser = argparse.ArgumentParser(description="Pull working proxies from Supabase")
    parser.add_argument("--type", choices=["residential", "datacenter", "unknown"], help="Filter by type")
    parser.add_argument("--vplink", action="store_true", help="Only VPLINK-verified proxies")
    parser.add_argument("--limit", type=int, default=10, help="Number of results (default 10)")
    parser.add_argument("--offset", type=int, default=0, help="Pagination offset")
    parser.add_argument("--ip", help="Lookup by IP address")
    parser.add_argument("--random", action="store_true", help="Pick random proxies from results")
    parser.add_argument("--export", choices=["table", "json", "plain"], default="table", help="Output format")
    parser.add_argument("--test", action="store_true", help="Test each proxy with a real HTTP request")
    parser.add_argument("--count", type=int, default=5, help="Number of proxies to test (default 5)")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    args = parser.parse_args()

    config = load_config()
    if not config.get("supabase_url") or not config.get("service_key"):
        print("  [!] No Supabase config found. Run install.sh or set env vars.")
        sys.exit(1)

    client = create_client(config["supabase_url"], config["service_key"])

    if args.stats:
        all_ = client.table("proxy_results").select("*").execute()
        data = all_.data
        total = len(data)
        residential = sum(1 for r in data if r.get("type") == "residential")
        datacenter = sum(1 for r in data if r.get("type") == "datacenter")
        unknown = sum(1 for r in data if r.get("type") == "unknown")
        vplink_ok = sum(1 for r in data if r.get("vplink_ok"))
        print()
        print(f"  Database Statistics")
        print(f"  {'─' * 40}")
        print(f"  Total proxies:     {total}")
        print(f"  Residential:       {residential}")
        print(f"  Datacenter:        {datacenter}")
        print(f"  Unknown:           {unknown}")
        print(f"  VPLINK verified:   {vplink_ok}")
        print()
        return

    if args.ip:
        resp = client.table("proxy_results").select("*").eq("ip", args.ip).execute()
        results = resp.data
    else:
        q = client.table("proxy_results").select("*")
        if args.type:
            q = q.eq("type", args.type)
        if args.vplink:
            q = q.eq("vplink_ok", True)
        q = q.order("last_seen", desc=True)
        limit = args.limit
        if args.random:
            all_resp = q.execute()
            all_data = all_resp.data
            limit = min(limit, len(all_data))
            results = random.sample(all_data, limit) if limit > 0 else []
        else:
            resp = q.range(args.offset, args.offset + limit - 1).execute()
            results = resp.data

    if not results:
        print("  No proxies found.")
        return

    if args.export == "json":
        print(json.dumps(results, indent=2, default=str))
        return

    test_count = min(args.count, len(results))

    for i, r in enumerate(results[:test_count] if args.test else results):
        tag = "🏠" if r.get("type") == "residential" else "🏢" if r.get("type") == "datacenter" else "❓"
        vp = "✅" if r.get("vplink_ok") else "❌"
        ip = r["ip"]
        port = r["port"]
        proto = r.get("proto", "http")
        lat = fmt(r.get("latency_ms"))
        country = r.get("country", "?")
        city = r.get("city", "?")
        isp = (r.get("isp") or "")[:35]

        if args.export == "plain":
            print(f"{proto}://{ip}:{port}")
        else:
            print(f"  {tag} {ip:>15}:{port:<5}  {lat:>6}  {country:<3}/{city:<14}  {isp:<35}  V:{vp}")

        if args.test:
            result = test_proxy(ip, port, proto)
            status = "✅" if result["ok"] else "❌"
            print(f"       └─ Test: {status}  HTTP {result['http_code']}  {result['time']}s")

    remaining = len(results) - test_count
    if remaining > 0 and args.test:
        print(f"       ... and {remaining} more (use --count to test more)")

    if len(results) == 1 and not args.test:
        r = results[0]
        print(f"       Proto:     {r.get('proto', 'http')}")
        print(f"       Latency:   {fmt(r.get('latency_ms'))}")
        print(f"       Type:      {r.get('type', '?')}")
        print(f"       ISP:       {r.get('isp', '?')}")
        print(f"       Location:  {r.get('city', '?')}, {r.get('region', '?')}, {r.get('country', '?')}")
        print(f"       First:     {r.get('first_seen', '?')}")
        print(f"       Last:      {r.get('last_seen', '?')}")
        print(f"       VPLINK:    {'✅ Passed' if r.get('vplink_ok') else '❌ Failed'}")

    print()


if __name__ == "__main__":
    main()
