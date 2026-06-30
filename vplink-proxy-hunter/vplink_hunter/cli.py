#!/usr/bin/env python3
"""VPLINK Proxy Hunter — CLI entrypoint.

3 engines, realtime dashboard, concurrent E3 verification.
Runs 24/7 with no blocking."""

import argparse
import asyncio
import os
import sys
import time

from . import config as cfg
from . import supabase_client as sb
from .engine1_generator import batch as gen_batch, scrape_lists
from .engine2_tester import worker as e2_worker
from .engine3_verifier import verify as e3_verify


def c(s, code=0):
    return f"\033[{code}m{s}\033[0m"


stats = dict(generated=0, tested=0, open_port=0, http_ok=0, residential=0, verified=0, saved_e2=0)
runners = []


def render():
    os.system("clear" if os.name == "posix" else "cls")
    e = time.time() - render.t0
    r = int(stats["tested"] / max(e, 1))

    sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 36))
    sys.stdout.write(c("""║  ██╗   ██╗██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗    ██╗  ██╗██╗   ║
║  ██║   ██║██╔══██╗██║     ██║████╗  ██║██║  ██║    ██║  ██║██║   ║
║  ██║   ██║██████╔╝██║     ██║██╔██╗ ██║███████║    ███████║██║   ║
║  ╚██╗ ██╔╝██╔═══╝ ██║     ██║██║╚██╗██║╚════██║    ██╔══██║██║   ║
║   ╚████╔╝ ██║     ███████╗██║██║ ╚████║     ██║    ██║  ██║██║   ║
║    ╚═══╝  ╚═╝     ╚══════╝╚═╝╚═╝  ╚═══╝     ╚═╝    ╚═╝  ╚═╝╚═╝   ║""", 93))
    sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 36))
    sys.stdout.write(c(f"  ⚡ {r}/s  ⏱ {int(e)}s  🧬 {stats['generated']} gen\n", 90))

    bar_w = 42
    tot = max(stats["generated"], 1)
    pct = stats["tested"] / tot
    fill = int(bar_w * min(pct, 1))
    bar = c("█" * fill, 92) + c("░" * (bar_w - fill), 90)
    sys.stdout.write(f"  [{bar}] {stats['tested']}/{tot}\n")

    sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 36))
    rows = [
        ("🧬  E1 GEN", stats["generated"]),
        ("🎯  E2 TEST", stats["tested"]),
        ("🔓  PORT", stats["open_port"]),
        ("🌐  HTTP", stats["http_ok"]),
        ("💾  E2 SAVED", stats["saved_e2"]),
        ("✅  E3 VRFYD", stats["verified"]),
    ]
    for i in range(0, 6, 2):
        l_name, l_val = rows[i]
        r_name, r_val = rows[i + 1]
        sys.stdout.write(c(f"║  {l_name:<10} {c(str(l_val),97):<14}  {r_name:<10} {c(str(r_val),97):<14}║\n", 90))
    sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 36))

    if stats["verified"] > 0:
        latest = runners[-3:] if runners else []
        sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 92))
        sys.stdout.write(c(f"║  ✅  E3 VERIFIED ({stats['verified']} total)\n", 92))
        for v in reversed(latest):
            tag = c("🏠", 92) if v.get("type") == "residential" else c("🏢", 93)
            line = f"║  {tag} {v['ip']:>15}:{v['port']:<5} {v['latency']:>5}ms {v.get('country','?')}/{v.get('city','?')}"
            sys.stdout.write(c(line, 97) + "\n")
        sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 92))

    sys.stdout.write("\033[J")
    sys.stdout.flush()


async def e3_worker(e3_queue, max_e3, stats, runners):
    """Background: consumes from e3_queue, runs VPLINK check, updates DB."""
    sem = asyncio.Semaphore(max_e3)
    while True:
        try:
            cand = await asyncio.wait_for(e3_queue.get(), timeout=1)
        except asyncio.TimeoutError:
            continue
        async with sem:
            try:
                verified = await e3_verify(cand, do_vplink=True)
                if verified:
                    stats["verified"] += 1
                    runners.append(verified)
                    if verified["type"] == "residential":
                        stats["residential"] += 1
                    verified["e2_ok"] = True
                    sb.upsert_proxy(verified)
            finally:
                e3_queue.task_done()


async def gen_worker(q):
    """Background: continuously generates IP:port batches into the queue."""
    while True:
        batch = gen_batch(2000)
        stats["generated"] += len(batch)
        for ip, port in batch:
            await q.put((ip, port))


async def main_loop(args):
    conf = cfg.get()
    sb.init(conf["supabase_url"], conf["service_key"])

    render.t0 = time.time()

    q = asyncio.Queue(maxsize=50000)
    e2_results = []
    e3_queue = asyncio.Queue()

    e2_pool = [asyncio.create_task(e2_worker(q, e2_results)) for _ in range(80)]
    e3_pool = [asyncio.create_task(e3_worker(e3_queue, args.e3_concurrency, stats, runners))
               for _ in range(max(1, args.e3_concurrency))]
    render_task = asyncio.create_task(_render_loop())

    try:
        scraped = await scrape_lists()
        if scraped:
            for ip, port in scraped:
                await q.put((ip, port))
            stats["generated"] += len(scraped)

        gen_task = asyncio.create_task(gen_worker(q))

        while True:
            # Drain E2 results immediately — no blocking
            while e2_results:
                cand = e2_results.pop(0)
                stats["tested"] += 1
                if not cand:
                    continue
                stats["http_ok"] += 1
                e2_entry = {
                    "ip": cand["ip"],
                    "port": cand["port"],
                    "proto": "http",
                    "latency": cand["latency"],
                    "type": "unknown",
                    "isp": cand.get("isp", ""),
                    "country": cand.get("country", ""),
                    "city": cand.get("city", ""),
                    "region": cand.get("region", ""),
                    "vplink_ok": False,
                    "e2_ok": True,
                }
                sb.upsert_proxy(e2_entry)
                stats["saved_e2"] += 1
                e3_queue.put_nowait(cand)

            if args.once and stats["tested"] > 0 and not e2_results:
                break

            await asyncio.sleep(0.01)

    except asyncio.CancelledError:
        pass
    finally:
        gen_task.cancel()
        render_task.cancel()
        for w in e2_pool + e3_pool:
            w.cancel()
        await asyncio.gather(gen_task, render_task, *e2_pool, *e3_pool, return_exceptions=True)

    render()


async def _render_loop():
    last = -1
    while True:
        if stats["tested"] > last:
            last = stats["tested"]
            render()
        await asyncio.sleep(0.25)


def cmd_list(args):
    conf = cfg.get()
    if not conf:
        return
    sb.init(conf["supabase_url"], conf["service_key"])
    if args.ip:
        results = sb.list_proxies_by_ip(args.ip)
    else:
        results = sb.list_proxies(
            type_filter=args.type,
            vplink_only=args.vplink,
            limit=args.limit or 50,
            offset=args.offset or 0,
        )
    if not results:
        print("  No proxies found.")
        return
    print(f"  Found {len(results)} proxy(es):")
    print()
    for r in results:
        tag = "🏠" if r.get("type") == "residential" else "🏢" if r.get("type") == "datacenter" else "❓"
        vp = "✅" if r.get("vplink_ok") else "❌"
        print(f"  {tag} {r['ip']:>15}:{r['port']:<5}  {r.get('latency_ms','?'):>5}ms  "
              f"{r.get('country','?'):<3}/{r.get('city','?'):<12}  "
              f"ISP: {r.get('isp','')[:25]:<25}  VPLINK:{vp}")


def cmd_stats(args):
    conf = cfg.get()
    if not conf:
        return
    sb.init(conf["supabase_url"], conf["service_key"])
    s = sb.get_stats()
    if not s:
        print("  No stats available.")
        return
    print(f"  Total proxies:     {s.get('total', 0)}")
    print(f"  Residential:       {s.get('residential', 0)}")
    print(f"  Datacenter:        {s.get('datacenter', 0)}")
    print(f"  Unknown:           {s.get('unknown', 0)}")
    print(f"  VPLINK verified:   {s.get('vplink_ok', 0)}")


def cmd_delete(args):
    conf = cfg.get()
    if not conf:
        return
    sb.init(conf["supabase_url"], conf["service_key"])
    ok = sb.delete_proxy(args.ip, args.port)
    if ok:
        print(f"  [✓] Deleted {args.ip}:{args.port}")
    else:
        print(f"  [!] Failed to delete {args.ip}:{args.port}")


def main():
    parser = argparse.ArgumentParser(description="VPLINK Proxy Hunter")
    parser.add_argument("--reset-config", action="store_true", help="Reset saved config")
    parser.add_argument("--status", action="store_true", help="Show scan stats")
    parser.add_argument("--once", action="store_true", help="Run one batch then exit")
    parser.add_argument("--list", action="store_true", help="List proxies from database")
    parser.add_argument("--type", help="Filter by type (residential, datacenter, unknown)")
    parser.add_argument("--vplink", action="store_true", help="Show only VPLINK-verified proxies")
    parser.add_argument("--ip", help="Lookup proxies by IP")
    parser.add_argument("--port", type=int, help="Port for delete operation")
    parser.add_argument("--limit", type=int, default=50, help="Max results to return (default 50)")
    parser.add_argument("--offset", type=int, default=0, help="Offset for pagination")
    parser.add_argument("--delete", action="store_true", help="Delete a proxy by IP:port")
    parser.add_argument("--db-stats", action="store_true", help="Show database statistics")
    parser.add_argument("--serve", action="store_true", help="Start the REST API server")
    parser.add_argument("--api-port", type=int, default=8080, help="API server port (default: 8080)")
    parser.add_argument("--gen-api-key", action="store_true", help="Generate/reset API key for proxy API")
    parser.add_argument("--e3-concurrency", type=int, default=5,
                        help="Concurrent E3 (VPLINK) verifications (default: 5)")
    args = parser.parse_args()

    if args.reset_config:
        import os
        os.remove(cfg.CONFIG_PATH)
        print("  [✓] Config reset.")
        return

    conf = cfg.get()
    if not conf:
        return

    if args.status:
        print(f"  Config: {cfg.CONFIG_PATH}")
        print(f"  Supabase: {conf['supabase_url']}")
        return

    if args.db_stats:
        cmd_stats(args)
        return

    if args.list:
        cmd_list(args)
        return

    if args.delete:
        cmd_delete(args)
        return

    if args.gen_api_key:
        conf["api_key"] = __import__("secrets").token_urlsafe(24)
        cfg.save(conf)
        print(f"  [✓] API key: {conf['api_key']}")
        print(f"  [i] Saved to {cfg.CONFIG_PATH}")
        return

    if args.serve:
        conf = cfg.get()
        sb.init(conf["supabase_url"], conf["service_key"])
        api_key = conf.get("api_key", "")
        if not api_key:
            api_key = __import__("secrets").token_urlsafe(24)
            conf["api_key"] = api_key
            cfg.save(conf)
            print(f"  [i] Generated API key: {api_key}")
        import importlib
        api_mod = importlib.import_module("proxy_api")
        api_mod.serve(port=args.api_port)
        return

    try:
        asyncio.run(main_loop(args))
    except KeyboardInterrupt:
        print("\n\n  ⏹  Stopped.")


if __name__ == "__main__":
    main()
