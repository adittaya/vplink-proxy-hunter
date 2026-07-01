#!/usr/bin/env python3
"""VPLINK Proxy Hunter — CLI entrypoint.

3 engines, realtime dashboard, concurrent E3.
Event-driven main loop (no busy-wait), crash-resistant workers,
auto-restart, port prioritization, stale cleanup."""

import argparse
import asyncio
import multiprocessing
import os
import sys
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from . import config as cfg
from . import supabase_client as sb
from .engine1_generator import batch as gen_batch, scrape_lists, set_biased_ports, set_biased_subnets, set_working_ips, get_biased_ports
from .engine2_tester import worker as e2_worker, best_ports
from .engine3_verifier import verify as e3_verify, cleanup_subprocesses as e3_cleanup, classify as e3_classify


def c(s, code=0):
    return f"\033[{code}m{s}\033[0m"


stats = dict(generated=0, tested=0, open_port=0, http_ok=0,
             residential=0, verified=0, qdepth=0)
db_totals = dict(total=0, e2_ok=0, vplink_ok=0, residential=0)
runners = []
def render():
    os.system("clear" if os.name == "posix" else "cls")
    e = time.time() - render.t0
    r = int(stats["tested"] / max(e, 1))
    qd = stats["qdepth"]

    sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 36))
    sys.stdout.write(c("""║  ██╗   ██╗██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗    ██╗  ██╗██╗   ║
║  ██║   ██║██╔══██╗██║     ██║████╗  ██║██║  ██║    ██║  ██║██║   ║
║  ██║   ██║██████╔╝██║     ██║██╔██╗ ██║███████║    ███████║██║   ║
║  ╚██╗ ██╔╝██╔═══╝ ██║     ██║██║╚██╗██║╚════██║    ██╔══██║██║   ║
║   ╚████╔╝ ██║     ███████╗██║██║ ╚████║     ██║    ██║  ██║██║   ║
║    ╚═══╝  ╚═╝     ╚══════╝╚═╝╚═╝  ╚═══╝     ╚═╝    ╚═╝  ╚═╝╚═╝   ║""", 93))
    sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 36))

    qbar_w = 30
    qfill = int(qbar_w * min(qd / 5000, 1))
    qbar = c("█" * qfill, 93) + c("░" * (qbar_w - qfill), 90)
    sys.stdout.write(c(f"  {r:>4}/s  {int(e):>6}s  queue [{qbar}] {qd:>5}\n", 90))

    dt = db_totals
    sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 36))
    rows = [
        ("SESSION", "GEN", stats["generated"]),
        ("SESSION", "TEST", stats["tested"]),
        ("SESSION", "HTTP", stats["http_ok"]),

        ("SESSION", "E3_OK", stats["verified"]),
    ]
    for label, key, val in rows:
        sys.stdout.write(c(f"║  {label:<8} {key:<6} {c(str(val),97):>10}  {c('|',90)}", 90))
    sys.stdout.write(c("╠" + "═" * 68 + "╣\n", 36))
    rows2 = [
        ("DB", "TOTAL", dt["total"]),
        ("DB", "RES", dt.get("residential", 0)),
        ("DB", "E2_OK", dt["e2_ok"]),
        ("DB", "E3_OK", dt["vplink_ok"]),
    ]
    for label, key, val in rows2:
        sys.stdout.write(c(f"║  {label:<8} {key:<6} {c(str(val),97):>10}  {c('|',90)}", 90))
    sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 36))

    if stats["verified"] > 0:
        latest = runners[-3:] if runners else []
        sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 92))
        sys.stdout.write(c(f"║  E3 VERIFIED  ({stats['verified']} this run)\n", 92))
        for v in reversed(latest):
            tag = "R" if v.get("type") == "residential" else "D"
            line = f"║  [{tag}] {v['ip']:>15}:{v['port']:<5} {v['latency']:>5}ms {v.get('country','?')}/{v.get('city','?')}"
            sys.stdout.write(c(line, 97) + "\n")
        sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 92))

    sys.stdout.write("\033[J")
    sys.stdout.flush()


async def e3_worker(e3_queue, stats, runners, e3_tracking, restart_event, already_verified):
    while True:
        got_item = False
        try:
            cand = await asyncio.wait_for(e3_queue.get(), timeout=1)
            got_item = True
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        try:
            verified = await e3_verify(cand, do_vplink=True)
            if verified and verified["type"] == "residential":
                already_verified.add((cand["ip"], cand["port"]))
                stats["verified"] += 1
                stats["residential"] += 1
                runners.append(verified)
                verified["e2_ok"] = True
                await sb.async_upsert_proxy(verified)
                if stats["verified"] % 20 == 0:
                    restart_event.set()
            e3_tracking["completed"] = e3_tracking.get("completed", 0) + 1
        except asyncio.CancelledError:
            break
        except Exception:
            e3_tracking["completed"] = e3_tracking.get("completed", 0) + 1
        finally:
            if got_item:
                e3_queue.task_done()


async def gen_worker(q, stats):
    """Match E2 throughput — target 500 IPs in queue, small steady batches."""
    TARGET = 500
    while True:
        depth = q.qsize()
        stats["qdepth"] = depth
        gap = TARGET - depth
        if gap <= 0:
            await asyncio.sleep(0.2)
            continue
        batch = gen_batch(min(gap, 50))
        stats["generated"] += len(batch)
        for ip in batch:
            await q.put(ip)
        await asyncio.sleep(0.1)


async def db_stats_task(interval: int = 10):
    """Refresh DB totals from Supabase every N seconds."""
    while True:
        try:
            counts = sb.get_counts()
            if counts:
                db_totals.update(counts)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def stale_cleanup_task(interval: int = 300):
    """Periodically remove proxies not seen in the last hour."""
    await asyncio.sleep(interval)
    while True:
        try:
            db = sb.get()
            if db:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                resp = db.table("proxy_results").select("ip,port").lt("last_seen", cutoff).execute()
                if resp.data:
                    for row in resp.data:
                        db.table("proxy_results").delete().eq("ip", row["ip"]).eq("port", row["port"]).execute()
                    sys.stderr.write(f"[cleanup] removed {len(resp.data)} stale proxies\n")
                    # Refresh DB totals immediately
                    counts = sb.get_counts()
                    if counts:
                        db_totals.update(counts)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def reverify_task(interval: int = 120):
    """Re-check existing VPLINK-verified proxies — delete if they lost internet."""
    await asyncio.sleep(interval)
    while True:
        try:
            db = sb.get()
            if not db:
                await asyncio.sleep(interval)
                continue
            rows = db.table("proxy_results").select("ip,port").eq("vplink_ok", True).execute()
            rows = rows.data or []
            if not rows:
                await asyncio.sleep(interval)
                continue
            import concurrent.futures
            from .engine3_verifier import check_download

            async def _check_one(row: dict) -> tuple[str, int, bool]:
                try:
                    r = await check_download(row["ip"], row["port"], timeout=25)
                    return (row["ip"], row["port"], r["ok"])
                except Exception:
                    return (row["ip"], row["port"], False)

            tasks = [_check_one(r) for r in rows]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            dead = []
            for r in results:
                if isinstance(r, tuple) and not r[2]:
                    dead.append((r[0], r[1]))
            if dead:
                for ip, port in dead:
                    db.table("proxy_results").delete().eq("ip", ip).eq("port", port).execute()
                sys.stderr.write(f"[reverify] {len(dead)} proxies lost internet — deleted\n")
                counts = sb.get_counts()
                if counts:
                    db_totals.update(counts)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def main_loop(args) -> bool:
    """Run one session. Returns True if caller should restart."""
    conf = cfg.get()
    sb.init(conf["supabase_url"], conf["service_key"])

    should_restart = False
    SESSION_RESTART_AFTER = 20
    stats["verified"] = 0

    # Bootstrap exact working IPs + already-verified from DB
    try:
        known_ips = sb.get_working_ips()
        if known_ips:
            set_working_ips(known_ips)
            sys.stderr.write(f"[boot] loaded {len(known_ips)} working IPs from DB\n")
        verified_list = sb.list_proxies(vplink_only=True)
        if verified_list:
            for p in verified_list:
                already_verified.add((p["ip"], p["port"]))
            sys.stderr.write(f"[boot] {len(already_verified)} already-verified proxies in skip set\n")
        # Re-classify existing DB records with updated CIDR + org detection
        upd, d = sb.reclassify_all(e3_classify)
        if upd or d:
            sys.stderr.write(f"[boot] re-classified: {upd} updated, {d} datacenter deleted\n")
    except Exception:
        pass

    # Immediate DB totals fetch (don't wait for background task)
    try:
        counts = sb.get_counts()
        if counts:
            db_totals.update(counts)
    except Exception:
        pass

    render.t0 = time.time()
    for k in ("generated", "tested", "http_ok", "verified", "residential"):
        stats[k] = 0
    stats["_stall_restart_at"] = time.time()

    q = asyncio.Queue(maxsize=10000)
    e2_results = deque()
    e3_queue = asyncio.Queue(maxsize=500)
    e2_event = asyncio.Event()
    e3_tracking = {"enqueued": 0, "completed": 0}
    e3_verified_event = asyncio.Event()
    known_ips: list[str] = []
    ip_last_hit: dict[str, float] = {}
    already_verified: set[tuple[str, int]] = set()

    e2_pool = [asyncio.create_task(e2_worker(q, e2_results, e2_event))
               for _ in range(60)]
    e3_pool = [asyncio.create_task(e3_worker(e3_queue, stats, runners, e3_tracking, e3_verified_event, already_verified))
               for _ in range(max(1, args.e3_concurrency))]
    render_task = asyncio.create_task(_render_loop())

    gen_task = cleanup_task = db_stats_task_handle = None
    try:
        scraped = await scrape_lists()
        if scraped:
            seen_ips = set()
            for ip, port in scraped:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    await q.put(ip)
            sys.stderr.write(f"[boot] scraped {len(scraped)} proxies → {len(seen_ips)} unique IPs\n")
            stats["generated"] += len(seen_ips)

        gen_task = asyncio.create_task(gen_worker(q, stats))
        cleanup_task = asyncio.create_task(stale_cleanup_task())
        reverify_task_handle = asyncio.create_task(reverify_task())
        db_stats_task_handle = asyncio.create_task(db_stats_task(interval=10))

        last_port_rebalance = time.time()

        while True:
            stats["qdepth"] = q.qsize()

            if should_restart:
                break

            # Timeout on event wait — prevents deadlock when all proxies fail
            try:
                await asyncio.wait_for(e2_event.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            e2_event.clear()

            if should_restart:
                break

            while e2_results:
                cand = e2_results.popleft()
                stats["tested"] += 1
                if not cand:
                    continue
                stats["http_ok"] += 1

                # Skip E3 if already verified this session
                key = (cand["ip"], cand["port"])
                if key in already_verified:
                    continue

                # Track exact IP for generator bias
                if cand["ip"] not in known_ips:
                    known_ips.append(cand["ip"])
                ip_last_hit[cand["ip"]] = time.time()

                # Drop if E3 queue is full (backpressure) — prevents hours-long backlog
                try:
                    e3_queue.put_nowait(cand)
                    e3_tracking["enqueued"] += 1
                except asyncio.QueueFull:
                    pass

                # Check restart immediately after each result
                if e3_verified_event.is_set():
                    e3_verified_event.clear()
                    sys.stderr.write(f"[restart] {stats['verified']} verified — clean restart\n")
                    should_restart = True
                    break

            if should_restart:
                break

            now = time.time()
            if stats["tested"] == stats.get("_last_tested", 0) and stats["tested"] > 0:
                if now - stats.get("_stall_warned", 0) > 30:
                    stats["_stall_warned"] = now
                    sys.stderr.write(f"[stall] no tests in 30s — queue={q.qsize()} known_ips={len(known_ips)}\n")
                if now - stats.get("_stall_restart_at", 0) > 60:
                    sys.stderr.write("[stall] 60s — auto-restarting\n")
                    should_restart = True
                    break
            else:
                stats["_stall_restart_at"] = now
            stats["_last_tested"] = stats["tested"]
            if now - last_port_rebalance > 60:
                last_port_rebalance = now
                good = best_ports(20)
                if good:
                    set_biased_ports(good)
                # Prune known IPs with no hit in 10 min or DC-classified
                stale_cutoff = now - 300
                prune_ips = sb.get_dc_ips()
                known_ips = [ip for ip in known_ips
                             if ip not in prune_ips and ip_last_hit.get(ip, 0) >= stale_cutoff]
                if prune_ips:
                    sys.stderr.write(f"[prune] removed {len(prune_ips)} DC IPs from gen pool\n")
                set_working_ips(known_ips)
                if known_ips:
                    if len(known_ips) >= 3:
                        # Explore neighbor IPs in same /24 for sister proxies
                        subnets = {f"{ip.split('.')[0]}.{ip.split('.')[1]}.{ip.split('.')[2]}" for ip in known_ips}
                        set_biased_subnets(subnets)

            if e3_verified_event.is_set():
                e3_verified_event.clear()
                sys.stderr.write(f"[restart] {stats['verified']} verified — clean restart\n")
                should_restart = True

            if args.once:
                all_e2_done = q.qsize() == 0 and not e2_results
                all_e3_done = (e3_queue.qsize() == 0
                               and e3_tracking["completed"] >= e3_tracking["enqueued"])
                if all_e2_done and all_e3_done and stats["tested"] > 0:
                    break

    except asyncio.CancelledError:
        pass
    finally:
        if gen_task:
            gen_task.cancel()
        render_task.cancel()
        if cleanup_task:
            cleanup_task.cancel()
        if reverify_task_handle:
            reverify_task_handle.cancel()
        if db_stats_task_handle:
            db_stats_task_handle.cancel()
        e3_cleanup()
        for w in e2_pool + e3_pool:
            w.cancel()
        tasks_to_gather = [render_task, *e2_pool, *e3_pool]
        if gen_task:
            tasks_to_gather.append(gen_task)
        if cleanup_task:
            tasks_to_gather.append(cleanup_task)
        if reverify_task_handle:
            tasks_to_gather.append(reverify_task_handle)
        if db_stats_task_handle:
            tasks_to_gather.append(db_stats_task_handle)
        await asyncio.gather(*tasks_to_gather, return_exceptions=True)

    render()
    return should_restart


async def _render_loop():
    last_test = -1
    last_db_state = None
    while True:
        refresh = False
        if stats["tested"] > last_test:
            last_test = stats["tested"]
            refresh = True
        state = (db_totals.get("total"), db_totals.get("e2_ok"), db_totals.get("vplink_ok"), db_totals.get("residential"))
        if state != last_db_state:
            last_db_state = state
            refresh = True
        if refresh:
            render()
        await asyncio.sleep(0.5)


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
        tag = "R" if r.get("type") == "residential" else "D" if r.get("type") == "datacenter" else "?"
        vp = "Y" if r.get("vplink_ok") else "N"
        print(f"  [{tag}] {r['ip']:>15}:{r['port']:<5}  {r.get('latency_ms','?'):>5}ms  "
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
        print(f"  [OK] Deleted {args.ip}:{args.port}")
    else:
        print(f"  [!] Failed to delete {args.ip}:{args.port}")


def _run_session(args):
    """Run one scan session (blocking, with dashboard)."""
    while True:
        try:
            should = asyncio.run(main_loop(args))
        except KeyboardInterrupt:
            break
        except Exception as exc:
            sys.stderr.write(f"[!] Crash: {exc}. Restarting in 3s...\n")
            time.sleep(3)
            continue
        if should:
            continue
        break


def _run_background(args, session_id):
    """Run a silent background session (no dashboard output)."""
    sys.stderr = open("/dev/null", "w")
    _run_session(args)


def _run(args):
    n = getattr(args, "sessions", 1)
    if n <= 1:
        _run_session(args)
        return

    procs = []
    for i in range(n - 1):
        p = multiprocessing.Process(target=_run_background, args=(args, i), daemon=True)
        p.start()
        procs.append(p)
    try:
        _run_session(args)
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
        for p in procs:
            p.join()


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
    parser.add_argument("--sessions", type=int, default=1,
                        help="Number of parallel scan sessions (default: 1)")
    args = parser.parse_args()

    if args.reset_config:
        if os.path.exists(cfg.CONFIG_PATH):
            os.remove(cfg.CONFIG_PATH)
            print("  [OK] Config reset.")
        else:
            print("  [!] No config file to reset.")
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

    if args.list or args.ip:
        cmd_list(args)
        return

    if args.delete:
        cmd_delete(args)
        return

    if args.gen_api_key:
        conf["api_key"] = __import__("secrets").token_urlsafe(24)
        cfg.save(conf)
        print(f"  [OK] API key: {conf['api_key']}")
        print(f"  [i] Saved to {cfg.CONFIG_PATH}")
        return

    if args.serve:
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

    _run(args)


if __name__ == "__main__":
    main()
