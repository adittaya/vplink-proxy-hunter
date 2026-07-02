#!/usr/bin/env python3
"""VPLINK Proxy Hunter — clean orchestration.

Scrape → Test → Verify → Upsert (append-only, no auto-delete)."""

import argparse
import asyncio
import sys
import time
from collections import deque

from . import config as cfg
from . import supabase_client as sb
from .engine1_generator import (
    scrape_lists, SOURCE_STATS, record_source_result, source_pass_rate, should_skip_source,
)
from .engine2_tester import worker as e2_worker, _ip_in_dc_cidr
from .engine3_verifier import verify as e3_verify, cleanup_subprocesses as e3_cleanup


def c(s, code=0):
    return f"\033[{code}m{s}\033[0m"


stats = dict(generated=0, tested=0, http_ok=0, verified=0, qdepth=0, e3_fails={})
db_totals = dict(total=0, e2_ok=0, vplink_ok=0, residential=0)
runners = []


def render():
    sys.stdout.write("\033[H\033[2J")
    e = time.time() - render.t0
    r = int(stats["tested"] / max(e, 1))
    dt = db_totals
    s = (
        c("╔════════════════════════════════════════════════════════════════════╗\n", 36) +
        c(f"║  VPLINK Proxy Hunter   {r:>4}/s   {int(e):>6}s                    ║\n", 93) +
        c("╠════════════════════════════════════════════════════════════════════╣\n", 36) +
        c(f"║  GEN {stats['generated']:>8}   Queue {stats['qdepth']:>5}                        ║\n", 90) +
        c(f"║  TEST {stats['tested']:>8}                                        ║\n", 90) +
        c(f"║  HTTP {stats['http_ok']:>8}                                        ║\n", 90) +
        c(f"║  E3  {stats['verified']:>8}                                        ║\n", 92) +
        c("╠════════════════════════════════════════════════════════════════════╣\n", 36) +
        c(f"║  DB TOTAL {dt['total']:>6}   RES {dt.get('residential',0):>6}                  ║\n", 90) +
        c(f"║  DB E2_OK {dt['e2_ok']:>6}   E3  {dt.get('vplink_ok',0):>6}                  ║\n", 90) +
        c("╚════════════════════════════════════════════════════════════════════╝\n", 36)
    )
    sys.stdout.write(s)
    if stats.get("e3_fails"):
        top = sorted(stats["e3_fails"].items(), key=lambda x: -x[1])[:5]
        sys.stdout.write(c("╔════ FAIL ═══════════════════════════════════════════════════════════╗\n", 93))
        for k, v in top:
            sys.stdout.write(c(f"║  {k:<30} {v:>6}\n", 91))
        sys.stdout.write(c("╚════════════════════════════════════════════════════════════════════╝\n", 93))
    if stats["verified"] > 0:
        latest = runners[-3:]
        sys.stdout.write(c("╔════════════════════════════════════════════════════════════════════╗\n", 92))
        sys.stdout.write(c(f"║  VERIFIED  ({stats['verified']} this run)\n", 92))
        for v in reversed(latest):
            tag = "R" if v.get("type") == "residential" else "D"
            line = f"║  [{tag}] {v['ip']:>15}:{v['port']:<5} {v['latency']:>5}ms {v.get('country','?')}/{v.get('city','?')}"
            sys.stdout.write(c(line, 97) + "\n")
        sys.stdout.write(c("╚════════════════════════════════════════════════════════════════════╝\n", 92))
    sys.stdout.flush()


async def _render_loop():
    last_state: tuple = ()
    last_heartbeat = 0.0
    while True:
        cur = (stats["generated"], stats["tested"], stats["http_ok"], stats["verified"],
               stats["qdepth"],
               db_totals.get("total"), db_totals.get("residential"),
               db_totals.get("e2_ok"), db_totals.get("vplink_ok"))
        now = time.time()
        if cur != last_state or now - last_heartbeat > 2:
            last_state = cur
            last_heartbeat = now
            render()
        await asyncio.sleep(0.5)


async def gen_worker(q, stats, e2_tested_at, source_for_ip):
    """Re-scrape proxy lists when queue runs low or every 20 min.

    Every 20 minutes the queue is cleared and a fresh scrape starts,
    so old/stale proxies are discarded rather than slowly trickling through.
    Tracks which source each IP came from for quality scoring."""
    MIN_REFILL = 1000
    E2_RE_TEST_INTERVAL = 900
    RESTART_CYCLE = 1200  # 20 minutes
    cycle_start = time.time()
    while True:
        depth = q.qsize()
        stats["qdepth"] = depth
        now = time.time()
        cycle_elapsed = now - cycle_start

        if cycle_elapsed >= RESTART_CYCLE:
            # Drain stale queue and start fresh
            for _ in range(q.qsize()):
                try:
                    q.get_nowait()
                except Exception:
                    break
            source_for_ip.clear()
            stats["generated"] = 0
            cycle_start = now
            proxies = await scrape_lists()
        elif depth >= MIN_REFILL:
            await asyncio.sleep(1)
            continue
        else:
            proxies = await scrape_lists()

        if proxies:
            local_seen: set[tuple[str, int]] = set()
            count = 0
            for item in proxies:
                ip, port = item[0], item[1]
                source = item[2] if len(item) >= 3 else "unknown"
                ip_port = (ip, port)
                if ip_port in local_seen:
                    continue
                local_seen.add(ip_port)
                if now - e2_tested_at.get(ip, 0) < E2_RE_TEST_INTERVAL:
                    continue
                if _ip_in_dc_cidr(ip):
                    continue
                try:
                    q.put_nowait(ip_port)
                    source_for_ip[ip_port] = source
                    count += 1
                except asyncio.QueueFull:
                    break
            stats["generated"] += count
        await asyncio.sleep(10)


async def e3_worker(e3_queue, already_verified, e3_in_flight):
    """Verify candidates from E3 queue and upsert to DB immediately."""
    while True:
        try:
            cand = await asyncio.wait_for(e3_queue.get(), timeout=1)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        try:
            key = (cand["ip"], cand["port"])
            if key in already_verified:
                continue
            verified = await e3_verify(cand, do_vplink=True, fail_counts=stats["e3_fails"])
            if verified and verified["type"] == "residential":
                already_verified.add(key)
                stats["verified"] += 1
                runners.append(verified)
                verified["e2_ok"] = True
                await sb.async_upsert_proxy(verified)
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        finally:
            e3_queue.task_done()
            e3_in_flight.discard((cand["ip"], cand["port"]))


async def db_poll_task(interval: int = 10):
    """Refresh DB totals for the dashboard."""
    while True:
        try:
            counts = sb.get_counts()
            if counts:
                db_totals.update(counts)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def main_loop(args):
    conf = cfg.get()
    sb.init(conf["supabase_url"], conf["service_key"])

    # Load already-verified from DB so we never re-verify
    already_verified: set[tuple[str, int]] = set()
    try:
        rows = sb.list_proxies(vplink_only=True)
        if rows:
            for p in rows:
                already_verified.add((p["ip"], p["port"]))
    except Exception:
        pass

    try:
        counts = sb.get_counts()
        if counts:
            db_totals.update(counts)
    except Exception:
        pass

    render.t0 = time.time()
    for k in ("generated", "tested", "http_ok", "verified"):
        stats[k] = 0

    q = asyncio.Queue(maxsize=10000)
    e2_results: deque = deque()
    e2_event = asyncio.Event()
    e2_tested_at: dict[str, float] = {}
    e3_in_flight: set[tuple[str, int]] = set()
    e3_queue = asyncio.Queue(maxsize=500)
    source_for_ip: dict[tuple[str, int], str] = {}
    source_stats_report: dict[str, dict] = {}

    e2_pool = [asyncio.create_task(e2_worker(q, e2_results, e2_event))
               for _ in range(80)]
    e3_pool = [asyncio.create_task(e3_worker(e3_queue, already_verified, e3_in_flight))
               for _ in range(max(1, args.e3_concurrency))]
    render_task = asyncio.create_task(_render_loop())
    db_poll = asyncio.create_task(db_poll_task(10))

    gen_task = None
    try:
        # Initial scrape — fill the queue with (ip, port) tuples
        proxies = await scrape_lists()
        if proxies:
            seen: set[tuple[str, int]] = set()
            for item in proxies:
                ip, port = item[0], item[1]
                source = item[2] if len(item) >= 3 else "unknown"
                ip_port = (ip, port)
                if ip_port not in seen and not _ip_in_dc_cidr(ip):
                    seen.add(ip_port)
                    source_for_ip[ip_port] = source
                    try:
                        q.put_nowait(ip_port)
                        stats["generated"] += 1
                    except asyncio.QueueFull:
                        break

        gen_task = asyncio.create_task(gen_worker(q, stats, e2_tested_at, source_for_ip))

        while True:
            stats["qdepth"] = q.qsize()
            try:
                await asyncio.wait_for(e2_event.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            e2_event.clear()

            while e2_results:
                cand = e2_results.popleft()
                stats["tested"] += 1
                e2_tested_at[cand["ip"]] = time.time()
                if not cand:
                    continue
                # Track source pass rate for quality scoring
                key = (cand["ip"], cand["port"])
                src = source_for_ip.pop(key, None)
                if src:
                    src_total = source_stats_report.setdefault(src, {"total": 0, "passed": 0})
                    src_total["total"] += 1
                    src_total["passed"] += 1
                    record_source_result(src, 1, 1)
                stats["http_ok"] += 1
                if key in already_verified or key in e3_in_flight:
                    continue
                e3_in_flight.add(key)
                try:
                    e3_queue.put_nowait(cand)
                except asyncio.QueueFull:
                    pass

            if args.once:
                all_e2_done = q.qsize() == 0 and not e2_results
                all_e3_done = (e3_queue.qsize() == 0)
                if all_e2_done and all_e3_done and stats["tested"] > 0:
                    break

    except asyncio.CancelledError:
        pass
    finally:
        if gen_task:
            gen_task.cancel()
        render_task.cancel()
        db_poll.cancel()
        e3_cleanup()
        for w in e2_pool + e3_pool:
            w.cancel()
        await asyncio.gather(render_task, db_poll, *e2_pool, *e3_pool,
                             *(gen_task,) if gen_task else (),
                             return_exceptions=True)

    render()


def cmd_list(args):
    conf = cfg.get()
    if not conf:
        return
    sb.init(conf["supabase_url"], conf["service_key"])
    if args.ip:
        results = sb.list_proxies_by_ip(args.ip)
    else:
        results = sb.list_proxies(type_filter=args.type, vplink_only=args.vplink,
                                  limit=args.limit or 50, offset=args.offset or 0)
    if not results:
        print("  No proxies found.")
        return
    print(f"  Found {len(results)} proxy(es):")
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
    for k, v in s.items():
        print(f"  {k:<20} {v}")


def cmd_delete(args):
    conf = cfg.get()
    if not conf:
        return
    sb.init(conf["supabase_url"], conf["service_key"])
    ok = sb.delete_proxy(args.ip, args.port)
    print(f"  {'OK' if ok else 'FAIL'}: Deleted {args.ip}:{args.port}")


def _print_source_report():
    if not SOURCE_STATS:
        return
    sys.stderr.write("╔══════ Source Quality Report ══════════════════════════════╗\n")
    for src in sorted(SOURCE_STATS.keys()):
        s = SOURCE_STATS[src]
        rate = s["passed"] / max(s["total"], 1) * 100
        skip = " SKIP" if s["total"] >= 100 and rate < 5 else ""
        sys.stderr.write(f"║  {src:<20} {s['passed']:>4}/{s['total']:<4} ({rate:5.1f}%){skip:<5} ║\n")
    sys.stderr.write("╚══════════════════════════════════════════════════════════════╝\n")


def _run_session(args):
    while True:
        try:
            asyncio.run(main_loop(args))
        except KeyboardInterrupt:
            _print_source_report()
            break
        except Exception as exc:
            _print_source_report()
            sys.stderr.write(f"[!] Crash: {exc}. Restarting in 3s...\n")
            time.sleep(3)
            continue
        break


def main():
    parser = argparse.ArgumentParser(description="VPLINK Proxy Hunter")
    parser.add_argument("--once", action="store_true", help="Run one batch then exit")
    parser.add_argument("--list", action="store_true", help="List proxies from database")
    parser.add_argument("--type", help="Filter by type")
    parser.add_argument("--vplink", action="store_true", help="VPLINK-verified only")
    parser.add_argument("--ip", help="Lookup by IP")
    parser.add_argument("--port", type=int, help="Port for delete")
    parser.add_argument("--limit", type=int, default=50, help="Max results")
    parser.add_argument("--offset", type=int, default=0, help="Pagination offset")
    parser.add_argument("--delete", action="store_true", help="Delete a proxy")
    parser.add_argument("--db-stats", action="store_true", help="Show DB statistics")
    parser.add_argument("--e3-concurrency", type=int, default=5, help="Concurrent E3 verifications")
    parser.add_argument("--reset-config", action="store_true", help="Reset saved config")
    parser.add_argument("--status", action="store_true", help="Show config status")
    args = parser.parse_args()

    if args.reset_config:
        import os
        if os.path.exists(cfg.CONFIG_PATH):
            os.remove(cfg.CONFIG_PATH)
            print("  Config reset.")
        else:
            print("  No config file.")
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

    _run_session(args)


if __name__ == "__main__":
    main()
