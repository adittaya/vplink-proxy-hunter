"""Engine 2 — Rapid Fire Tester.

TCP pre-check → HTTP GET via proxy.
80+ async workers, ~40-50 IPs/s."""

import asyncio
import json
import time
import subprocess
from collections import defaultdict

port_hits = defaultdict(int)
port_tries = defaultdict(int)


async def tcp_check(ip: str, port: int, timeout: int = 2) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def http_test(ip: str, port: int, timeout: int = 6) -> dict | None:
    proxy_url = f"http://{ip}:{port}"
    cmd = [
        "curl", "-s", "--connect-timeout", "3", "--max-time", str(timeout - 1),
        "-x", proxy_url, "http://ipinfo.io/json",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        if proc.returncode != 0 or not out:
            return None
        data = json.loads(out.decode())
        return data
    except Exception:
        return None


async def test_one(ip: str, port: int) -> dict | None:
    t0 = time.time()

    if not await tcp_check(ip, port, timeout=2):
        return None

    info = await http_test(ip, port, timeout=6)
    if not info:
        return None

    latency = round((time.time() - t0) * 1000)
    org = (info.get("org") or "").lower()
    ip_addr = info.get("ip", ip)

    port_tries[port] += 1
    port_hits[port] += 1

    return {
        "ip": ip_addr,
        "port": port,
        "proto": "http",
        "latency": latency,
        "isp": info.get("org", ""),
        "country": info.get("country", ""),
        "city": info.get("city", ""),
        "region": info.get("region", ""),
        "org": org,
    }


def best_ports(n: int = 10) -> list[int]:
    scored = [(p, port_hits.get(p, 0) / max(port_tries.get(p, 1), 1))
              for p in set(port_hits.keys()) | set(port_tries.keys())]
    scored.sort(key=lambda x: -x[1])
    return [p for p, _ in scored[:n]]


async def worker(q: asyncio.Queue, results: list):
    while True:
        try:
            ip, port = await asyncio.wait_for(q.get(), timeout=1)
        except asyncio.TimeoutError:
            continue
        try:
            result = await test_one(ip, port)
            results.append(result)
        finally:
            q.task_done()
