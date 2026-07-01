"""Engine 2 — Rapid Fire Tester.

Raw asyncio socket HTTP through proxy.
Concurrent port scanning per IP — tests all 19 ports at once."""

import asyncio
import json
import time
from collections import defaultdict

from .engine1_generator import PROXY_PORTS, get_biased_ports

port_hits = defaultdict(int)
port_tries = defaultdict(int)
_ipinfo_cache: dict[str, dict] = {}

_HTTP_GET_TPL = (
    "GET http://ipinfo.io/json HTTP/1.1\r\n"
    "Host: ipinfo.io\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    "Accept: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
)


async def _check_https_connect(ip: str, port: int) -> bool:
    """Quick check: can this proxy establish an HTTPS CONNECT tunnel?"""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3
        )
        writer.write(
            b"CONNECT httpbin.org:443 HTTP/1.1\r\n"
            b"Host: httpbin.org:443\r\n"
            b"Connection: close\r\n\r\n"
        )
        await asyncio.wait_for(writer.drain(), timeout=2)
        resp = await asyncio.wait_for(reader.read(256), timeout=3)
        return b"200" in resp
    except Exception:
        return False
    finally:
        try:
            if writer:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass


async def test_one(ip: str, port: int) -> dict | None:
    t0 = time.time()
    port_tries[port] += 1

    # Pre-check: HTTPS CONNECT (filter out HTTP-only proxies early)
    if not await _check_https_connect(ip, port):
        return None

    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3
        )
    except (asyncio.TimeoutError, OSError, Exception):
        return None

    # Use cached ipinfo data if available (same IP, different port)
    if ip in _ipinfo_cache:
        data = _ipinfo_cache[ip]
        latency = round((time.time() - t0) * 1000)
        port_hits[port] += 1
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "ip": ip, "port": port, "proto": "http", "latency": latency,
            "isp": data.get("org", ""), "country": data.get("country", ""),
            "city": data.get("city", ""), "region": data.get("region", ""),
            "org": (data.get("org") or "").lower(),
        }

    try:
        writer.write(_HTTP_GET_TPL.encode())
        await asyncio.wait_for(writer.drain(), timeout=2)

        response = b""
        deadline = time.time() + 4
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(
                reader.read(4096), timeout=min(remaining, 2)
            )
            if not chunk:
                break
            response += chunk
    except (asyncio.TimeoutError, Exception):
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    try:
        header_end = response.index(b"\r\n\r\n")
        headers_raw = response[:header_end].decode(errors="replace")
        body = response[header_end + 4:]

        status_line = headers_raw.split("\r\n")[0] if headers_raw else ""
        if "200" not in status_line:
            return None

        data = json.loads(body.decode(errors="replace"))
    except (ValueError, json.JSONDecodeError, IndexError):
        return None

    latency = round((time.time() - t0) * 1000)
    org = (data.get("org") or "").lower()
    ip_addr = data.get("ip", ip)
    _ipinfo_cache[ip_addr] = data

    port_hits[port] += 1

    return {
        "ip": ip_addr,
        "port": port,
        "proto": "http",
        "latency": latency,
        "isp": data.get("org", ""),
        "country": data.get("country", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "org": org,
    }


def best_ports(n: int = 10) -> list[int]:
    scored = [(p, port_hits.get(p, 0) / max(port_tries.get(p, 1), 1))
              for p in set(port_hits.keys()) | set(port_tries.keys())]
    scored.sort(key=lambda x: -x[1])
    return [p for p, _ in scored[:n]]


async def test_ip(ip: str) -> list[dict]:
    """Test all ports for an IP concurrently, return all working results."""
    ports = get_biased_ports()
    tasks = [asyncio.create_task(test_one(ip, port)) for port in ports]
    done, _ = await asyncio.wait(tasks, timeout=15, return_when=asyncio.ALL_COMPLETED)
    results = []
    for t in done:
        r = t.result()
        if r:
            results.append(r)
    return results


async def worker(q: asyncio.Queue, results: list, ready_event: asyncio.Event):
    """Consume IP from queue, test all ports concurrently, append results."""
    while True:
        got_item = False
        try:
            ip = await asyncio.wait_for(q.get(), timeout=1)
            got_item = True
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        try:
            working = await test_ip(ip)
            for result in working:
                results.append(result)
                ready_event.set()
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        finally:
            if got_item:
                q.task_done()
