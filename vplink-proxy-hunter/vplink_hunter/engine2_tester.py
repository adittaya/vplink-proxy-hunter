"""Engine 2 — Rapid Fire Tester.

Raw asyncio socket HTTP through proxy.
No subprocess, no httpx dependency — pure async IO with full control."""

import asyncio
import json
import time
from collections import defaultdict

port_hits = defaultdict(int)
port_tries = defaultdict(int)

_HTTP_GET_TPL = (
    "GET http://ipinfo.io/json HTTP/1.1\r\n"
    "Host: ipinfo.io\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    "Accept: application/json\r\n"
    "Connection: close\r\n"
    "\r\n"
)


async def test_one(ip: str, port: int) -> dict | None:
    t0 = time.time()
    port_tries[port] += 1

    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=4
        )
    except asyncio.TimeoutError:
        return None
    except OSError:
        return None
    except Exception:
        return None

    try:
        writer.write(_HTTP_GET_TPL.encode())
        await asyncio.wait_for(writer.drain(), timeout=3)

        response = b""
        deadline = time.time() + 5
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
    except asyncio.TimeoutError:
        return None
    except Exception:
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


async def worker(q: asyncio.Queue, results: list, ready_event: asyncio.Event):
    """Consume IP:port from queue, test via raw socket, append result."""
    while True:
        got_item = False
        try:
            ip, port = await asyncio.wait_for(q.get(), timeout=1)
            got_item = True
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        try:
            result = await test_one(ip, port)
            results.append(result)
            ready_event.set()
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        finally:
            if got_item:
                q.task_done()
