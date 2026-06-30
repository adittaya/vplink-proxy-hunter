"""Engine 2 — Rapid Fire Tester.

Single-step TCP+HTTP via httpx async client.
No subprocess overhead, aggressive timeouts, crash-resistant workers."""

import asyncio
import time
from collections import defaultdict

import httpx

port_hits = defaultdict(int)
port_tries = defaultdict(int)


async def test_one(ip: str, port: int, timeout: float = 8.0) -> dict | None:
    t0 = time.time()
    port_tries[port] += 1
    proxy_url = f"http://{ip}:{port}"

    try:
        async with httpx.AsyncClient(
            proxies={"http://": proxy_url, "https://": proxy_url},
            timeout=httpx.Timeout(timeout, connect=3.0),
            follow_redirects=True,
        ) as client:
            resp = await client.get("http://ipinfo.io/json")
            if resp.status_code != 200:
                return None
            data = resp.json()
    except httpx.ConnectError:
        return None
    except httpx.ConnectTimeout:
        return None
    except httpx.ReadTimeout:
        return None
    except httpx.ProxyError:
        return None
    except Exception:
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
    """Consume IP:port from queue, test via httpx, append result."""
    while True:
        try:
            ip, port = await asyncio.wait_for(q.get(), timeout=1)
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
            q.task_done()
