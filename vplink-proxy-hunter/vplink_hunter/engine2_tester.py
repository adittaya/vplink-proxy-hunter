"""Engine 2 — Rapid Fire Tester.

Raw asyncio socket HTTP through proxy.
Concurrent port scanning per IP — tests all 19 ports at once."""

import asyncio
import ipaddress
import json
import socket
import time
from collections import defaultdict

from .engine3_verifier import DATACENTER_CIDRS

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


async def _connect(ip: str, port: int, timeout: float = 0.5) -> tuple | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 2)
    except (OSError, AttributeError):
        pass
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            loop.sock_connect(sock, (ip, port)), timeout=timeout
        )
        reader, writer = await asyncio.open_connection(sock=sock)
        return reader, writer
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


async def _check_https_connect(ip: str, port: int) -> bool:
    """Quick check: can this proxy establish an HTTPS CONNECT tunnel?"""
    conn = await _connect(ip, port, timeout=0.5)
    if conn is None:
        return False
    reader, writer = conn
    try:
        writer.write(
            b"CONNECT httpbin.org:443 HTTP/1.1\r\n"
            b"Host: httpbin.org:443\r\n"
            b"Connection: close\r\n\r\n"
        )
        await asyncio.wait_for(writer.drain(), timeout=1)
        resp = await asyncio.wait_for(reader.read(256), timeout=1)
        return b"200" in resp
    except Exception:
        return False
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def test_one(ip: str, port: int) -> dict | None:
    t0 = time.time()
    port_tries[port] += 1

    if not await _check_https_connect(ip, port):
        return None

    conn = await _connect(ip, port, timeout=0.5)
    if conn is None:
        return None
    reader, writer = conn

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
        await asyncio.wait_for(writer.drain(), timeout=1)

        response = b""
        deadline = time.time() + 1
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(
                reader.read(4096), timeout=min(remaining, 0.5)
            )
            if not chunk:
                break
            response += chunk
    except (asyncio.TimeoutError, Exception):
        return None
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
            try:
                await writer.wait_closed()
            except (Exception, asyncio.CancelledError):
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


def _ip_in_dc_cidr(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for net in DATACENTER_CIDRS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


async def test_ip(ip: str, primary_port: int) -> dict | None:
    if _ip_in_dc_cidr(ip):
        return None
    return await test_one(ip, primary_port)


async def worker(q: asyncio.Queue, results: list, ready_event: asyncio.Event):
    """Consume (ip, port) from queue, test the port, append result if working."""
    while True:
        got_item = False
        try:
            ip_port = await asyncio.wait_for(q.get(), timeout=1)
            got_item = True
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        try:
            ip, port = ip_port
            result = await test_ip(ip, port)
            if result:
                results.append(result)
                ready_event.set()
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        finally:
            if got_item:
                q.task_done()
