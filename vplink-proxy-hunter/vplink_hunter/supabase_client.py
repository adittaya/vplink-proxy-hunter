import asyncio
import functools
import sys
from datetime import datetime, timezone
from supabase import create_client, Client

_client = None


def _log(msg):
    sys.stderr.write(f"[supabase] {msg}\n")
    sys.stderr.flush()


def init(url: str, key: str) -> Client:
    global _client
    if not url or not key:
        _log("missing url or key")
        return None
    _client = create_client(url, key)
    _log(f"initialized: url={url[:30]}... key={key[:20]}...")
    return _client


def get() -> Client:
    return _client


def upsert_proxy(proxy: dict, retries: int = 3):
    if not _client:
        _log("client not initialized")
        return
    row = {
        "ip": proxy["ip"],
        "port": proxy["port"],
        "proto": proxy.get("proto", "http"),
        "latency_ms": proxy.get("latency", 0),
        "type": proxy.get("type", "unknown"),
        "isp": proxy.get("isp", ""),
        "country": proxy.get("country", ""),
        "city": proxy.get("city", ""),
        "region": proxy.get("region", ""),
        "vplink_ok": proxy.get("vplink_ok", False),
        "e2_ok": proxy.get("e2_ok", True),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    for attempt in range(retries):
        try:
            _client.table("proxy_results").upsert(
                row,
                on_conflict="ip,port",
            ).execute()
            return
        except Exception as e:
            if attempt < retries - 1:
                import time as _time
                _time.sleep(0.5 * (attempt + 1))
            else:
                _log(f"upsert error after {retries} attempts: {e}")


def get_proxy(ip: str, port: int) -> dict | None:
    if not _client:
        return None
    try:
        resp = _client.table("proxy_results").select("*").eq("ip", ip).eq("port", port).execute()
        if resp.data:
            return resp.data[0]
    except Exception:
        pass
    return None


def list_proxies(type_filter: str | None = None, vplink_only: bool = False,
                 limit: int = 50, offset: int = 0) -> list:
    if not _client:
        return []
    try:
        q = _client.table("proxy_results").select("*")
        if type_filter:
            q = q.eq("type", type_filter)
        if vplink_only:
            q = q.eq("vplink_ok", True)
        resp = q.order("last_seen", desc=True).range(offset, offset + limit - 1).execute()
        return resp.data
    except Exception:
        return []


def list_proxies_by_ip(ip: str) -> list:
    if not _client:
        return []
    try:
        resp = _client.table("proxy_results").select("*").eq("ip", ip).execute()
        return resp.data
    except Exception:
        return []


def delete_proxy(ip: str, port: int) -> bool:
    if not _client:
        return False
    try:
        _client.table("proxy_results").delete().eq("ip", ip).eq("port", port).execute()
        return True
    except Exception:
        return False


def get_stats() -> dict:
    if not _client:
        return {}
    try:
        all_ = _client.table("proxy_results").select("*").execute()
        total = len(all_.data)
        residential = sum(1 for r in all_.data if r.get("type") == "residential")
        datacenter = sum(1 for r in all_.data if r.get("type") == "datacenter")
        vplink_ok = sum(1 for r in all_.data if r.get("vplink_ok"))
        unknown = sum(1 for r in all_.data if r.get("type") == "unknown")
        return {
            "total": total,
            "residential": residential,
            "datacenter": datacenter,
            "vplink_ok": vplink_ok,
            "unknown": unknown,
        }
    except Exception:
        return {}


def get_counts() -> dict:
    """Fast COUNT queries for dashboard totals."""
    if not _client:
        return {"total": 0, "e2_ok": 0, "vplink_ok": 0, "residential": 0}
    try:
        total = _client.table("proxy_results").select("count", count="exact").execute()
        e2 = _client.table("proxy_results").select("count", count="exact").eq("e2_ok", True).execute()
        vp = _client.table("proxy_results").select("count", count="exact").eq("vplink_ok", True).execute()
        res = _client.table("proxy_results").select("count", count="exact").eq("type", "residential").execute()
        return {
            "total": total.count if total.count else 0,
            "e2_ok": e2.count if e2.count else 0,
            "vplink_ok": vp.count if vp.count else 0,
            "residential": res.count if res.count else 0,
        }
    except Exception:
        return {"total": 0, "e2_ok": 0, "vplink_ok": 0, "residential": 0}


def update_stats(scanned: int, found: int, residential: int, dc: int):
    if not _client:
        return
    try:
        _client.rpc("update_scan_stats", {
            "p_scanned": scanned,
            "p_found": found,
            "p_residential": residential,
            "p_datacenter": dc,
        }).execute()
    except Exception:
        pass


async def async_upsert_proxy(proxy: dict, retries: int = 3):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, functools.partial(upsert_proxy, proxy, retries))


def get_successful_subnets() -> set[str]:
    """Return set of 'A.B' /16 subnets from proxies that passed E2."""
    if not _client:
        return set()
    try:
        resp = _client.table("proxy_results").select("ip").eq("e2_ok", True).execute()
        subnets: set[str] = set()
        for row in resp.data:
            parts = row["ip"].split(".")
            if len(parts) >= 2:
                subnets.add(f"{parts[0]}.{parts[1]}")
        return subnets
    except Exception:
        return set()


def get_working_ips() -> list[str]:
    """Return list of exact IPs that passed E2 (no duplicates)."""
    if not _client:
        return []
    try:
        resp = _client.table("proxy_results").select("ip").eq("e2_ok", True).execute()
        seen: set[str] = set()
        ips: list[str] = []
        for row in resp.data:
            ip = row["ip"]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except Exception:
        return []


def get_dc_ips() -> set[str]:
    """Return set of IPs classified as datacenter."""
    if not _client:
        return set()
    try:
        resp = _client.table("proxy_results").select("ip").eq("type", "datacenter").execute()
        return {row["ip"] for row in (resp.data or [])}
    except Exception:
        return set()


async def async_get_subnets() -> set[str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_successful_subnets)


async def async_get_proxy(ip: str, port: int) -> dict | None:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(get_proxy, ip, port))


def reclassify_all(classify_fn):
    """Re-check all DB records using a classify(ip, org) function.
    
    Classify_fn takes (ip, org) and returns 'residential' or 'datacenter'.
    Records that change type are updated; datacenter records are deleted.
    Returns (updated, deleted).
    """
    if not _client:
        return (0, 0)
    try:
        resp = _client.table("proxy_results").select("ip,port,type,isp").execute()
        rows = resp.data or []
    except Exception:
        return (0, 0)

    updated = 0
    deleted = 0
    for row in rows:
        new_type = classify_fn(row["ip"], row.get("isp", ""))
        if new_type == "datacenter":
            try:
                _client.table("proxy_results").delete().eq("ip", row["ip"]).eq("port", row["port"]).execute()
                deleted += 1
            except Exception:
                pass
        elif new_type != row.get("type"):
            try:
                _client.table("proxy_results").update({"type": new_type}).eq("ip", row["ip"]).eq("port", row["port"]).execute()
                updated += 1
            except Exception:
                pass
    return (updated, deleted)
