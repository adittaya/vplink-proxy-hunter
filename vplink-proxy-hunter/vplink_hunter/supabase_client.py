from supabase import create_client, Client

_client = None


def init(url: str, key: str) -> Client:
    global _client
    if not url or not key:
        print("  [!] Supabase init: missing url or key")
        return None
    _client = create_client(url, key)
    return _client


def get() -> Client:
    return _client


def upsert_proxy(proxy: dict):
    if not _client:
        print("  [!] upsert: client not initialized")
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
        "last_seen": "now()",
    }
    try:
        _client.table("proxy_results").upsert(
            row,
            on_conflict="ip,port",
        ).execute()
    except Exception as e:
        print(f"  [!] upsert error: {e}")


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
