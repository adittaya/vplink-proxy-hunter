"""Engine 3 — VPLINK Verifier + Residential Detector.

Uses curl via subprocess for reliable CONNECT tunnel + TLS handling.
Avoids httpx proxy configuration incompatibilities across versions."""

import asyncio
import re
import signal
import subprocess

# Track running curl processes so we can kill them on shutdown
_curl_procs: set[asyncio.subprocess.Process] = set()

DATACENTER_ORGS = re.compile(
    r"alibaba|amazon|google|hetzner|ovh|digitalocean|vultr|"
    r"linode|microsoft|oracle|ibm|rackspace|softlayer|scaleway|"
    r"contabo|netcup|cogent|datacamp|zenlayer|psychz|gige|choopa|"
    r"sharktech|cloudflare|vps\b|dedicated|hosting|colocrossing|"
    r"theplanet|leaseweb|akamai|stackpath|oneprovider|worldstream|"
    r"buyvm|snel|racknerd|hostiger|nfry|serverel|choopa|zare|"
    r"tencent|dpkgsoft|m247|mevspace|terrahost|"
    r"datapacket|multacom|crosslayer|hosthat|astrohost|"
    r"gcore|lansrv|hitron|voxility|datawise|"
    r"firstheberg|starline|develapp|itltd|zenex|"
    r"naver[^a-z]|nhn\s|kakao\s|kt\s*cloud|lg.?cns|"
    r"ionos|hostinger|hostgator|bluehost|godaddy|dreamhost|"
    r"a2\s*hosting|siteground|inmotion|liquid.?web|"
    r"kinsta|wp.?engine|namecheap|hostarmada|kamatera|"
    r"interserver|cloudways|greengeeks|scalahosting|"
    r"fastcomet|chemicloud|tmdhosting|verpex|servers\.com|"
    r"phoenixnap|hivelocity|hostwinds|hostpapa|"
    r"coreweave|equinix|digital.?realty|flexential|"
    r"cyxtera|vapor.?io|iron.?mountain"
)

def cleanup_subprocesses():
    """Kill any leftover curl processes (call before event loop closes)."""
    for proc in list(_curl_procs):
        if proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass
    _curl_procs.clear()


VPLINK_TEST_URL = "https://vplink.in/UbpV2D"
VPN_DETECTED_PATTERNS = re.compile(
    r"vpn\s*detected|proxy\s*detected|access\s*denied|blocked|"
    r"your\s*ip\s*has\s*been|suspicious\s*activity",
    re.IGNORECASE,
)
WORKING_PATTERNS = re.compile(
    r"Please Wait|Opening Link|whatsgrouphub|click here|"
    r"window\.location|Continue",
)


async def _curl_get(url: str, proxy: str, timeout: int = 12) -> str | None:
    """Fetch URL through proxy via curl subprocess."""
    cmd = [
        "curl", "-sL", "--max-time", str(timeout),
        "-x", proxy,
        url,
    ]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        _curl_procs.add(proc)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        if proc.returncode != 0 or not out:
            return None
        return out.decode(errors="replace")
    except Exception:
        return None
    finally:
        if proc:
            _curl_procs.discard(proc)
            if proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass


async def check_vplink(ip: str, port: int, timeout: float = 10.0) -> dict:
    """Test proxy against VPLINK via curl subprocess.
    
    Uses curl -x through the proxy for reliable CONNECT tunnel + TLS.
    Avoids httpx proxy configuration incompatibilities across versions.
    Returns {'ok': bool, 'detail': str}."""
    proxy_url = f"http://{ip}:{port}"
    text = await _curl_get(VPLINK_TEST_URL, proxy_url, timeout=int(timeout))

    if text is None:
        return {"ok": False, "detail": "curl_failed"}

    if not text:
        return {"ok": False, "detail": "empty_response"}

    if VPN_DETECTED_PATTERNS.search(text):
        return {"ok": False, "detail": "vpn_detected"}

    if WORKING_PATTERNS.search(text) or len(text) > 500:
        return {"ok": True, "detail": "passed"}

    if len(text) < 200:
        return {"ok": False, "detail": "too_short"}

    return {"ok": False, "detail": "unknown_pattern"}


def classify(org: str) -> str:
    return "datacenter" if DATACENTER_ORGS.search(org.lower()) else "residential"


async def verify(candidate: dict, do_vplink: bool = True) -> dict | None:
    """Engine 3: verify candidate → return dict or None."""
    vplink_result = {"ok": False, "detail": "skipped"}

    if do_vplink:
        vplink_result = await check_vplink(candidate["ip"], candidate["port"])
        if not vplink_result["ok"]:
            return None
    else:
        vplink_result["ok"] = True

    proxy_type = classify(candidate.get("org", ""))

    return {
        "ip": candidate["ip"],
        "port": candidate["port"],
        "proto": "http",
        "latency": candidate["latency"],
        "type": proxy_type,
        "isp": candidate.get("isp", ""),
        "country": candidate.get("country", ""),
        "city": candidate.get("city", ""),
        "region": candidate.get("region", ""),
        "vplink_ok": vplink_result["ok"],
    }
