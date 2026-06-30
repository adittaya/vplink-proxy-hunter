"""Engine 3 — VPLINK Verifier + Residential Detector.

httpx async client replaces curl subprocess.
Proper timeout handling, crash-resistant, no fork overhead."""

import asyncio
import re

import httpx

DATACENTER_ORGS = re.compile(
    r"alibaba|amazon|google|hetzner|ovh|digitalocean|vultr|"
    r"linode|microsoft|oracle|ibm|rackspace|softlayer|scaleway|"
    r"contabo|netcup|cogent|datacamp|zenlayer|psychz|gige|choopa|"
    r"sharktech|cloudflare|vps|dedicated|hosting|colocrossing|"
    r"theplanet|leaseweb|akamai|stackpath|oneprovider|worldstream|"
    r"buyvm|snel|racknerd|hostiger|nfry|serverel|choopa|zare"
)

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


async def check_vplink(ip: str, port: int, timeout: float = 10.0) -> dict:
    """Test proxy against VPLINK via httpx. Returns {'ok': bool, 'detail': str}."""
    proxy_url = f"http://{ip}:{port}"

    try:
        async with httpx.AsyncClient(
            proxies={"http://": proxy_url, "https://": proxy_url},
            timeout=httpx.Timeout(timeout, connect=5.0),
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                VPLINK_TEST_URL,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36"
                },
            )
            text = resp.text
    except httpx.ConnectError:
        return {"ok": False, "detail": "connect_failed"}
    except httpx.ConnectTimeout:
        return {"ok": False, "detail": "connect_timeout"}
    except httpx.ReadTimeout:
        return {"ok": False, "detail": "read_timeout"}
    except httpx.ProxyError:
        return {"ok": False, "detail": "proxy_error"}
    except httpx.HTTPStatusError:
        return {"ok": False, "detail": "http_error"}
    except Exception:
        return {"ok": False, "detail": "unknown"}

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
