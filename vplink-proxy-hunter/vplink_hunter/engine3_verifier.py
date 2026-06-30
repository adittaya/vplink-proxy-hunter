"""Engine 3 — VPLINK Verifier + Residential Detector.

Takes Engine 2 candidates, tests against VPLINK,
classifies as residential/datacenter, upserts to Supabase."""

import asyncio
import json
import re
import subprocess
import time

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


async def check_vplink(ip: str, port: int, timeout: int = 12) -> dict:
    """Test proxy against VPLINK. Returns {'ok': bool, 'detail': str}."""
    proxy_url = f"http://{ip}:{port}"
    cmd = [
        "curl", "-s", "-L", "--connect-timeout", "5", "--max-time", str(timeout),
        "-x", proxy_url,
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        VPLINK_TEST_URL,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        if proc.returncode not in (0, 22):
            return {"ok": False, "detail": "curl_failed"}
        if not out:
            return {"ok": False, "detail": "empty_response"}

        text = out.decode("utf-8", errors="replace")

        if VPN_DETECTED_PATTERNS.search(text):
            return {"ok": False, "detail": "vpn_detected"}

        if WORKING_PATTERNS.search(text) or len(text) > 500:
            return {"ok": True, "detail": "passed"}

        if len(text) < 200:
            return {"ok": False, "detail": "too_short"}

        return {"ok": False, "detail": "unknown"}
    except Exception:
        return {"ok": False, "detail": "exception"}


def classify(org: str) -> str:
    """Residential or datacenter based on org."""
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
