"""Engine 1 — Proxy List Scraper.

Fetches fresh proxy candidates from quality public sources."""

import asyncio
import re
import subprocess

BLOCKED_SUBNETS = [
    "0.",
    "10.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "100.64.", "100.65.", "100.66.", "100.67.", "100.68.", "100.69.",
    "100.70.", "100.71.", "100.72.", "100.73.", "100.74.", "100.75.",
    "100.76.", "100.77.", "100.78.", "100.79.", "100.80.", "100.81.",
    "100.82.", "100.83.", "100.84.", "100.85.", "100.86.", "100.87.",
    "100.88.", "100.89.", "100.90.", "100.91.", "100.92.", "100.93.",
    "100.94.", "100.95.", "100.96.", "100.97.", "100.98.", "100.99.",
    "100.100.", "100.101.", "100.102.", "100.103.", "100.104.", "100.105.",
    "100.106.", "100.107.", "100.108.", "100.109.", "100.110.", "100.111.",
    "100.112.", "100.113.", "100.114.", "100.115.", "100.116.", "100.117.",
    "100.118.", "100.119.", "100.120.", "100.121.", "100.122.", "100.123.",
    "100.124.", "100.125.", "100.126.", "100.127.",
    "192.0.0.", "192.0.2.", "192.88.99.",
    "198.18.", "198.19.", "198.51.100.",
    "203.0.113.",
    "6.", "7.", "11.", "21.", "22.",
    "26.", "28.", "29.", "30.", "33.",
    "48.", "53.", "57.",
    "214.", "215.",
    "224.", "225.", "226.", "227.", "228.", "229.", "230.",
    "231.", "232.", "233.", "234.", "235.", "236.", "237.", "238.",
    "239.", "240.", "241.", "242.", "243.", "244.", "245.", "246.",
    "247.", "248.", "249.", "250.", "251.", "252.", "253.", "254.", "255.",
]

PROXY_SOURCES = [
    ("proxyscrape_v4", "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text"),
    ("proxifly_http", "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt"),
    ("monosans_http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("proxripper_http", "https://raw.githubusercontent.com/mohammedcha/ProxRipper/main/full_proxies/http.txt"),
    ("proxygenerator_stable", "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/http.txt"),
    ("ianlusule_http", "https://raw.githubusercontent.com/Ian-Lusule/Proxies/main/proxies/http.txt"),
    ("vpslabcloud_http", "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt"),
    ("clearproxy_http", "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt"),
]
IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d+)")


def _blocked_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in BLOCKED_SUBNETS)


async def fetch_url(url: str, timeout: int = 10) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sL", "--max-time", str(timeout),
            url, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        return out.decode(errors="replace")
    except Exception:
        return ""


async def scrape_lists() -> list[tuple[str, int]]:
    seen = set()
    proxies = []

    async def fetch_source(name, url):
        text = await fetch_url(url)
        found = 0
        for match in IP_RE.finditer(text):
            ip, port_str = match.groups()
            port = int(port_str)
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                proxies.append((ip, port))
                found += 1
        return name, found

    tasks = [fetch_source(name, url) for name, url in PROXY_SOURCES]
    results = await asyncio.gather(*tasks)

    return proxies
