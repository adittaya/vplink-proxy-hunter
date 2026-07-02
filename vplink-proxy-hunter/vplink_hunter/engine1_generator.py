"""Engine 1 — Proxy List Scraper with source scoring.

Fetches fresh proxy candidates from quality public sources.
Tracks pass rate per source so low-quality lists get skipped automatically."""

import asyncio
import base64
import json
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
    ("solispi_http", "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt"),
    ("thespeedx_http", "https://raw.githubusercontent.com/TheSpeedX/proxy-list/master/http.txt"),
]
IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d+)")
PROXYDB_RE = re.compile(r'href="/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)#(http|https)"')
TOTAL_RE = re.compile(r"Showing \d+ to \d+ of (\d+) total")
def _js_arith(expr: str) -> int:
    expr = expr.strip()
    m = re.match(r'(\d+)\s*([+-])\s*(\d+)', expr)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        return a + b if op == '+' else a - b
    try:
        return int(expr)
    except ValueError:
        return 0

def _apply_methods(base: str, methods: str) -> str:
    while methods:
        m = re.match(r'\.substring\(([^,]+),\s*([^)]+)\)\s*(.*)', methods)
        if m:
            a, b = _js_arith(m.group(1)), _js_arith(m.group(2))
            base = base[a:b]
            methods = m.group(3).strip()
            continue
        m = re.match(r'\.repeat\((\d+)\)\s*(.*)', methods)
        if m:
            base = base * int(m.group(1))
            methods = m.group(2).strip()
            continue
        m = re.match(r'\.split\(""\)\.reverse\(\)\.join\(""\)\s*(.*)', methods)
        if m:
            base = base[::-1]
            methods = m.group(1).strip()
            continue
        m = re.match(r'\.concat\((.+)\)\s*(.*)', methods)
        if m:
            arg = m.group(1).strip()
            if arg.startswith('"') and arg.endswith('"'):
                base = base + arg[1:-1]
            else:
                base = base + _js_eval(arg)
            methods = m.group(2).strip()
            continue
        break
    return base


def _js_eval(expr: str) -> str:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    m = re.fullmatch(r'atob\("([^"]*)"\)', expr)
    if m:
        try:
            return base64.b64decode(m.group(1)).decode()
        except Exception:
            return ""
    m = re.fullmatch(
        r'\[([^\]]+)\]\.map\(\(([^)]+)\)\s*=>\s*String\.fromCharCode\(([^)]+)\)\)\.join\(""\)',
        expr,
    )
    if m:
        codes = [int(x.strip()) for x in m.group(1).split(',')]
        return ''.join(chr(c) for c in codes if 32 <= c <= 126)
    m = re.match(r'("[^"]*")(.*)', expr)
    if m:
        return _apply_methods(m.group(1)[1:-1], m.group(2).strip())
    m = re.match(r'\[([^\]]+)\](.*)', expr)
    if m:
        codes = [int(x.strip()) for x in m.group(1).split(',')]
        base = ''.join(chr(c) for c in codes if 32 <= c <= 126)
        return _apply_methods(base, m.group(2).strip())
    return expr

def _match_parens(text: str, start: int) -> int:
    count = 1
    for i in range(start, len(text)):
        if text[i] == '(':
            count += 1
        elif text[i] == ')':
            count -= 1
            if count == 0:
                return i
    return -1


def _valid_ip(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

# Source scoring — shared across the pipeline
# Format: {"source_name": {"total": int, "passed": int}}
SOURCE_STATS: dict[str, dict] = {}
MIN_PASS_RATE = 0.05
MIN_SAMPLES = 100


def should_skip_source(source: str) -> bool:
    stats = SOURCE_STATS.get(source)
    if not stats or stats["total"] < MIN_SAMPLES:
        return False
    rate = stats["passed"] / max(stats["total"], 1)
    return rate < MIN_PASS_RATE


def record_source_result(source: str, total: int, passed: int):
    if source not in SOURCE_STATS:
        SOURCE_STATS[source] = {"total": 0, "passed": 0}
    SOURCE_STATS[source]["total"] += total
    SOURCE_STATS[source]["passed"] += passed


def source_pass_rate(source: str) -> str:
    stats = SOURCE_STATS.get(source)
    if not stats or stats["total"] == 0:
        return "?/? (---)"
    return f"{stats['passed']}/{stats['total']} ({stats['passed']/stats['total']*100:.0f}%)"


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


async def scrape_proxydb(max_pages: int = 10) -> list[tuple[str, int, str]]:
    """Scrape proxydb.net with pagination, HTTP/HTTPS only."""
    source = "proxydb"
    results = []
    base = "https://proxydb.net/?protocol=http&offset="
    first = await fetch_url(base + "0")
    if not first:
        return results

    total_match = TOTAL_RE.search(first)
    total_proxies = int(total_match.group(1)) if total_match else 0
    total_pages = min(max_pages, (total_proxies + 29) // 30)

    seen = set()
    for match in PROXYDB_RE.finditer(first):
        ip, port_str, _ = match.groups()
        port = int(port_str)
        key = (ip, port)
        if key not in seen and not _blocked_ip(ip):
            seen.add(key)
            results.append((ip, port, source))

    for page in range(1, total_pages):
        await asyncio.sleep(0.5)
        text = await fetch_url(f"{base}{page * 30}")
        if not text:
            continue
        for match in PROXYDB_RE.finditer(text):
            ip, port_str, _ = match.groups()
            port = int(port_str)
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                results.append((ip, port, source))

    return results


async def scrape_geonode(max_pages: int = 3) -> list[tuple[str, int, str]]:
    """Scrape geonode free proxy list via their public API."""
    source = "geonode"
    results = []
    base = "https://proxylist.geonode.com/api/proxy-list?limit=500&sort_by=responseTime&sort_type=asc&page="
    text = await fetch_url(base + "1", timeout=15)
    if not text:
        return results

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return results

    total = data.get("total", 0)
    total_pages = min(max_pages, (total + 499) // 500)

    seen = set()
    for page in range(1, total_pages + 1):
        if page > 1:
            await asyncio.sleep(0.3)
            text = await fetch_url(f"{base}{page}", timeout=15)
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue

        for proxy in data.get("data", []):
            protocols = proxy.get("protocols", [])
            if not any(p in protocols for p in ("http", "https")):
                continue
            ip = proxy.get("ip", "")
            port = int(proxy.get("port", 0))
            if port == 0:
                continue
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                results.append((ip, port, source))

    return results


async def scrape_proxynova() -> list[tuple[str, int, str]]:
    """Scrape ProxyNova HTML table with JS-obfuscated IPs.

    ProxyNova obfuscates IPs with document.write() using patterns like:
      atob(), .substring(), .repeat(), .split().reverse().join(), .map()."""
    source = "proxynova"
    results = []
    text = await fetch_url("https://www.proxynova.com/proxy-server-list/", timeout=15)
    if not text:
        return results

    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL)
    seen = set()
    for row in rows:
        tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(tds) < 2:
            continue
        ip_cell, port_cell = tds[0], tds[1]
        ip = None
        m = re.search(
            r'<abbr title="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.', ip_cell,
        )
        if m and _valid_ip(m.group(1)):
            ip = m.group(1)
        else:
            dw_start = ip_cell.find("document.write(")
            if dw_start >= 0:
                paren = dw_start + len("document.write(")
                end = _match_parens(ip_cell, paren)
                if end >= 0:
                    expr = ip_cell[paren:end]
                    result = _js_eval(expr)
                    for m2 in re.finditer(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result,
                    ):
                        if _valid_ip(m2.group(1)):
                            ip = m2.group(1)
                            break
                    if not ip:
                        for m2 in re.finditer(
                            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expr,
                        ):
                            if _valid_ip(m2.group(1)):
                                ip = m2.group(1)
                                break
        if not ip or _blocked_ip(ip):
            continue
        port_m = re.search(r'>(\d{2,5})<', port_cell)
        if not port_m:
            continue
        port = int(port_m.group(1))
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            results.append((ip, port, source))

    return results


async def scrape_fpln() -> list[tuple[str, int, str]]:
    """Scrape free-proxy-list.net, us-proxy.org, sslproxies.org HTML tables.

    These sites share the same table structure and list hundreds of proxies."""
    source = "fpln"
    results = []
    urls = [
        "https://free-proxy-list.net/",
        "https://www.us-proxy.org/",
        "https://www.sslproxies.org/",
    ]
    seen = set()
    for url in urls:
        text = await fetch_url(url, timeout=15)
        if not text:
            continue
        ips = re.findall(
            r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>\s*<td>(\d+)</td>',
            text,
        )
        for ip, port_str in ips:
            port = int(port_str)
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                results.append((ip, port, source))
    return results


async def scrape_lists() -> list[tuple[str, int, str]]:
    """Fetch from all sources, skip low-quality lists.

    Returns (ip, port, source_name) tuples in source order
    (newest/freshest first from each source)."""
    seen = set()
    proxies: list[tuple[str, int, str]] = []

    async def fetch_source(name, url):
        if should_skip_source(name):
            return name, 0
        text = await fetch_url(url)
        found = 0
        for match in IP_RE.finditer(text):
            ip, port_str = match.groups()
            port = int(port_str)
            key = (ip, port)
            if key not in seen and not _blocked_ip(ip):
                seen.add(key)
                proxies.append((ip, port, name))
                found += 1
        return name, found

    tasks = [fetch_source(name, url) for name, url in PROXY_SOURCES]
    await asyncio.gather(*tasks)

    if not should_skip_source("proxydb"):
        pd = await scrape_proxydb()
        for item in pd:
            key = (item[0], item[1])
            if key not in seen:
                seen.add(key)
                proxies.append(item)

    if not should_skip_source("geonode"):
        gn = await scrape_geonode()
        for item in gn:
            key = (item[0], item[1])
            if key not in seen:
                seen.add(key)
                proxies.append(item)

    if not should_skip_source("proxynova"):
        pn = await scrape_proxynova()
        for item in pn:
            key = (item[0], item[1])
            if key not in seen:
                seen.add(key)
                proxies.append(item)

    if not should_skip_source("fpln"):
        fpl = await scrape_fpln()
        for item in fpl:
            key = (item[0], item[1])
            if key not in seen:
                seen.add(key)
                proxies.append(item)

    return proxies
