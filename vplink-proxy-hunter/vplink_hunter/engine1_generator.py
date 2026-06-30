"""Engine 1 — Smart IP Generator + Proxy List Scraper.

Generates random IP:port combos biased toward residential ISPs.
Bias port selection toward ports with proven hit rates from Engine 2."""

import asyncio
import random
import re
import subprocess

PROXY_PORTS = [
    80, 81, 443, 8080, 8081, 8443,
    3128, 3129, 3130,
    8888, 8889, 8899,
    9999, 9000, 9001, 9100,
    8000, 8001, 8008,
    1080, 1081, 10801,
    8118, 8181,
    9090, 9091,
    3690, 4145, 6588,
    10000, 10001, 11223,
    23652, 23756, 25461,
    27112, 28073,
    33333, 34445, 35555,
    36666, 37777, 38888,
    39999, 40000, 41114,
    42222, 43333, 44444,
    45555, 46666, 47777,
    48888, 49999, 50000,
    51111, 52222, 53333,
    54444, 55555, 56666,
    57777, 58888, 59999,
    60000, 61111, 62222,
    63333, 64444, 65535,
]

RES_FIRST_OCTETS = [
    1, 2, 4, 5, 8, 9, 12,
    14, 23, 24, 25, 27, 31, 32, 36, 37, 38, 39, 40, 41,
    42, 43, 45, 46, 47, 49, 50, 51, 52,
    56, 58, 59, 60, 61, 62, 63, 64, 65, 66,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
    87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
    97, 101, 102, 103, 105, 106, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120,
    121, 122, 123, 124, 125, 126, 128,
    160, 163, 164, 166, 176, 177, 178, 179, 180,
    181, 182, 183, 186, 187, 188, 189, 190, 191,
    196, 197, 200, 201, 202, 203, 210, 211, 212,
    213, 217, 218, 219, 220, 221, 222,
    223,
]

_biased_subnets: set[str] | None = None
_biased_subnet_pool: list[tuple[int, int, int, int]] | None = None
_working_ips: list[str] = []


def set_biased_subnets(subnets: set[str]):
    global _biased_subnets, _biased_subnet_pool
    _biased_subnets = subnets
    _biased_subnet_pool = None
    if subnets:
        pool = []
        for s in subnets:
            parts = s.split(".")
            if len(parts) == 2:
                try:
                    a, b = int(parts[0]), int(parts[1])
                    if a in RES_FIRST_OCTETS and 0 <= b <= 255:
                        pool.append((a, b, None, None))
                except ValueError:
                    pass
        _biased_subnet_pool = pool if pool else None


def set_working_ips(ips: list[str]):
    global _working_ips
    _working_ips = ips


BLOCKED_SUBNETS = [
    "0.",
    "10.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    # RFC 6598 Carrier-grade NAT
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
    # RFC 5735 / RFC 6890 special-purpose
    "192.0.0.", "192.0.2.", "192.88.99.",
    "198.18.", "198.19.", "198.51.100.",
    "203.0.113.",
    # DoD /8s — allocated but generally not publicly routable
    "6.", "7.", "11.", "21.", "22.",
    "26.", "28.", "29.", "30.", "33.",
    "48.", "53.", "57.",
    "214.", "215.",
    # Multicast + reserved
    "224.", "225.", "226.", "227.", "228.", "229.", "230.",
    "231.", "232.", "233.", "234.", "235.", "236.", "237.", "238.",
    "239.", "240.", "241.", "242.", "243.", "244.", "245.", "246.",
    "247.", "248.", "249.", "250.", "251.", "252.", "253.", "254.", "255.",
]

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d+)")

PROXY_SOURCES = [
    ("proxyscrape_http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"),
    ("speedx_http", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"),
    ("shifty_http", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"),
    ("jetkai_http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies_http.txt"),
    ("plist_http", "https://www.proxy-list.download/api/v1/get?type=http"),
]

_biased_ports = None


def set_biased_ports(ports: list[int]):
    global _biased_ports
    _biased_ports = ports


def _blocked_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in BLOCKED_SUBNETS)


def generate_ip() -> str:
    while True:
        # 60% from exact known-working IPs (try different ports/siblings)
        if _working_ips and random.random() < 0.6:
            ip = random.choice(_working_ips)
            if not _blocked_ip(ip):
                return ip
        # 30% from known /16 subnets
        if _biased_subnet_pool and random.random() < 0.3:
            a, b, _, _ = random.choice(_biased_subnet_pool)
        else:
            a = random.choice(RES_FIRST_OCTETS)
            b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(2, 253)
        ip = f"{a}.{b}.{c}.{d}"
        if not _blocked_ip(ip):
            return ip


_known_ip_port_idx: dict[str, int] = {}


def generate_port(ip: str = "") -> int:
    """Cycle ports in order for known IPs, random for unknown."""
    ports = _biased_ports if _biased_ports else PROXY_PORTS
    if ip in _working_ips:
        idx = _known_ip_port_idx.get(ip, 0)
        _known_ip_port_idx[ip] = (idx + 1) % len(ports)
        return ports[idx]
    return random.choice(ports)


def generate() -> tuple:
    ip = generate_ip()
    port = generate_port(ip)
    return ip, port


def reset_port_cycle():
    global _known_ip_port_idx
    _known_ip_port_idx = {}


def batch(count: int = 2000) -> list:
    return [generate() for _ in range(count)]


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
    """Fetch known working proxies from public lists."""
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
