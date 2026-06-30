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

DC_FIRST_OCTETS = {
    3, 13, 15, 16, 17, 18, 19, 20, 34, 35,
    44, 52, 54, 55, 56, 98, 99, 100, 104, 107,
    108, 129, 130, 131, 132, 133, 134, 135, 136,
    137, 138, 139, 140, 141, 142, 143, 144, 145,
    146, 147, 148, 149, 150, 151, 152, 153, 154,
    155, 156, 157, 158, 159, 161, 162, 165, 167,
    168, 169, 170, 171, 172, 173, 174, 175, 184,
    185, 192, 193, 194, 195, 198, 199, 204, 205,
    206, 207, 208, 209, 216,
}

RES_FIRST_OCTETS = [
    1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    14, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30, 31, 32, 33, 36, 37, 38, 39, 40, 41,
    42, 43, 45, 46, 47, 48, 49, 50, 51, 53,
    57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
    87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
    97, 101, 102, 103, 105, 106, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120,
    121, 122, 123, 124, 125, 126, 127, 128,
    160, 163, 164, 166, 176, 177, 178, 179, 180,
    181, 182, 183, 186, 187, 188, 189, 190, 191,
    196, 197, 200, 201, 202, 203, 210, 211, 212,
    213, 214, 215, 217, 218, 219, 220, 221, 222,
    223,
]

_WEIGHTS = [10 if o in RES_FIRST_OCTETS else 1 for o in range(1, 224)]
_WEIGHTS = _WEIGHTS[:223]

BLOCKED_SUBNETS = [
    "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "224.", "225.", "226.", "227.", "228.", "229.", "230.",
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
        a = random.choices(range(1, 224), weights=_WEIGHTS, k=1)[0]
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(2, 253)
        ip = f"{a}.{b}.{c}.{d}"
        if not _blocked_ip(ip):
            return ip


_biased_ports_cache = None


def generate_port():
    global _biased_ports_cache
    ports = _biased_ports if _biased_ports else PROXY_PORTS
    _biased_ports_cache = ports
    return random.choice(ports)


def generate() -> tuple:
    return generate_ip(), generate_port()


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
