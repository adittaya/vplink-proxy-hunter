#!/usr/bin/env python3
"""
proxy_finder.py — 3 wild engines, no external lists, pure brute force random.

  Engine 1: IP Generator   → spawns IP:port combos from real country distros
  Engine 2: Rapid Fire      → async TCP + curl, 80 workers
  Engine 3: Deep Verifier   → triple-checks & residential detection
"""

import asyncio
import json
import os
import random
import subprocess
import sys
import time

PROXY_PORTS = [80, 81, 3128, 3129, 8080, 8081, 8888, 9999, 9000, 10000,
               1080, 1081, 10801, 8118, 8000, 8443, 9090, 3690, 4145, 6588]

COUNTRY_PREFIXES = {
    "US": [(4, 8), (12, 15), (23, 23), (24, 47), (50, 81), (96, 99), (104, 107)],
    "GB": [(82, 90), (92, 94), (109, 109), (146, 147), (148, 149), (151, 152)],
    "DE": [(2, 3), (77, 80), (84, 87), (141, 143), (144, 145), (146, 147)],
    "NL": [(80, 83), (84, 85), (87, 89), (141, 141), (145, 145), (188, 188)],
    "FR": [(80, 94), (109, 109), (176, 178), (193, 193), (194, 194)],
    "RU": [(31, 31), (37, 37), (46, 46), (62, 62), (77, 95), (109, 109), (128, 159), (176, 176), (178, 178), (185, 185), (188, 188), (193, 195), (212, 213), (217, 217)],
    "BR": [(17, 19), (138, 139), (152, 152), (177, 179), (187, 189), (191, 191)],
    "IN": [(1, 6), (14, 14), (27, 29), (43, 43), (49, 49), (59, 59), (103, 126), (163, 175), (180, 183), (202, 223)],
    "ID": [(36, 39), (101, 125), (128, 160), (175, 203), (210, 212)],
    "VN": [(1, 1), (14, 14), (27, 27), (42, 42), (58, 59), (101, 126), (128, 160), (171, 176), (183, 183), (203, 203), (210, 211)],
}

PREFIX_KEYS = list(COUNTRY_PREFIXES.keys())

_BLOCKED = [
    "0.", "10.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "100.64.", "100.65.", "100.66.", "100.67.", "100.68.",
    "100.69.", "100.70.", "100.71.", "100.72.", "100.73.", "100.74.",
    "100.75.", "100.76.", "100.77.", "100.78.", "100.79.", "100.80.",
    "100.81.", "100.82.", "100.83.", "100.84.", "100.85.", "100.86.",
    "100.87.", "100.88.", "100.89.", "100.90.", "100.91.", "100.92.",
    "100.93.", "100.94.", "100.95.", "100.96.", "100.97.", "100.98.",
    "100.99.", "100.100.", "100.101.", "100.102.", "100.103.", "100.104.",
    "100.105.", "100.106.", "100.107.", "100.108.", "100.109.", "100.110.",
    "100.111.", "100.112.", "100.113.", "100.114.", "100.115.", "100.116.",
    "100.117.", "100.118.", "100.119.", "100.120.", "100.121.", "100.122.",
    "100.123.", "100.124.", "100.125.", "100.126.", "100.127.",
    "192.0.0.", "192.0.2.", "192.88.99.", "198.18.", "198.19.", "198.51.100.",
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


def _blocked_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _BLOCKED)


DATACENTER_ORGS = [
    "alibaba", "amazon", "google", "hetzner", "ovh", "digitalocean", "vultr",
    "linode", "microsoft", "oracle", "ibm", "rackspace", "softlayer", "scaleway",
    "contabo", "netcup", "cogent", "datacamp", "zenlayer", "psychz",
    "gige", "choopa", "sharktech", "cloudflare", "vps", "dedicated", "hosting",
    "colocrossing", "theplanet", "leaseweb", "akamai", "incapsula", "stackpath",
    "oneprovider", "worldstream", "buyvm", "snel", "racknerd", "hostiger",
    "tencent", "dpkgsoft", "m247", "mevspace", "terrahost",
    "datapacket", "multacom", "crosslayer", "hosthat", "astrohost",
    "gcore", "lansrv", "hitron", "voxility", "datawise",
    "firstheberg", "starline", "develapp", "itltd", "zenex",
    "naver business", "naver cloud", "nhn", "kakao", "kt cloud",
    "ionos", "hostinger", "hostgator", "bluehost", "godaddy", "dreamhost",
    "a2 hosting", "siteground", "inmotion", "liquid web",
    "kinsta", "wp engine", "namecheap", "hostarmada", "kamatera",
    "interserver", "cloudways", "greengeeks", "scalahosting",
    "fastcomet", "chemicloud", "tmdhosting", "verpex", "servers.com",
    "phoenixnap", "hivelocity", "hostwinds", "hostpapa",
    "coreweave", "equinix", "digital realty", "flexential",
    "cyxtera", "vapor.io", "iron mountain",
]


def c(s, code=0):
    return f"\033[{code}m{s}\033[0m"


def random_ip():
    while True:
        country = random.choice(PREFIX_KEYS)
        lo, hi = random.choice(COUNTRY_PREFIXES[country])
        a = random.randint(lo, hi) if lo != hi else lo
        a = max(1, min(223, a))
        ip = f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(2,253)}"
        if not _blocked_ip(ip):
            return ip, country


def generate_target():
    ip, co = random_ip()
    return ip, random.choice(PROXY_PORTS), co


class ProxyFinder:
    def __init__(self):
        self.stats = dict(generated=0, tested=0, open_port=0, http_ok=0, residential=0, verified=0)
        self.verified = []
        self.t0 = time.time()
        self.running = True
        self._last_test = 0

    def render(self):
        os.system("clear" if os.name == "posix" else "cls")
        e = time.time() - self.t0
        r = int(self.stats["tested"] / max(e, 1))

        sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 36))
        sys.stdout.write(c("""║  ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗     ██╗    ║
║  ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝    ██╔╝    ║
║  █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗      ██║     ║
║  ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝      ██║     ║
║  ██║     ██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗    ╚██╗    ║
║  ╚═╝     ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝     ╚═╝    ║""", 93))
        sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 36))

        bar_w = 40
        f = min(self.stats["tested"] / max(self.stats["generated"], 1), 1)
        fill = int(bar_w * f)
        pct = f * 100
        bar = "█" * fill + "░" * (bar_w - fill)
        sys.stdout.write(c(f"  ⚡ {r}/s  ⏱ {e:.0f}s  🧬 {self.stats['generated']} gen\n", 90))
        sys.stdout.write(f"  [{c(bar, 92)}] {pct:.1f}% tested\n")
        sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 36))

        rows = [
            ("🧬  ENGINE 1", self.stats["generated"], "Generate"),
            ("🎯  ENGINE 2", self.stats["tested"], "Test"),
            ("🔓", self.stats["open_port"], "Port Open"),
            ("🌐", self.stats["http_ok"], "HTTP OK"),
            ("🏠  ENGINE 3", self.stats["residential"], "Residential"),
            ("✅", self.stats["verified"], "Verified"),
        ]
        for em, val, label in rows:
            sys.stdout.write(c(f"║  {em} {c(str(val)+' '+label,97):<55}║\n", 90))
        sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 36))

        if self.verified:
            sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 92))
            sys.stdout.write(c(f"║  🏆  ENGINE 3 — VERIFIED  ({len(self.verified)} total)\n", 92))
            for v in reversed(self.verified[-3:]):
                row = f"║  ✅  {v['ip']:>15}:{v['port']:<5}  {v['latency']:>5}ms  {v['country']}/{v['city']:<20}  {v['isp'][:25]}"
                sys.stdout.write(c(row, 97) + "\n")
            best = self.verified[0]
            sys.stdout.write(c("╠" + "═" * 68 + "╣\n", 92))
            sys.stdout.write(c(f"║  🎯  BEST: {best['ip']}:{best['port']}  {best['latency']}ms  {best['country']}/{best['city']}\n", 93))
            pu = f"http://{best['ip']}:{best['port']}"
            sys.stdout.write(c(f"║  ➜  curl -x {pu} https://vplink.in/UbpV2D\n", 93))
            sys.stdout.write(c("╚" + "═" * 68 + "╝\n", 92))

        sys.stdout.write("\033[J")
        sys.stdout.flush()

    # ─── Engine 1: Generator ──────────────────────────────────────

    async def engine1(self, n=2000):
        batch = []
        for _ in range(n):
            batch.append(generate_target())
            self.stats["generated"] += 1
        return batch

    # ─── Engine 2: TCP pre-check + HTTP test ──────────────────────

    async def engine2_tcp_check(self, ip, port):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def engine2_http_test(self, ip, port):
        cmd = [
            "curl", "-s", "--connect-timeout", "3", "--max-time", "5",
            "-x", f"http://{ip}:{port}",
            "http://ipinfo.io/json",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=7)
            if proc.returncode != 0 or not out:
                return None
            return out.decode()
        except Exception:
            return None

    async def engine2_test(self, ip, port, country):
        self.stats["tested"] += 1
        t0 = time.time()

        if not await self.engine2_tcp_check(ip, port):
            return None
        self.stats["open_port"] += 1

        raw = await self.engine2_http_test(ip, port)
        if not raw:
            return None
        self.stats["http_ok"] += 1

        try:
            info = json.loads(raw)
        except json.JSONDecodeError:
            return None

        org = (info.get("org") or "").lower()
        latency = round((time.time() - t0) * 1000)
        ptype = "datacenter" if any(dc in org for dc in DATACENTER_ORGS) else "residential"

        if ptype == "residential":
            self.stats["residential"] += 1

        return {
            "ip": ip, "port": port, "latency": latency, "type": ptype,
            "isp": info.get("org", ""), "city": info.get("city", ""),
            "country": info.get("country", ""),
        }

    # ─── Engine 3: Verifier ───────────────────────────────────────

    async def engine3(self, cand):
        if cand["type"] != "residential" or cand["latency"] > 3000:
            return None

        ok, total_lat = 0, 0
        for _ in range(3):
            t0 = time.time()
            raw = await self.engine2_http_test(cand["ip"], cand["port"])
            if raw:
                try:
                    json.loads(raw)
                    ok += 1
                    total_lat += round((time.time() - t0) * 1000)
                except json.JSONDecodeError:
                    pass

        if ok < 2:
            return None

        v = {"ip": cand["ip"], "port": cand["port"], "latency": round(total_lat / ok),
             "type": "residential", "isp": cand["isp"], "city": cand["city"],
             "country": cand["country"]}
        self.stats["verified"] += 1
        self.verified.append(v)
        self.verified.sort(key=lambda x: x["latency"])

        pu = f"http://{v['ip']}:{v['port']}"
        os.environ["PROXY_FINDER_RESULT"] = pu
        with open("/tmp/opencode/proxy_finder_result.txt", "w") as f:
            f.write(pu)
        return v

    # ─── Worker pool ──────────────────────────────────────────────

    async def worker(self, q):
        while self.running:
            try:
                ip, port, co = await asyncio.wait_for(q.get(), timeout=1)
            except asyncio.TimeoutError:
                continue
            try:
                cand = await self.engine2_test(ip, port, co)
                if cand:
                    await self.engine3(cand)
            finally:
                q.task_done()

    async def display(self):
        last = -1
        while self.running:
            if self.stats["tested"] > last:
                last = self.stats["tested"]
                self.render()
            await asyncio.sleep(0.25)

    async def run(self):
        self.render()
        sys.stdout.write(c("╔" + "═" * 68 + "╗\n", 93))
        sys.stdout.write(c("║  🧬  Engine 1: IP Gen       —  random IPs x {} ports\n".format(len(PROXY_PORTS)), 93))
        sys.stdout.write(c("║  🎯  Engine 2: Rapid Fire    —  TCP → curl, {} workers\n".format(80), 93))
        sys.stdout.write(c("║  ✅  Engine 3: Deep Verify   —  3x check + residential filter\n", 93))
        sys.stdout.write(c("╚" + "═" * 68 + "╝\n\n", 93))
        sys.stdout.flush()

        q = asyncio.Queue(maxsize=5000)
        pool = [asyncio.create_task(self.worker(q)) for _ in range(80)]
        disp = asyncio.create_task(self.display())

        try:
            while self.stats["verified"] < 5:
                batch = await self.engine1(2000)
                for item in batch:
                    await q.put(item)
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False
            disp.cancel()
            for w in pool:
                w.cancel()
            await asyncio.gather(disp, *pool, return_exceptions=True)

        self.render()
        if self.verified:
            b = self.verified[0]
            sys.stdout.write(c(f"\n  🏆  {len(self.verified)} verified residential proxies!\n", 92))
            sys.stdout.write(c(f"\n  🎯  BEST: {b['ip']}:{b['port']}  {b['latency']}ms  {b['country']}/{b['city']}\n", 93))
            sys.stdout.write(c(f"  ➜  curl -x http://{b['ip']}:{b['port']} https://vplink.in/UbpV2D\n\n", 92))
        else:
            sys.stdout.write(c(f"\n  ❌  No residential proxies after {self.stats['tested']} scans.\n", 91))
            sys.stdout.write("     Public IP space is vast (~4B IPs). This is expected.\n")
            sys.stdout.write("     Each batch is a lottery ticket. Keep running.\n\n")
        sys.stdout.flush()


if __name__ == "__main__":
    f = ProxyFinder()
    try:
        asyncio.run(f.run())
    except KeyboardInterrupt:
        print("\n\n  ⏹  Killed by user.")
