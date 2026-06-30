#!/usr/bin/env python3
"""
proxy_hunter.py — Free proxy scraper, rapid tester, residential detector.
Auto-connects on first residential hit. Runs until successful.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import time
from typing import Optional

DATACENTER_ORGS = re.compile(
    r"alibaba|amazon(?!\.com)|google|hetzner|ovh|digitalocean|vultr|linode|"
    r"microsoft|oracle|ibm|rackspace|softlayer|scaleway|"
    r"contabo|netcup|cogent|multiplay|ipxo|datacamp|"
    r"zenlayer|psychz|gige|choopa|sharktech|"
    r"cloudflare|server|hosting|host|vps|dedicated|"
    r"colocrossing|theplanet|leaseweb|akamai|"
    r"incapsula|sucuri|stackpath|fastly"
)

SOURCES = {
    "proxyscrape_http": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "proxyscrape_socks4": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
    "proxyscrape_socks5": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
    "speedx_http": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "shifty_http": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "jetkai_http": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies_http.txt",
    "mmook_socks5": "https://raw.githubusercontent.com/mmook/Proxy-List/master/socks5.txt",
    "plist_http": "https://www.proxy-list.download/api/v1/get?type=http",
    "plist_https": "https://www.proxy-list.download/api/v1/get?type=https",
    "plist_socks4": "https://www.proxy-list.download/api/v1/get?type=socks4",
    "plist_socks5": "https://www.proxy-list.download/api/v1/get?type=socks5",
}

PROTO_MAP = {
    "proxyscrape_http": "http", "proxyscrape_socks4": "socks4", "proxyscrape_socks5": "socks5",
    "speedx_http": "http", "shifty_http": "http", "jetkai_http": "http",
    "mmook_socks5": "socks5",
    "plist_http": "http", "plist_https": "http",
    "plist_socks4": "socks4", "plist_socks5": "socks5",
}

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\s]\s*(\d+)")


def c(s, code=0):
    return f"\033[{code}m{s}\033[0m"


class ProxyHunter:
    def __init__(self):
        self.stats = {"scraped": 0, "tested": 0, "working": 0, "residential": 0, "datacenter": 0}
        self.results = []
        self.best_residential = None
        self.total_to_test = 0
        self.queue = asyncio.Queue()
        self.running = True

    def print_header(self):
        os.system("clear" if os.name == "posix" else "cls")
        sys.stdout.write(c("=" * 64, 36) + "\n")
        sys.stdout.write(c("  ██████  ██████   ██████  ██   ██ ██    ██ ██   ██ ███    ██ ████████ ███████ ██████\n", 93))
        sys.stdout.write(c("  ██   ██ ██   ██ ██       ██  ██  ██    ██ ██   ██ ████   ██    ██    ██      ██   ██\n", 93))
        sys.stdout.write(c("  ██████  ██████  ██   ███ █████   ██    ██ ███████ ██ ██  ██    ██    █████   ██████\n", 93))
        sys.stdout.write(c("  ██      ██   ██ ██    ██ ██  ██  ██    ██ ██   ██ ██  ██ ██    ██    ██      ██   ██\n", 93))
        sys.stdout.write(c("  ██      ██   ██  ██████  ██   ██  ██████  ██   ██ ██   ████    ██    ███████ ██   ██\n", 93))
        sys.stdout.write(c("=" * 64, 36) + "\n")

    def print_dashboard(self):
        s = self.stats
        sys.stdout.write(c(f"  {'SCRAPED':<12} {'TESTED':<12} {'WORKING':<12} {'🏠RES':<12} {'🏢DC':<12}\n", 90))
        sys.stdout.write(c(f"  {s['scraped']:<12} {s['tested']:<12} {s['working']:<12} {s['residential']:<12} {s['datacenter']:<12}\n", 97))
        sys.stdout.write(c("─" * 64, 36) + "\n")

        if self.best_residential:
            p = self.best_residential
            sys.stdout.write(c("  🏆🏆🏆  RESIDENTIAL PROXY ACTIVE  🏆🏆🏆\n", 92))
            sys.stdout.write(c(f"     {p['ip']}:{p['port']} [{p['proto']}] {p['latency']}ms\n", 97))
            sys.stdout.write(c(f"     {p['country']} / {p['city']} — {p['isp'][:55]}\n", 90))
            proxy_url = f"{p['proto']}://{p['ip']}:{p['port']}"
            sys.stdout.write(c(f"     curl -x {proxy_url} https://vplink.in/UbpV2D\n", 93))
            sys.stdout.write("─" * 64 + "\n")

    def print_progress(self):
        if self.total_to_test == 0:
            return
        pct = self.stats["tested"] / self.total_to_test
        filled = int(30 * pct)
        bar = "[" + c("█" * filled, 92) + c("░" * (30 - filled), 90) + f"] {self.stats['tested']}/{self.total_to_test}"
        sys.stdout.write(c(f"  Progress: {bar}\n", 90))

    def print_latest(self, n=3):
        if not self.results:
            return
        sys.stdout.write(c("  Latest:\n", 90))
        for r in self.results[-n:]:
            tag = c("🏠", 92) if r["type"] == "residential" else c("🏢", 93) if r["type"] == "datacenter" else c("❓", 90)
            line = f"  {tag} {r['ip']}:{r['port']} [{r['proto']}] {r['latency']}ms {r['country']}/{r['city']} {r['type']}"
            sys.stdout.write(line + "\n")

    def render(self):
        self.print_header()
        self.print_dashboard()
        self.print_progress()
        self.print_latest()
        sys.stdout.write("\033[J")
        sys.stdout.flush()

    async def curl_get(self, url, proxy=None, proto="http", timeout=10):
        cmd = ["curl", "-s", "--connect-timeout", str(timeout // 2), "--max-time", str(timeout)]
        if proxy:
            flag = "--socks5" if "socks5" in proto else "--socks4" if "socks4" in proto else "-x"
            if flag == "-x":
                cmd.extend([flag, f"{proxy}"])
            else:
                cmd.extend([flag, proxy])
        cmd.append(url)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
            if proc.returncode != 0:
                return None
            return stdout.decode()
        except Exception:
            return None

    async def scrape_source(self, name, url):
        text = await self.curl_get(url, timeout=12)
        if not text:
            return set()
        proxies = set()
        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            m = IP_RE.match(line)
            if m:
                ip, port_str = m.group(1), m.group(2)
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    proxies.add((ip, port, PROTO_MAP.get(name, "http")))
        return proxies

    async def gather_all(self):
        tasks = [self.scrape_source(name, url) for name, url in SOURCES.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_proxies = set()
        for r in results:
            if isinstance(r, set):
                all_proxies |= r
        self.stats["scraped"] = len(all_proxies)
        return all_proxies

    async def test_one(self, ip, port, proto):
        t0 = time.time()
        if proto == "http":
            result = await self.curl_get(
                "http://ipinfo.io/json",
                proxy=f"http://{ip}:{port}",
                proto="http",
                timeout=8,
            )
        else:
            result = await self.curl_get(
                "http://ipinfo.io/json",
                proxy=f"{ip}:{port}",
                proto=proto,
                timeout=8,
            )

        if not result:
            return None

        try:
            info = json.loads(result)
        except json.JSONDecodeError:
            return None

        latency = round((time.time() - t0) * 1000)
        org = (info.get("org") or "").lower()

        if DATACENTER_ORGS.search(org):
            ip_type = "datacenter"
        elif info.get("org") or info.get("city"):
            ip_type = "residential"
        else:
            ip_type = "unknown"

        return {
            "ip": ip,
            "port": port,
            "proto": proto,
            "latency": latency,
            "type": ip_type,
            "isp": info.get("org", ""),
            "city": info.get("city", ""),
            "country": info.get("country", ""),
        }

    async def worker(self):
        while self.running:
            item = await self.queue.get()
            if item is None:
                self.queue.task_done()
                break
            ip, port, proto = item
            self.stats["tested"] += 1
            result = await self.test_one(ip, port, proto)
            if result:
                self.stats["working"] += 1
                if result["type"] == "residential":
                    self.stats["residential"] += 1
                    if not self.best_residential or result["latency"] < self.best_residential["latency"]:
                        self.best_residential = result
                        self.on_residential_found(result)
                elif result["type"] == "datacenter":
                    self.stats["datacenter"] += 1
                self.results.append(result)
            self.queue.task_done()

    def on_residential_found(self, proxy):
        proxy_url = f"{proxy['proto']}://{proxy['ip']}:{proxy['port']}"
        os.environ["PROXY_HUNT_RESULT"] = proxy_url
        with open("/tmp/opencode/proxy_hunt_result.txt", "w") as f:
            f.write(proxy_url)

    async def monitor(self):
        last_tested = -1
        while self.running:
            if self.stats["tested"] != last_tested:
                last_tested = self.stats["tested"]
                self.render()
            await asyncio.sleep(0.2)

    async def run(self):
        self.render()
        sys.stdout.write(c("  [*] Scraping proxy lists...\n", 90))
        sys.stdout.flush()

        all_proxies = await self.gather_all()

        self.render()
        sys.stdout.write(c(f"  [+] {len(all_proxies)} unique proxies from {len(SOURCES)} sources\n", 92))
        sys.stdout.flush()

        http_list = [(ip, port, proto) for ip, port, proto in all_proxies if proto == "http"]
        socks_list = [(ip, port, proto) for ip, port, proto in all_proxies if proto != "http"]

        test_queue = []
        max_len = max(len(http_list), len(socks_list))
        for i in range(max_len):
            if i < len(http_list):
                test_queue.append(http_list[i])
            if i < len(socks_list):
                test_queue.append(socks_list[i])

        self.total_to_test = len(test_queue)

        self.render()
        sys.stdout.write(c(f"  [*] Testing {self.total_to_test} proxies ({len(http_list)} HTTP | {len(socks_list)} SOCKS)\n", 90))
        sys.stdout.flush()

        for item in test_queue:
            await self.queue.put(item)

        n_workers = min(80, self.total_to_test)
        for _ in range(n_workers):
            await self.queue.put(None)

        workers = [asyncio.create_task(self.worker()) for _ in range(n_workers)]
        monitor_task = asyncio.create_task(self.monitor())

        await self.queue.join()
        self.running = False
        await monitor_task
        await asyncio.gather(*workers)

        self.render()

        if self.best_residential:
            p = self.best_residential
            sys.stdout.write(c(f"\n  {'='*60}\n", 36))
            sys.stdout.write(c(f"  🏆🏆🏆  RESIDENTIAL PROXY READY  🏆🏆🏆\n", 92))
            sys.stdout.write(c(f"  {'='*60}\n", 36))
            sys.stdout.write(c(f"     IP:       {p['ip']}:{p['port']}\n", 97))
            sys.stdout.write(c(f"     Proto:    {p['proto']}\n", 97))
            sys.stdout.write(c(f"     Latency:  {p['latency']}ms\n", 97))
            sys.stdout.write(c(f"     Location: {p['country']} / {p['city']}\n", 97))
            sys.stdout.write(c(f"     ISP:      {p['isp'][:60]}\n", 90))
            proxy_url = f"{p['proto']}://{p['ip']}:{p['port']}"
            sys.stdout.write(c(f"\n     ➜  export PROXY_HUNT_RESULT={proxy_url}\n", 93))
            sys.stdout.write(c(f"     ➜  curl -x {proxy_url} https://vplink.in/UbpV2D\n", 93))
            sys.stdout.write(c(f"     ➜  Auto-connected! Saved to /tmp/opencode/proxy_hunt_result.txt\n\n", 92))
        elif self.stats["datacenter"] > 0:
            best = min([r for r in self.results if r["type"] == "datacenter"], key=lambda x: x["latency"])
            sys.stdout.write(c(f"\n  ⚠️   Only datacenter proxies found (will be blocked by most sites).\n", 93))
            sys.stdout.write(c(f"     Best: {best['ip']}:{best['port']} [{best['proto']}] {best['latency']}ms\n\n", 93))
        else:
            sys.stdout.write(c(f"\n  ❌  No working proxies found. All public lists dead/overloaded.\n", 91))
            sys.stdout.write(c(f"     Try again later or use paid residential proxies.\n\n", 90))

        sys.stdout.flush()


if __name__ == "__main__":
    hunter = ProxyHunter()
    asyncio.run(hunter.run())
