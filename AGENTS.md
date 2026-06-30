# VPLINK Proxy Hunter — Agent Guide

## What This Project Does

A 3-engine async pipeline that **discovers, tests, and verifies** open HTTP proxies, then persists only working residential proxies to a Supabase database. The goal is finding reliable residential proxies for web scraping / automation.

## Architecture

```
Engine 1 (Generator)     →  Random IP:port biased toward residential ISPs
Engine 2 (Tester)         →  TCP connect + HTTP GET via proxy (80 async workers)
Engine 3 (Verifier)       →  VPLINK check + residential/datacenter classification
        ↓
   Supabase DB            →  proxy_results table with CRUD API
```

## Database Schema (`proxy_results`)

| Column | Type | Description |
|--------|------|-------------|
| `ip` | TEXT | Proxy IP address (UNIQUE with port) |
| `port` | INTEGER | Proxy port |
| `proto` | TEXT | Protocol (http) |
| `latency_ms` | INTEGER | Response time in ms |
| `type` | TEXT | `residential`, `datacenter`, `unknown` |
| `isp` | TEXT | ISP / organization name |
| `country` | TEXT | 2-letter country code |
| `city` | TEXT | City name |
| `region` | TEXT | Region / state |
| `vplink_ok` | BOOLEAN | Passed VPLINK verification |
| `e2_ok` | BOOLEAN | Passed Engine 2 (HTTP test) |
| `first_seen` | TIMESTAMPTZ | When first discovered |
| `last_seen` | TIMESTAMPTZ | Last verification time |

## CLI Reference

### Scanner
```
vplink-hunter              # Run continuously (Ctrl+C to stop)
vplink-hunter --once       # Single batch then exit
```

### Database CRUD
```
vplink-hunter --list                    # Latest 50 proxies
vplink-hunter --list --type residential # Filter by type
vplink-hunter --list --vplink           # Only VPLINK-verified
vplink-hunter --list --ip 1.2.3.4      # Lookup by IP
vplink-hunter --list --limit 100       # Pagination
vplink-hunter --delete --ip X --port Y # Delete a record
vplink-hunter --db-stats               # Database summary
```

### Standalone Tools
```
python3 proxy_pull.py                    # Pull working proxies with details
python3 proxy_pull.py --type residential # Filter by type
python3 proxy_pull.py --vplink           # Only VPLINK-verified
python3 proxy_pull.py --limit 20        # More results
python3 proxy_pull.py --random           # Random selection
python3 proxy_pull.py --test --count 5  # Pull + test 5 proxies
python3 proxy_pull.py --export json     # JSON output
python3 proxy_pull.py --stats           # DB statistics
python3 proxy_pull.py --ip 1.2.3.4     # IP lookup

python3 examples/proxy_connect_test.py          # Test 5 proxies × 5 URLs
python3 examples/proxy_connect_test.py --count 10
```

## API Reference (Supabase Client)

All database operations go through `vplink_hunter/supabase_client.py`:

| Function | Description |
|----------|-------------|
| `init(url, key)` | Initialize client with service key |
| `upsert_proxy(proxy)` | Insert or update (on conflict ip+port) |
| `get_proxy(ip, port)` | Get single proxy by IP + port |
| `list_proxies(type, vplink_only, limit, offset)` | List with filters |
| `list_proxies_by_ip(ip)` | List all records for an IP |
| `delete_proxy(ip, port)` | Delete a proxy |
| `get_stats()` | Count by type, vplink status |

## Supabase Config

Config is stored at `~/.config/vplink-hunter/config.json`:
```json
{
  "supabase_url": "https://xxxx.supabase.co",
  "anon_key": "sb_publishable_xxxx",
  "service_key": "sb_secret_xxxx"
}
```

## OAuth / API Keys Needed From User

The user needs to provide these Supabase credentials:

1. **Supabase Project URL** — `https://xxxx.supabase.co`
2. **Supabase Anon Key** — Public publishable key (`sb_publishable_xxxx`)
3. **Supabase Service Key** — Secret key for server-side access (`sb_secret_xxxx`)

Optional:
4. **Supabase CLI Token** — For DB management (`sbp_xxxx`), generated at `https://supabase.com/dashboard/account/tokens`

## Install

```bash
git clone https://github.com/adittaya/vplink-proxy-hunter
cd vplink-proxy-hunter
bash install.sh
```
