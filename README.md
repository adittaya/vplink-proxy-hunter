# VPLINK Proxy Hunter

3-engine proxy discovery, testing & verification pipeline with Supabase CRUD.

## One-liner install

```bash
git clone --depth 1 https://github.com/adittaya/vplink-proxy-hunter && cd vplink-proxy-hunter && bash install.sh
```

## Usage

```bash
vplink-hunter                      # start scanning
vplink-hunter --once               # single batch
vplink-hunter --list               # query database
vplink-hunter --list --type residential
vplink-hunter --db-stats           # database summary

python3 proxy_pull.py              # pull working proxy details
python3 proxy_pull.py --test       # pull + test 5 proxies
python3 proxy_pull.py --stats      # show DB statistics

python3 examples/proxy_connect_test.py   # test 5 proxies × 5 URLs
```
