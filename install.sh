#!/usr/bin/env bash
set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Check Python ────────────────────────────────────────────────
echo -e "${BOLD}[1/4] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY=$(python3 --version 2>&1)
    echo "  Found: $PY"
else
    echo "  [!] Python3 is required. Install it first."
    exit 1
fi

# ─── Check curl ───────────────────────────────────────────────────
echo -e "${BOLD}[2/4] Checking curl...${NC}"
if command -v curl &>/dev/null; then
    echo "  Found: $(curl --version | head -1)"
else
    echo "  [!] curl is required. Install it with: sudo apt install curl"
    exit 1
fi

# ─── Install package ─────────────────────────────────────────────
echo -e "${BOLD}[3/4] Installing vplink-proxy-hunter...${NC}"
cd "$(dirname "$0")/vplink-proxy-hunter"
pip install -e . 2>&1 | sed 's/^/  /'
echo -e "  ${GREEN}[✓] Installed${NC}"

# ─── Config ──────────────────────────────────────────────────────
echo -e "${BOLD}[4/4] Setting up Supabase config...${NC}"
python3 -c "from vplink_hunter import config; config.get()" 2>&1 || true

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run:  ${BOLD}vplink-hunter${NC}"
echo -e "  Or:   ${BOLD}vplink-hunter --once${NC}  (single batch)"
echo -e "  Help: ${BOLD}vplink-hunter --help${NC}"
echo ""
