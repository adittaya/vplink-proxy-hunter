#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/adittaya/vplink-proxy-hunter"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}[1/4] Checking Python...${NC}"
command -v python3 &>/dev/null || { echo "  [!] Python3 required"; exit 1; }
echo "  Found: $(python3 --version)"

echo -e "${BOLD}[2/4] Checking curl & git...${NC}"
command -v curl &>/dev/null || { echo "  [!] curl required"; exit 1; }
echo "  Found: $(curl --version | head -1)"
command -v git &>/dev/null || { echo "  [!] git required"; exit 1; }
echo "  Found: $(git --version)"

echo -e "${BOLD}[3/4] Downloading & installing...${NC}"
git clone --depth 1 "$REPO.git" "$TMP_DIR" 2>&1 | sed 's/^/  /'
pip install -e "$TMP_DIR/vplink-proxy-hunter" 2>&1 | sed 's/^/  /'
echo -e "  ${GREEN}[✓] Installed${NC}"

echo -e "${BOLD}[4/4] Setting up Supabase config...${NC}"
python3 -c "import sys; sys.path.insert(0, '$TMP_DIR/vplink-proxy-hunter'); from vplink_hunter import config; config.get()" 2>&1 || true

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run:  ${BOLD}vplink-hunter${NC}"
echo -e "  Or:   ${BOLD}vplink-hunter --once${NC}  (single batch)"
echo -e "  Help: ${BOLD}vplink-hunter --help${NC}"
echo ""
