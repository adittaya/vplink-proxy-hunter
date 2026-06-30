#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect source directory ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/vplink-proxy-hunter/pyproject.toml" ]; then
    PKG_DIR="$SCRIPT_DIR/vplink-proxy-hunter"
elif [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    PKG_DIR="$SCRIPT_DIR"
else
    echo -e "  ${RED}[!] Cannot find vplink-proxy-hunter package${NC}"
    exit 1
fi

VENV_DIR="$HOME/.local/share/vplink-hunter/venv"
BIN_DIR="$HOME/.local/bin"

# ─── [1/4] Check Python ──────────────────────────────────────────
echo -e "${BOLD}[1/4] Checking Python...${NC}"
command -v python3 &>/dev/null || { echo -e "  ${RED}[!] Python3 required${NC}"; exit 1; }
python3 -c "import sys; sys.exit(0) if sys.version_info >= (3,10) else sys.exit(1)" 2>/dev/null || {
    echo -e "  ${RED}[!] Python >= 3.10 required${NC}"; exit 1;
}
echo -e "  ${GREEN}[✓]${NC} Python $(python3 --version | cut -d' ' -f2)"

# ─── [2/4] Check curl (needed at runtime) ─────────────────────────
echo -e "${BOLD}[2/4] Checking curl...${NC}"
command -v curl &>/dev/null || {
    echo -e "  ${YELLOW}[!] curl not found. Install it: sudo apt install curl${NC}"
    exit 1
}
echo -e "  ${GREEN}[✓]${NC} $(curl --version | head -1)"

# ─── [3/4] Virtual env + install ──────────────────────────────────
echo -e "${BOLD}[3/4] Installing...${NC}"
mkdir -p "$VENV_DIR" "$BIN_DIR"

# Fix: dont fail if venv module is missing
if ! python3 -m venv --help &>/dev/null; then
    echo -e "  ${RED}[!] python3-venv module required. Install: sudo apt install python3-venv${NC}"
    exit 1
fi

python3 -m venv --clear "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install -q -e "$PKG_DIR" 2>&1 | sed 's/^/  /'
ln -sf "$VENV_DIR/bin/vplink-hunter" "$BIN_DIR/vplink-hunter"

# Add to PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    SHELL_CONFIG=""
    case "$SHELL" in
        */bash) SHELL_CONFIG="$HOME/.bashrc" ;;
        */zsh)  SHELL_CONFIG="$HOME/.zshrc" ;;
    esac
    if [ -n "$SHELL_CONFIG" ]; then
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_CONFIG"
        echo -e "  ${YELLOW}[i]${NC} Added $BIN_DIR to PATH in $SHELL_CONFIG"
    fi
fi
export PATH="$PATH:$BIN_DIR"
echo -e "  ${GREEN}[✓]${NC} Installed"

# ─── [4/4] Supabase config ─────────────────────────────────────────
echo -e "${BOLD}[4/4] Supabase configuration...${NC}"
echo ""
echo -e "  ${YELLOW}Enter your Supabase credentials (Ctrl+C to skip)${NC}"
echo ""
python3 -c "
import sys
sys.path.insert(0, '$PKG_DIR')
from vplink_hunter import config
cfg = config.get()
if cfg:
    print('  [✓] Config saved')
" 2>&1

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run:   ${BOLD}vplink-hunter${NC}"
echo -e "  Or:    ${BOLD}vplink-hunter --once${NC}"
echo -e "  API:   ${BOLD}vplink-hunter --serve${NC}  (REST API for proxy rotation)"
echo -e "  Help:  ${BOLD}vplink-hunter --help${NC}"
echo ""
echo -e "  ${YELLOW}REST API quick-start:${NC}"
echo -e "    ${BOLD}vplink-hunter --serve${NC}"
echo -e "    ${BOLD}curl 'http://localhost:8080/api/proxy?key=\$(cat ~/.config/vplink-hunter/config.json | python3 -c \"import sys,json; print(json.load(sys.stdin).get('api_key',''))\")'${NC}"
echo ""
echo -e "  ${YELLOW}Note:${NC} Restart shell or run:  ${BOLD}source ~/.bashrc${NC}"
echo ""
