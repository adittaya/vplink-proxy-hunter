#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/adittaya/vplink-proxy-hunter"
VENV_DIR="$HOME/.local/share/vplink-hunter/venv"
BIN_DIR="$HOME/.local/bin"

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect package manager ───────────────────────────────────────
install_pkg() {
    if command -v apt &>/dev/null; then
        sudo apt update -qq && sudo apt install -y -qq "$@"
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y -q "$@"
    elif command -v yum &>/dev/null; then
        sudo yum install -y -q "$@"
    elif command -v apk &>/dev/null; then
        sudo apk add --quiet "$@"
    elif command -v brew &>/dev/null; then
        brew install "$@"
    else
        echo -e "  ${RED}[!] No package manager found. Install manually: $*${NC}"
        return 1
    fi
}

# ─── [1/5] System dependencies ────────────────────────────────────
echo -e "${BOLD}[1/5] System dependencies...${NC}"
MISSING=""

command -v python3 &>/dev/null || MISSING="$MISSING python3"
python3 -c "import sys; sys.exit(0) if sys.version_info >= (3,10) else sys.exit(1)" 2>/dev/null || {
    echo -e "  ${RED}[!] Python >= 3.10 required${NC}"; exit 1;
}
echo -e "  ${GREEN}[✓]${NC} Python $(python3 --version | cut -d' ' -f2)"

command -v pip3 &>/dev/null || MISSING="$MISSING python3-pip"
command -v curl &>/dev/null || MISSING="$MISSING curl"
command -v git &>/dev/null || MISSING="$MISSING git"
command -v venv &>/dev/null; python3 -m venv --help &>/dev/null || MISSING="$MISSING python3-venv"

if [ -n "$MISSING" ]; then
    echo -e "  Installing:$MISSING"
    install_pkg $MISSING
    echo -e "  ${GREEN}[✓]${NC} Dependencies installed"
else
    echo -e "  ${GREEN}[✓]${NC} All system deps present"
fi

# ─── [2/5] Download source ────────────────────────────────────────
echo -e "${BOLD}[2/5] Downloading source...${NC}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
git clone --depth 1 "$REPO.git" "$TMP_DIR" 2>&1 | sed 's/^/  /'
echo -e "  ${GREEN}[✓]${NC} Source cloned"

# ─── [3/5] Virtual environment ────────────────────────────────────
echo -e "${BOLD}[3/5] Setting up virtual environment...${NC}"
mkdir -p "$VENV_DIR" "$BIN_DIR"
python3 -m venv --clear "$VENV_DIR"
source "$VENV_DIR/bin/activate"
echo -e "  ${GREEN}[✓]${NC} venv at $VENV_DIR"

# ─── [4/5] Install package ────────────────────────────────────────
echo -e "${BOLD}[4/5] Installing vplink-proxy-hunter...${NC}"
pip install -q -e "$TMP_DIR/vplink-proxy-hunter" 2>&1 | sed 's/^/  /'
ln -sf "$VENV_DIR/bin/vplink-hunter" "$BIN_DIR/vplink-hunter"
echo -e "  ${GREEN}[✓]${NC} Installed"

# ─── Add to PATH ──────────────────────────────────────────────────
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

# ─── [5/5] Supabase config ─────────────────────────────────────────
echo -e "${BOLD}[5/5] Supabase configuration...${NC}"
echo ""
echo -e "  ${YELLOW}Enter your Supabase credentials (or Ctrl+C to skip)${NC}"
echo ""
python3 -c "
import sys, json, os
sys.path.insert(0, '$TMP_DIR/vplink-proxy-hunter')
from vplink_hunter import config
cfg = config.get()
if cfg:
    print('  ' + '✓ Config saved')
" 2>&1

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run:  ${BOLD}vplink-hunter${NC}"
echo -e "  Or:   ${BOLD}vplink-hunter --once${NC}"
echo -e "  Help: ${BOLD}vplink-hunter --help${NC}"
echo ""
echo -e "  ${YELLOW}Note:${NC} Restart your shell or run:  ${BOLD}source ~/.bashrc${NC}"
echo ""
