#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
REPO="https://github.com/adittaya/vplink-proxy-hunter.git"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect OS ────────────────────────────────────────────────
if [ -f /etc/debian_version ]; then
    OS="debian"
    PKG_MANAGER="apt"
elif [ -f /etc/redhat-release ]; then
    OS="rhel"
    PKG_MANAGER="yum"
elif [ -f /etc/arch-release ]; then
    OS="arch"
    PKG_MANAGER="pacman"
elif [ "$(uname)" = "Darwin" ]; then
    OS="macos"
else
    OS="linux"
    PKG_MANAGER="apt"
fi

# ─── [1/6] Install system dependencies ────────────────────────
echo -e "${BOLD}[1/6] Installing system dependencies...${NC}"

if [ "$OS" = "debian" ] || [ "$OS" = "linux" ]; then
    sudo apt update -qq 2>/dev/null || true
    sudo apt install -y -qq python3 python3-pip python3-venv curl git 2>&1 | sed 's/^/  /'
elif [ "$OS" = "rhel" ]; then
    sudo yum install -y python3 python3-pip python3-virtualenv curl git 2>&1 | sed 's/^/  /'
elif [ "$OS" = "arch" ]; then
    sudo pacman -S --noconfirm python python-pip python-virtualenv curl git 2>&1 | sed 's/^/  /'
elif [ "$OS" = "macos" ]; then
    if ! command -v brew &>/dev/null; then
        echo -e "  ${YELLOW}[!] Installing Homebrew...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python curl git 2>&1 | sed 's/^/  /'
fi

echo -e "  ${GREEN}[✓]${NC} System deps ready"

# ─── [2/6] Check Python ───────────────────────────────────────
echo -e "${BOLD}[2/6] Checking Python...${NC}"
command -v python3 &>/dev/null || { echo -e "  ${RED}[!] python3 install failed${NC}"; exit 1; }
python3 -c "import sys; sys.exit(0) if sys.version_info >= (3,8) else sys.exit(1)" 2>/dev/null || {
    echo -e "  ${RED}[!] Python 3.8+ required, got $(python3 --version)${NC}"; exit 1;
}
echo -e "  ${GREEN}[✓]${NC} Python $(python3 --version | cut -d' ' -f2)"

# ─── [3/6] Check curl (needed at runtime) ─────────────────────
echo -e "${BOLD}[3/6] Checking curl...${NC}"
command -v curl &>/dev/null || { echo -e "  ${RED}[!] curl install failed${NC}"; exit 1; }
echo -e "  ${GREEN}[✓]${NC} $(curl --version | head -1)"

# ─── [4/6] Clone or find repo ─────────────────────────────────
echo -e "${BOLD}[4/6] Getting source code...${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR=""

# Check if we're inside the repo already
if [ -f "$SCRIPT_DIR/vplink-proxy-hunter/pyproject.toml" ]; then
    REPO_DIR="$SCRIPT_DIR/vplink-proxy-hunter"
    echo -e "  ${GREEN}[✓]${NC} Found local copy at $REPO_DIR"
elif [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    REPO_DIR="$SCRIPT_DIR"
    echo -e "  ${GREEN}[✓]${NC} Found local copy at $REPO_DIR"
else
    # Clone to home dir
    REPO_DIR="$HOME/vplink-proxy-hunter"
    if [ -d "$REPO_DIR" ]; then
        echo -e "  ${YELLOW}[i]${NC} Updating existing clone..."
        cd "$REPO_DIR" && git pull 2>&1 | sed 's/^/  /'
    else
        echo -e "  ${YELLOW}[i]${NC} Cloning from GitHub..."
        git clone --depth=1 "$REPO" "$REPO_DIR" 2>&1 | sed 's/^/  /'
    fi
    echo -e "  ${GREEN}[✓]${NC} Cloned to $REPO_DIR"
fi

# ─── [5/6] Install package ────────────────────────────────────
echo -e "${BOLD}[5/6] Installing Python package...${NC}"

VENV_DIR="$HOME/.local/share/vplink-hunter/venv"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$VENV_DIR" "$BIN_DIR"

python3 -m venv --clear "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Upgrade pip inside venv
pip install -q --upgrade pip 2>&1 | sed 's/^/  /'

pip install -q -e "$REPO_DIR" 2>&1 | sed 's/^/  /'

# Symlink the CLI and tools
ln -sf "$VENV_DIR/bin/vplink-hunter" "$BIN_DIR/vplink-hunter"
ln -sf "$REPO_DIR/proxy_pull.py" "$BIN_DIR/proxy-pull" 2>/dev/null || true
ln -sf "$REPO_DIR/proxy_finder.py" "$BIN_DIR/proxy-finder" 2>/dev/null || true

# Update PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    SHELL_CONFIG=""
    case "$SHELL" in
        */bash) SHELL_CONFIG="$HOME/.bashrc" ;;
        */zsh)  SHELL_CONFIG="$HOME/.zshrc" ;;
    esac
    if [ -n "$SHELL_CONFIG" ]; then
        if ! grep -q '\.local/bin' "$SHELL_CONFIG" 2>/dev/null; then
            echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$SHELL_CONFIG"
            echo -e "  ${YELLOW}[i]${NC} Added ~/.local/bin to PATH in $SHELL_CONFIG"
        fi
    fi
fi
export PATH="$PATH:$BIN_DIR"

echo -e "  ${GREEN}[✓]${NC} Package installed"

# ─── [6/6] Configure Supabase ─────────────────────────────────
echo -e "${BOLD}[6/6] Supabase configuration...${NC}"

if [ -f "$HOME/.config/vplink-hunter/config.json" ]; then
    echo -e "  ${GREEN}[✓]${NC} Config already exists at ~/.config/vplink-hunter/config.json"
else
    echo ""
    echo -e "  ${YELLOW}Enter your Supabase credentials (or press Enter to skip):${NC}"
    echo ""
    read -rp "  Supabase URL [https://xxxx.supabase.co]: " SB_URL
    read -rp "  Service Key [sb_secret_xxxx]: " SB_KEY
    read -rp "  Anon Key [sb_publishable_xxxx] (optional): " SB_ANON
    echo ""

    if [ -n "$SB_URL" ] && [ -n "$SB_KEY" ]; then
        mkdir -p "$HOME/.config/vplink-hunter"
        cat > "$HOME/.config/vplink-hunter/config.json" <<-EOF
{
  "supabase_url": "${SB_URL}",
  "service_key": "${SB_KEY}",
  "anon_key": "${SB_ANON:-}"
}
EOF
        echo -e "  ${GREEN}[✓]${NC} Config saved to ~/.config/vplink-hunter/config.json"
    else
        echo -e "  ${YELLOW}[i]${NC} Skipped config setup. Run 'vplink-hunter' later to configure."
    fi
fi

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    vplink-hunter          # Run scanner (continuous)"
echo -e "    vplink-hunter --once   # Single batch"
echo -e "    vplink-hunter --list   # List DB proxies"
echo -e "    vplink-hunter --serve  # REST API"
echo -e "    vplink-hunter --help   # All options"
echo ""
echo -e "  ${YELLOW}Note:${NC} Restart your shell or run:  ${BOLD}source ~/.bashrc${NC}"
echo ""
