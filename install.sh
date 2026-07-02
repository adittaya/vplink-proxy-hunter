#!/usr/bin/env bash
# VPLINK Proxy Hunter — Universal Installer
# Works on: Linux, macOS, Termux, proot-distro, WSL
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
REPO="https://github.com/adittaya/vplink-proxy-hunter.git"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPLINK PROXY HUNTER INSTALLER       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ─── Detect environment ─────────────────────────────────────────
SUDO="sudo"
IS_TERMUX=false
IS_PROOT=false
PKG_INSTALL=""

if [ -n "${TERMUX_VERSION:-}" ] || [ "$(uname -o 2>/dev/null)" = "Android" ]; then
    IS_TERMUX=true
    SUDO=""
    PKG_INSTALL="pkg install -y"
    echo -e "  ${YELLOW}[i]${NC} Termux detected"
elif [ -f /etc/debian_version ]; then
    if [ "$(whoami)" = "root" ]; then
        SUDO=""
    fi
    PKG_INSTALL="apt install -y"
    echo -e "  ${YELLOW}[i]${NC} Debian/Ubuntu detected"
elif [ -f /etc/arch-release ]; then
    PKG_INSTALL="pacman -S --noconfirm"
    echo -e "  ${YELLOW}[i]${NC} Arch Linux detected"
elif [ -f /etc/redhat-release ]; then
    if command -v dnf &>/dev/null; then
        PKG_INSTALL="dnf install -y"
    else
        PKG_INSTALL="yum install -y"
    fi
    echo -e "  ${YELLOW}[i]${NC} RHEL/Fedora detected"
elif [ -f /etc/alpine-release ]; then
    PKG_INSTALL="apk add"
    echo -e "  ${YELLOW}[i]${NC} Alpine Linux detected"
elif [ "$(uname)" = "Darwin" ]; then
    SUDO=""
    echo -e "  ${YELLOW}[i]${NC} macOS detected"
else
    # Fallback: try apt
    PKG_INSTALL="apt install -y"
    echo -e "  ${YELLOW}[i]${NC} Linux (apt fallback) detected"
fi

# ─── [1/6] Install system dependencies ────────────────────────
echo ""
echo -e "${BOLD}[1/6] Installing system dependencies...${NC}"

if [ "$IS_TERMUX" = true ]; then
    pkg update -y 2>/dev/null || true
    $SUDO $PKG_INSTALL python python-pip curl git 2>&1 | sed 's/^/  /'
elif [ -n "$PKG_INSTALL" ]; then
    if [ "$PKG_INSTALL" = "apt install -y" ] && [ "$SUDO" = "sudo" ]; then
        sudo apt update -qq 2>/dev/null || true
    fi
    # python3-venv might not exist everywhere; try without it
    $SUDO $PKG_INSTALL python3 python3-pip python3-venv curl git 2>&1 | sed 's/^/  /' || \
    $SUDO $PKG_INSTALL python3 python3-pip curl git 2>&1 | sed 's/^/  /'
elif [ "$(uname)" = "Darwin" ]; then
    if ! command -v brew &>/dev/null; then
        echo -e "  ${YELLOW}[!] Installing Homebrew...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python curl git 2>&1 | sed 's/^/  /'
fi

echo -e "  ${GREEN}[✓]${NC} System deps ready"

# ─── [2/6] Check Python ───────────────────────────────────────
echo ""
echo -e "${BOLD}[2/6] Checking Python...${NC}"

PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${RED}[!] Python not found. Install it manually.${NC}"
    exit 1
fi

$PYTHON -c "import sys; sys.exit(0) if sys.version_info >= (3,8) else sys.exit(1)" 2>/dev/null || {
    echo -e "  ${RED}[!] Python 3.8+ required, got $($PYTHON --version)${NC}"
    exit 1
}
echo -e "  ${GREEN}[✓]${NC} $($PYTHON --version)"

# ─── [3/6] Check curl ──────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/6] Checking curl...${NC}"
command -v curl &>/dev/null || { echo -e "  ${RED}[!] curl not found. Install it.${NC}"; exit 1; }
echo -e "  ${GREEN}[✓]${NC} $(curl --version | head -1)"

# ─── [4/6] Get source code ─────────────────────────────────────
echo ""
echo -e "${BOLD}[4/6] Getting source code...${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR=""

# Check local copy
if [ -f "$SCRIPT_DIR/requirements.txt" ] && [ -d "$SCRIPT_DIR/vplink-proxy-hunter" ]; then
    REPO_DIR="$SCRIPT_DIR"
    echo -e "  ${GREEN}[✓]${NC} Found local copy"
elif [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    REPO_DIR="$SCRIPT_DIR"
    echo -e "  ${GREEN}[✓]${NC} Found local copy"
else
    # Clone to system-appropriate location
    if [ "$IS_TERMUX" = true ]; then
        REPO_DIR="$HOME/storage/downloads/vplink-proxy-hunter"
    else
        REPO_DIR="$HOME/vplink-proxy-hunter"
    fi

    if [ -d "$REPO_DIR" ]; then
        echo -e "  ${YELLOW}[i]${NC} Updating existing clone..."
        cd "$REPO_DIR" && git pull 2>&1 | sed 's/^/  /'
    else
        echo -e "  ${YELLOW}[i]${NC} Cloning from GitHub..."
        git clone --depth=1 "$REPO" "$REPO_DIR" 2>&1 | sed 's/^/  /'
    fi
    echo -e "  ${GREEN}[✓]${NC} Source at $REPO_DIR"
fi

# ─── [5/6] Install Python package ─────────────────────────────
echo ""
echo -e "${BOLD}[5/6] Installing Python package...${NC}"

VENV_DIR="$HOME/.local/share/vplink-hunter/venv"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$VENV_DIR" "$BIN_DIR"

# Try creating venv; fall back to --user install if venv fails
VENV_OK=false
if $PYTHON -m venv --help &>/dev/null; then
    rm -rf "$VENV_DIR"
    if $PYTHON -m venv "$VENV_DIR" 2>/dev/null; then
        source "$VENV_DIR/bin/activate"
        pip install -q --upgrade pip 2>/dev/null || true
        VENV_OK=true
    fi
fi

if [ "$VENV_OK" = true ]; then
    pip install -q -e "$REPO_DIR" 2>&1 | sed 's/^/  /'
    # Symlink the CLI and tools
    mkdir -p "$BIN_DIR"
    ln -sf "$VENV_DIR/bin/vplink-hunter" "$BIN_DIR/vplink-hunter"
    echo -e "  ${GREEN}[✓]${NC} Installed in virtualenv"
else
    # Fallback: system/user install
    echo -e "  ${YELLOW}[!]${NC} venv unavailable; installing with --user"
    $PYTHON -m pip install --user --upgrade pip 2>/dev/null || true
    $PYTHON -m pip install --user -e "$REPO_DIR" 2>&1 | sed 's/^/  /'
    # Find the CLI entry
    USER_BIN="$HOME/.local/bin"
    if [ "$IS_TERMUX" = true ]; then
        USER_BIN="$PREFIX/bin"
    fi
    echo -e "  ${GREEN}[✓]${NC} Installed (user)"
    BIN_DIR="$USER_BIN"
fi

# Symlink standalone tools
ln -sf "$REPO_DIR/proxy_pull.py" "$BIN_DIR/proxy-pull" 2>/dev/null || true
ln -sf "$REPO_DIR/proxy_finder.py" "$BIN_DIR/proxy-finder" 2>/dev/null || true
ln -sf "$REPO_DIR/proxy_hunter.py" "$BIN_DIR/proxy-hunter" 2>/dev/null || true
chmod +x "$REPO_DIR/proxy_pull.py" "$REPO_DIR/proxy_finder.py" "$REPO_DIR/proxy_hunter.py" 2>/dev/null || true

# ─── Add to PATH ──────────────────────────────────────────────
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    SHELL_CONFIG=""
    case "${SHELL##*/}" in
        bash) SHELL_CONFIG="$HOME/.bashrc" ;;
        zsh)  SHELL_CONFIG="$HOME/.zshrc"  ;;
        fish) SHELL_CONFIG="$HOME/.config/fish/config.fish" ;;
    esac

    if [ -n "$SHELL_CONFIG" ] && [ -f "$SHELL_CONFIG" ]; then
        if ! grep -qF "$BIN_DIR" "$SHELL_CONFIG" 2>/dev/null; then
            if [ "${SHELL##*/}" = "fish" ]; then
                echo "fish_add_path $BIN_DIR" >> "$SHELL_CONFIG"
            else
                echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_CONFIG"
            fi
            echo -e "  ${YELLOW}[i]${NC} Added $BIN_DIR to PATH in $SHELL_CONFIG"
        fi
    elif [ -n "$SHELL_CONFIG" ]; then
        mkdir -p "$(dirname "$SHELL_CONFIG")"
        if [ "${SHELL##*/}" = "fish" ]; then
            echo "fish_add_path $BIN_DIR" > "$SHELL_CONFIG"
        else
            echo "export PATH=\"\$PATH:$BIN_DIR\"" > "$SHELL_CONFIG"
        fi
        echo -e "  ${YELLOW}[i]${NC} Created $SHELL_CONFIG with PATH"
    fi
    export PATH="$PATH:$BIN_DIR"
fi

# ─── [6/6] Configure Supabase ─────────────────────────────────
echo ""
echo -e "${BOLD}[6/6] Supabase configuration...${NC}"

CONFIG_DIR="$HOME/.config/vplink-hunter"
CONFIG_FILE="$CONFIG_DIR/config.json"

if [ -f "$CONFIG_FILE" ]; then
    echo -e "  ${GREEN}[✓]${NC} Config already exists at $CONFIG_FILE"
    echo ""
    echo -e "  ${BOLD}To reconfigure:${NC} rm $CONFIG_FILE && bash install.sh"
else
    echo ""
    echo -e "  ${YELLOW}Enter your Supabase credentials (or press Enter 3x to skip):${NC}"
    echo ""
    read -rp "  Supabase URL [https://xxxx.supabase.co]: " SB_URL
    read -rp "  Service Key [sb_secret_xxxx]: " SB_KEY
    read -rp "  Anon Key [sb_publishable_xxxx]: " SB_ANON
    echo ""

    if [ -n "$SB_URL" ] && [ -n "$SB_KEY" ]; then
        mkdir -p "$CONFIG_DIR"
        cat > "$CONFIG_FILE" <<-EOF
{
  "supabase_url": "${SB_URL}",
  "service_key": "${SB_KEY}",
  "anon_key": "${SB_ANON:-}"
}
EOF
        chmod 600 "$CONFIG_FILE"
        echo -e "  ${GREEN}[✓]${NC} Config saved to $CONFIG_FILE"
    else
        echo -e "  ${YELLOW}[i]${NC} Skipped. Run 'vplink-hunter' later to configure."
    fi
fi

# ─── Copy .env.example if .env doesn't exist ──────────────────
if [ ! -f "$REPO_DIR/.env" ] && [ -f "$REPO_DIR/.env.example" ]; then
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    echo -e "  ${YELLOW}[i]${NC} Created .env from .env.example — edit with your keys"
fi

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    vplink-hunter              # Start scanner (continuous)"
echo -e "    vplink-hunter --once       # Single batch then exit"
echo -e "    vplink-hunter --list       # Query database"
echo -e "    vplink-hunter --db-stats   # Database summary"
echo -e "    proxy-pull --help          # Pull proxies with filters"
echo -e "    python3 $REPO_DIR/examples/proxy_connect_test.py  # Test proxies"
echo ""
echo -e "  ${YELLOW}Note:${NC} Restart your shell or run:  ${BOLD}source ~/.bashrc${NC}"
echo ""
