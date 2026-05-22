#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  ProjectZ v1.0 — Installer
#  Author: cyberhowler (R.G)
#  Usage:  bash install.sh
#          bash install.sh --venv        (install inside virtualenv)
#          bash install.sh --system      (force system-wide install)
# ─────────────────────────────────────────────────────────────────────────────

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }

USE_VENV=0
[[ "$1" == "--venv" ]] && USE_VENV=1

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
cat << 'BANNER'
██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗███████╗
██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝╚════██║
██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║       ██╔╝
██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║      ██╔╝
██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝
BANNER
echo -e "${WHITE}     ProjectZ v1.0 — OSINT Framework Installer${RESET}"
echo -e "${CYAN}     by cyberhowler (R.G)${RESET}"
echo ""

# ── Check Python version ──────────────────────────────────────────────────────
info "Checking Python version..."
PY=$(command -v python3 || command -v python)
[[ -z "$PY" ]] && error "Python 3.10+ not found. Install from https://python.org"

PY_VER=$($PY -c "import sys; print(sys.version_info.major * 10 + sys.version_info.minor)")
[[ "$PY_VER" -lt 310 ]] && error "Python 3.10+ required. Found: $($PY --version)"
success "Python $($PY --version) ✓"

# ── Virtualenv ────────────────────────────────────────────────────────────────
if [[ $USE_VENV -eq 1 ]]; then
    info "Creating virtual environment (.venv)..."
    $PY -m venv .venv
    source .venv/bin/activate
    PY=python
    PIP=pip
    success "Virtualenv activated"
else
    PIP=$(command -v pip3 || command -v pip)
    [[ -z "$PIP" ]] && error "pip not found"
fi

# ── Upgrade pip ───────────────────────────────────────────────────────────────
info "Upgrading pip..."
$PIP install --upgrade pip -q

# ── Install Python dependencies ───────────────────────────────────────────────
info "Installing Python dependencies from requirements.txt..."
$PIP install -r requirements.txt -q
success "Python packages installed ✓"

# ── Create data directory structure ───────────────────────────────────────────
info "Creating data directories..."
mkdir -p data/{db,results,cache,logs,profiles,wordlists}
mkdir -p data/cache/{dns,whois,crtsh,google}
mkdir -p logs/scans
success "Directory structure created ✓"

# ── Copy .env if not exists ───────────────────────────────────────────────────
if [[ ! -f .env ]]; then
    cp .env.example .env
    success ".env created from template (edit to add API keys)"
else
    warn ".env already exists — skipping"
fi

# ── Check optional system tools ───────────────────────────────────────────────
echo ""
info "Checking optional system tools..."

check_tool() {
    if command -v "$1" &> /dev/null; then
        success "$1 found ✓"
    else
        warn "$1 not found — $2"
    fi
}

check_tool nmap    "port scanning limited to async TCP fallback (install: apt install nmap)"
check_tool masscan "mass scanning unavailable (install: apt install masscan)"
check_tool whois   "WHOIS fallback active (install: apt install whois)"

# ── Verify framework loads ────────────────────────────────────────────────────
echo ""
info "Verifying framework imports..."
$PY -c "
import sys
sys.path.insert(0, '.')
try:
    from src.core.engine import MODULE_REGISTRY, MODULE_GROUPS
    from src.core.config import config
    from src.core.profiles import ProfileManager
    total_mods = len(MODULE_REGISTRY)
    total_prof = len(ProfileManager.list_all())
    print(f'  Modules loaded : {total_mods}')
    print(f'  Profiles loaded: {total_prof}')
except Exception as e:
    print(f'  Warning: {e}')
    sys.exit(1)
" && success "Framework verified ✓" || warn "Some imports failed — check requirements"

# ── Print quick-start ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${RESET}"
echo -e "${WHITE}  Installation complete! Quick start:${RESET}"
echo ""
echo -e "  ${CYAN}python3 projectz.py example.com quick${RESET}"
echo -e "  ${CYAN}python3 projectz.py example.com --profile pentest${RESET}"
echo -e "  ${CYAN}python3 projectz.py example.com --profile red_team -f html${RESET}"
echo -e "  ${CYAN}python3 projectz.py --preflight${RESET}  ← check API keys"
echo -e "  ${CYAN}python3 projectz.py --list-profiles${RESET}"
echo ""
echo -e "  ${YELLOW}Edit .env to add free API keys for better results${RESET}"
echo -e "${GREEN}════════════════════════════════════════════════════════${RESET}"
echo ""
