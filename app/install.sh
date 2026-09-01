#!/bin/bash
# Exit on error, unset variables are errors, and pipe failures are caught
set -euo pipefail

# Color output for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# Pick package manager based on the operating system
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
fi
case "${ID:-}" in
    fedora|rhel|centos) PKG_MGR="dnf" ;;
    *)
        case "${ID_LIKE:-}" in
            *fedora*|*rhel*|*centos*) PKG_MGR="dnf" ;;
            *) PKG_MGR="apt" ;;
        esac
        ;;
esac

pkg_install() {
    if [ "$PKG_MGR" = "dnf" ]; then
        sudo dnf install -y "$@"
    else
        sudo apt install -y "$@"
    fi
}

# ---------------------------------------------------------------------
# 1. Update system and install base dependencies
# ---------------------------------------------------------------------
print_info "Updating system packages and installing base dependencies..."
if [ "$PKG_MGR" = "dnf" ]; then
    sudo dnf makecache
    pkg_install git make gcc libpcap-devel python3 python3-pip python3-devel curl wget
else
    sudo apt update -y
    sudo apt upgrade -y
    pkg_install git make gcc libpcap-dev python3 python3-pip python3-venv curl wget
fi

# ---------------------------------------------------------------------
# 2. Ensure Go is installed and set up GOPATH/GOBIN
# ---------------------------------------------------------------------
if ! command_exists go; then
    print_error "Go is not installed. Please install Go from https://golang.org/doc/install"
    exit 1
fi
export GOPATH="${GOPATH:-$HOME/go}"
export GOBIN="${GOBIN:-$GOPATH/bin}"
mkdir -p "$GOBIN"
print_info "Go environment: GOPATH=$GOPATH, GOBIN=$GOBIN"
export PATH="$GOBIN:$HOME/.local/bin:$PATH"

# ---------------------------------------------------------------------
# 3. Install Go tools
# ---------------------------------------------------------------------
print_info "Installing/Updating Go tools..."
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["subjs"]="github.com/lc/subjs@latest"
    ["webanalyze"]="github.com/rverton/webanalyze/cmd/webanalyze@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["getjs"]="github.com/003random/getJS/v2@latest"
    ["gf"]="github.com/tomnomnom/gf@latest"
    ["amass"]="github.com/owasp-amass/amass/v3/cmd/amass@latest"
    ["fakjs"]="github.com/thd3r/fakjs@latest"
    ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
)

for tool in "${!GO_TOOLS[@]}"; do
    module="${GO_TOOLS[$tool]}"
    print_info "Installing $tool from $module ..."
    go install "$module"
    
    # Verify
    if command_exists "$tool"; then
        print_info "$tool installed successfully → $(command -v $tool)"
    else
        print_warn "$tool may not be in PATH. Try restarting shell or check $GOBIN"
    fi
done

# ---------------------------------------------------------------------
# 4. Clone / Update Nuclei templates
# ---------------------------------------------------------------------
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"
if [ ! -d "$NUCLEI_TEMPLATES_DIR" ]; then
    print_info "Cloning Nuclei templates to $NUCLEI_TEMPLATES_DIR ..."
    git clone https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_TEMPLATES_DIR"
else
    print_info "Updating Nuclei templates in $NUCLEI_TEMPLATES_DIR ..."
    (cd "$NUCLEI_TEMPLATES_DIR" && git pull --ff-only) || print_warn "Failed to update templates (git pull)."
fi

# ---------------------------------------------------------------------
# 5. Install APT packages (nmap, masscan)
# ---------------------------------------------------------------------
print_info "Installing scanner packages..."
for pkg in nmap masscan; do
    if ! command_exists "$pkg"; then
        pkg_install "$pkg"
        print_info "$pkg installed."
    else
        print_warn "$pkg already installed."
    fi
done

# ---------------------------------------------------------------------
# 6. Install Python tools
# ---------------------------------------------------------------------
print_info "Installing Python-based tools..."

# 6a. Paramspider
PARAMSPIDER_DIR="/opt/paramspider"
if [ ! -d "$PARAMSPIDER_DIR" ]; then
    print_info "Cloning Paramspider..."
    sudo git clone https://github.com/devanshbatham/paramspider.git "$PARAMSPIDER_DIR"
    (cd "$PARAMSPIDER_DIR" && sudo python3 -m pip install .)
    sudo ln -sf /root/.local/bin/paramspider /usr/local/bin/paramspider 2>/dev/null || true
else
    print_warn "Paramspider already exists."
fi

# 6b. LinkFinder
LINKFINDER_DIR="/opt/LinkFinder"
if [ ! -d "$LINKFINDER_DIR" ]; then
    print_info "Cloning LinkFinder..."
    sudo git clone https://github.com/GerbenJavado/LinkFinder.git "$LINKFINDER_DIR"
    (cd "$LINKFINDER_DIR" && sudo python3 setup.py install)
else
    print_warn "LinkFinder already exists."
fi

# 6c. cloud_enum
CLOUD_ENUM_DIR="/opt/cloud_enum"
if [ ! -d "$CLOUD_ENUM_DIR" ]; then
    print_info "Installing cloud_enum..."
    sudo git clone https://github.com/initstring/cloud_enum.git "$CLOUD_ENUM_DIR"
    (cd "$CLOUD_ENUM_DIR" && sudo python3 -m pip install -r requirements.txt --break-system-packages)
    sudo ln -sf "$CLOUD_ENUM_DIR/cloud_enum.py" /usr/local/bin/cloud_enum
    sudo chmod +x /usr/local/bin/cloud_enum
else
    print_warn "cloud_enum already exists."
fi

# ---------------------------------------------------------------------
# 7. Final summary & verification
# ---------------------------------------------------------------------
echo ""
print_info "Installation completed!"

echo "Key tools verification:"
for tool in subfinder dnsx nuclei httpx ffuf nmap amass paramspider; do
    if command_exists "$tool"; then
        print_info "✓ $tool → $(command -v $tool)"
    else
        print_warn "✗ $tool not found in PATH"
    fi
done

print_info "Add these lines to ~/.bashrc (or ~/.zshrc) and restart your shell:"
echo "   export PATH=\"\$PATH:$GOBIN:\$HOME/.local/bin:/usr/local/bin\""
echo "   export NUCLEI_TEMPLATES_PATH=$NUCLEI_TEMPLATES_DIR"

print_info "Done! Test tools with: <toolname> -h"