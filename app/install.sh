#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting installation of penetration testing tools based on config.json..."

# Function to check if a command exists
command_exists () {
    command -v "$1" >/dev/null 2>&1
}

# --- Update System Packages ---
echo ""
echo "Updating system packages..."
sudo apt update -y
sudo apt upgrade -y

# --- Install Common Dependencies ---
echo ""
echo "Installing common dependencies for Go and Python tools..."
sudo apt install -y git make gcc libpcap-dev python3 python3-pip

# --- Go Tools Installation ---
# Ensure Go is installed and GOPATH/GOBIN are set
if ! command_exists go; then
    echo ""
    echo "Go is not installed. Please install Go and set up GOPATH/GOBIN before running this script."
    echo "You can follow instructions from https://golang.org/doc/install"
    exit 1
fi

export GOBIN="/home/koimet/go/bin" # Ensure GOBIN is set as per your configuration
mkdir -p "$GOBIN"
echo "Go environment detected. Installing Go tools to $GOBIN..."

# Mapping tool names from config.json to their Go module paths
declare -A GO_TOOLS_MAP=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    ["subjs"]="github.com/lc/subjs@latest" # common module path for subjs
    ["webanalyze"]="github.com/rverton/webanalyze/cmd/webanalyze@latest" # Correct Go path
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx"
    ["getjs"]="github.com/003random/getJS/v2@latest" # common module path for getJS
    ["gf"]="github.com/tomnomnom/gf"
    ["amass"]="github.com/OWASP/Amass/v3/cmd/amass"
    ["fakjs"]="github.com/thd3r/fakjs@latest" # Added fakjs as a Go tool
)

for tool_name in "${!GO_TOOLS_MAP[@]}"; do
    module_path="${GO_TOOLS_MAP[$tool_name]}"
    # Determine the actual binary name that `go install` will produce
    binary_name=$(basename "$module_path")
    # If the path includes /cmd/toolname, the binary name is 'toolname'
    if [[ "$binary_path" == *"/cmd/"* ]]; then
        binary_name=$(echo "$module_path" | awk -F'/cmd/' '{print $2}' | cut -d'@' -f1)
    elif [[ "$binary_name" == *"@"* ]]; then
        binary_name=$(echo "$binary_name" | cut -d'@' -f1)
    fi

    target_path="$GOBIN/$binary_name"

    if [ ! -f "$target_path" ]; then
        echo "Installing $tool_name from $module_path..."
        go install "$module_path"
    else
        echo "$tool_name already exists at $target_path. Skipping."
    fi
done

# Nuclei Templates (still needed for Nuclei to function)
NUCLEI_TEMPLATES_PATH="/home/koimet/nuclei-templates"
if [ ! -d "$NUCLEI_TEMPLATES_PATH" ]; then
    echo ""
    echo "Cloning Nuclei Templates to $NUCLEI_TEMPLATES_PATH..."
    git clone https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_TEMPLATES_PATH"
else
    echo "Nuclei templates already exist at $NUCLEI_TEMPLATES_PATH. Skipping."
fi


# --- APT Package Installations ---
echo ""
echo "Installing tools via apt (nmap, masscan) if not present..."

APT_TOOLS=(
    "nmap"
    "masscan"
)

for tool in "${APT_TOOLS[@]}"; do
    if ! command_exists "$tool"; then
        echo "Installing $tool..."
        sudo apt install -y "$tool"
    else
        echo "$tool already installed. Skipping."
    fi
done

# --- Python Tools Installation ---
echo ""
echo "Installing Python tools..."

# Paramspider
PARAMSPIDER_DIR="/opt/paramspider"
if [ ! -d "$PARAMSPIDER_DIR" ]; then
    echo "Cloning Paramspider to $PARAMSPIDER_DIR..."
    sudo git clone https://github.com/devanshbatham/paramspider.git "$PARAMSPIDER_DIR"
    echo "Installing Paramspider dependencies..."
    (
        cd "$PARAMSPIDER_DIR"
        sudo pip3 install . # Install from current directory
    )
    # Paramspider executable might be in ~/.local/bin or /usr/local/bin depending on pip setup
    # If it's not in PATH, you might need to symlink it.
    if ! command_exists "paramspider"; then
        echo "Attempting to create symlink for paramspider to /usr/local/bin/..."
        # Check if it's in ~/.local/bin and symlink
        if [ -f "$HOME/.local/bin/paramspider" ]; then
            sudo ln -s "$HOME/.local/bin/paramspider" "/usr/local/bin/paramspider"
        else
            echo "Warning: paramspider executable not found in default pip locations. You might need to manually symlink it or add ~/.local/bin to your PATH."
        fi
    fi
else
    echo "Paramspider already exists at $PARAMSPIDER_DIR. Skipping cloning and installation."
    echo "To ensure it's updated, you might manually run: (cd $PARAMSPIDER_DIR && sudo git pull && sudo pip3 install .)"
fi


# LinkFinder
LINKFINDER_DIR="/opt/LinkFinder"
if [ ! -d "$LINKFINDER_DIR" ]; then
    echo "Cloning LinkFinder to $LINKFINDER_DIR..."
    sudo git clone https://github.com/GerbenJavado/LinkFinder.git "$LINKFINDER_DIR"
    echo "Installing LinkFinder dependencies and setting up..."
    # Navigate to the directory to run setup.py
    (cd "$LINKFINDER_DIR" && sudo python3 setup.py install)
else
    echo "LinkFinder already exists at $LINKFINDER_DIR. Skipping cloning and installation."
    echo "To ensure it's updated, you might manually run: (cd $LINKFINDER_DIR && sudo git pull && sudo python3 setup.py install)"
fi

# Subdover
SUBDOVER_DIR="/opt/subdover"
if [ ! -d "$SUBDOVER_DIR" ]; then
    echo "Cloning subdover to $SUBDOVER_DIR..."
    sudo git clone https://github.com/PushpenderIndia/subdover.git "$SUBDOVER_DIR"
    echo "Installing subdover dependencies and setting up..."
    # Navigate to the directory for installation
    (
        cd "$SUBDOVER_DIR"
        sudo chmod +x installer_linux.py
        sudo python3 installer_linux.py
        sudo chmod +x subdover.py # Make main script executable
    )
    # Create a symlink to make it accessible from anywhere
    if [ ! -f "/usr/local/bin/subdover" ]; then
        echo "Creating symlink for subdover to /usr/local/bin/subdover..."
        sudo ln -s "$SUBDOVER_DIR/subdover.py" "/usr/local/bin/subdover"
    else
        echo "Symlink for subdover already exists."
    fi
else
    echo "subdover already exists at $SUBDOVER_DIR. Skipping cloning and installation."
    echo "To ensure it's updated, you might manually run: (cd $SUBDOVER_DIR && sudo git pull && sudo python3 installer_linux.py)"
fi

echo ""
echo "Installation script finished."
echo "Remember to source your shell configuration file (e.g., 'source ~/.bashrc' or 'source ~/.zshrc') if Go paths were just set."
echo "Verify installations by running each tool's command (e.g., 'subfinder -h', 'nmap -h', 'subdover --help')."
