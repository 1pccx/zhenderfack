#!/bin/bash

# NetDefender Snort Setup & Network Optimization Script
# This script sets up Snort, configures persistent Netplan for the Snort VM, and configures pigrelay connection.

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_prompt() {
    echo -e "${BLUE}[INPUT]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run this script as root or with sudo"
    exit 1
fi

# 1. Recover from any previously broken dpkg/apt states (auto-heal VMs)
print_status "Recovering from any potentially broken previous package installation states..."
dpkg --configure -a || true
apt --fix-broken install -y || true

# 2. Update package list
print_status "Updating package list..."
apt update

# 3. Non-interactive installation of Snort packages to prevent debian frontend prompts
print_status "Installing Snort and networking tools (non-interactive mode)..."
export DEBIAN_FRONTEND=noninteractive
apt install -y \
    python3 \
    python3-pip \
    snort \
    vim \
    screen \
    net-tools

# 4. Install python dependencies
print_status "Installing Python dependencies..."
python3 -m pip install scapy six

# 5. Configure Netplan interactively to make Snort's static IP persistent across reboots
print_status "Backing up existing Netplan configuration on Snort VM..."
cp /etc/netplan/*.yaml /etc/netplan/01-network-manager-all.yaml.backup || true
touch /etc/netplan/01-network-manager-all.yaml

NETPLAN_CONFIGURED=false
while [ "$NETPLAN_CONFIGURED" = false ]; do
    print_status "Configuring Snort VM Netplan network..."
    print_warning "Available network interfaces on this machine:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo

    print_prompt "Enter the network interface name (e.g., ens33):"
    read -r INTERFACE

    if [ -z "$INTERFACE" ]; then
        print_error "Interface cannot be empty"
        exit 1
    fi

    print_prompt "Enter the persistent static IP address for $INTERFACE (e.g., 192.168.8.133/24):"
    read -r SNORT_IP

    print_prompt "Enter the default gateway for $INTERFACE (e.g., 192.168.8.2):"
    read -r SNORT_GATEWAY

    print_prompt "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4):"
    read -r SNORT_DNS
    DNS1=$(echo "$SNORT_DNS" | cut -d',' -f1 | tr -d ' ')
    DNS2=$(echo "$SNORT_DNS" | cut -d',' -f2 | tr -d ' ')

    # Build persistent Netplan configuration
    cat > /etc/netplan/01-network-manager-all.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - $SNORT_IP
      routes:
        - to: default
          via: $SNORT_GATEWAY
      nameservers:
        addresses:
          - $DNS1
EOF

    if [[ -n "$DNS2" ]]; then
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
          - $DNS2
EOF
    fi

    echo ""
    print_status "Generated Snort VM Netplan Configuration:"
    echo "========================================="
    cat /etc/netplan/01-network-manager-all.yaml
    echo "========================================="
    echo ""

    print_prompt "Does this configuration look correct? (y/n):"
    read -r CONFIRM

    if [[ "$CONFIRM" == "y" ]] || [[ "$CONFIRM" == "Y" ]]; then
        NETPLAN_CONFIGURED=true
        print_status "Configuration accepted."
    else
        print_warning "Configuration rejected. Restarting Netplan prompt..."
        echo ""
    fi
done

# Set permissions and apply netplan
chmod 600 /etc/netplan/*yaml
print_status "Applying persistent Netplan network..."
systemctl restart systemd-networkd || true
netplan apply || true

# 6. Set network interface to promiscuous mode
print_status "Setting interface $INTERFACE to promiscuous mode..."
ifconfig "$INTERFACE" promisc || true
ip link set "$INTERFACE" promisc on || true

# 7. Configure pigrelay.py with Controller IP
print_status "Configuring pigrelay.py..."
print_prompt "Enter the Ryu Controller IP address (default: 192.168.8.132):"
read -r CONTROLLER_IP
CONTROLLER_IP=${CONTROLLER_IP:-192.168.8.132}

if [ -f "./pigrelay.py" ]; then
    sed -i "s/CONTROLLER_IP = .*/CONTROLLER_IP = '$CONTROLLER_IP'/g" ./pigrelay.py
    print_status "Updated CONTROLLER_IP in pigrelay.py to $CONTROLLER_IP"
else
    print_error "pigrelay.py not found"
    exit 1
fi

if [ -f "./settings.py" ]; then
    sed -i "s/CONTROLLER_IP = .*/CONTROLLER_IP = '$CONTROLLER_IP'/g" ./settings.py
    print_status "Updated CONTROLLER_IP in settings.py to $CONTROLLER_IP"
fi

# Stop any old screen sessions
print_status "Cleaning up old Snort sessions..."
screen -S snort -X quit >/dev/null 2>&1 || true
screen -S pigrelay -X quit >/dev/null 2>&1 || true

# Start Snort in background screen session
print_status "Starting Snort in a background screen session..."
screen -dmS snort snort -i "$INTERFACE" -A unsock -l /tmp -c /etc/snort/snort.conf

# Ask if user wants to run pigrelay.py now
print_prompt "Do you want to start pigrelay.py now? (y/n):"
read -r -n 1 -r REPLY
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Starting pigrelay.py..."
    python3 pigrelay.py
else
    print_status "========================================================="
    print_status "NetDefender Snort Setup Completed successfully!"
    print_status "========================================================="
    print_status "To start pigrelay.py later, run:"
    echo "    cd $(pwd)"
    echo "    python3 pigrelay.py"
    echo ""
    print_status "To check Snort capture screen, run:"
    echo "    screen -r snort"
    print_status "========================================================="
fi