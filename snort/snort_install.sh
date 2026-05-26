#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

if [ "$EUID" -ne 0 ]; then
    print_error "Please run this script as root or with sudo"
    exit 1
fi

print_status "Updating package list"
apt update

print_status "Installing Snort packages"
apt install -y \
    python3 \
    python3-pip \
    snort \
    vim \
    screen \
    net-tools

pip3 install scapy six

print_prompt "Enter Snort interface name, e.g. ens33:"
read -r INTERFACE

if [ -z "$INTERFACE" ]; then
    print_error "Interface cannot be empty"
    exit 1
fi

print_status "Setting $INTERFACE to promiscuous mode"
ifconfig "$INTERFACE" promisc || true
ip link set "$INTERFACE" promisc on || true

print_status "Configuring pigrelay.py"

CONTROLLER_IP="192.168.8.132"

if [ -f "./pigrelay.py" ]; then
    sed -i "s/^CONTROLLER_IP = .*/CONTROLLER_IP = '$CONTROLLER_IP'/g" ./pigrelay.py
    print_status "Updated CONTROLLER_IP to $CONTROLLER_IP"
else
    print_error "pigrelay.py not found"
    exit 1
fi

print_status "Stopping old sessions"
screen -S snort -X quit >/dev/null 2>&1 || true
screen -S pigrelay -X quit >/dev/null 2>&1 || true

print_status "Starting Snort"

screen -dmS snort \
snort -i "$INTERFACE" \
-A unsock \
-l /tmp \
-c /etc/snort/snort.conf

sleep 2

print_status "Starting pigrelay"

screen -dmS pigrelay python3 pigrelay.py

print_status "Snort setup completed"

echo "screen -r snort"
echo "screen -r pigrelay"