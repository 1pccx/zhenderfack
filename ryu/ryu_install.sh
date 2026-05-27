#!/bin/bash

# NetDefender Ryu + PostgreSQL + Docker Setup Script
# This script sets up the Ryu VM environment with Open vSwitch, persistent Netplan, SSH, PostgreSQL, and custom Docker servers.

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_prompt() {
    echo -e "${BLUE}[INPUT]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Starting NetDefender Ryu VM setup..."

# 1. Update and upgrade system packages
print_status "Updating system packages..."
apt update
apt upgrade -y

# 2. Install required packages
print_status "Installing required openvswitch, ssh, and system packages..."
apt install -y \
    openvswitch-switch \
    vim \
    net-tools \
    iptables-persistent \
    dhcpcd5 \
    htop \
    ifmetric \
    software-properties-common \
    screen \
    dnsmasq \
    postgresql \
    postgresql-contrib \
    git \
    curl \
    openssh-server

# 3. Configure SSH Server
print_status "Configuring SSH Server..."
systemctl enable ssh
systemctl start ssh

# 4. Install specific Docker version
print_status "Installing Docker..."
apt install docker.io=20.10.12-0ubuntu4 -y || apt install docker.io -y

# 5. Add Python PPA and Install Python 3.9
print_status "Adding Python PPA repository for Python 3.9..."
add-apt-repository -y ppa:deadsnakes/ppa
apt update

print_status "Installing Python 3.9 and utilities..."
apt install -y python3.9 python3.9-distutils python3.9-venv

# 6. Install pip and libraries specifically for Python 3.9
print_status "Installing pip for Python 3.9..."
if [ -f "get-pip.py" ]; then
    python3.9 get-pip.py
else
    curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3.9 get-pip.py
fi

print_status "Installing Python packages for Ryu and PostgreSQL integration..."
python3.9 -m pip install "setuptools==67.6.1" wheel
python3.9 -m pip install "dnspython==1.16.0"
python3.9 -m pip install "eventlet==0.30.2"
python3.9 -m pip install --no-build-isolation "ryu==4.34"
python3.9 -m pip install psycopg2-binary requests six scapy docker tabulate

# 7. Configure Docker Network Plugin and virtual ethernet interfaces
print_status "Configuring Docker net-dhcp plugin..."
docker plugin install --grant-all-permissions ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64 || true

print_status "Creating virtual ethernet pair and veth interface configurations..."
ip link delete veth0 >/dev/null 2>&1 || true
ip link delete my-bridge >/dev/null 2>&1 || true
ip link add veth0 type veth peer name veth1 || true
ip addr add 192.168.100.1/24 dev veth0 || true
ip link add my-bridge type bridge || true
ip link set my-bridge up || true
ip link set veth1 master my-bridge || true
ip link set veth0 up || true
ip link set veth1 up || true

# 8. Configure iptables and IP forwarding
print_status "Configuring firewall and IP forwarding rules..."
iptables -A FORWARD -i my-bridge -j ACCEPT || true
iptables -I FORWARD -o my-bridge -j ACCEPT || true
iptables -P FORWARD ACCEPT || true

if ! grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
    if grep -q "^#net.ipv4.ip_forward" /etc/sysctl.conf; then
        sed -i 's/^#net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    elif grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
fi
sysctl -p

# 9. Configure dnsmasq
print_status "Configuring dnsmasq service..."
cat > /etc/dnsmasq.conf << EOF
port=0
interface=veth0
no-dhcp-interface=br0
listen-address=192.168.100.1
listen-address=127.0.0.1
dhcp-range=192.168.100.2,192.168.100.254,255.255.255.0,1h
dhcp-option=3,192.168.100.1
dhcp-option=28,192.168.100.255
dhcp-option=6,8.8.8.8,8.8.4.4
EOF

# 10. Configure Netplan interactively with loop for re-entry
print_status "Backing up existing Netplan configuration..."
cp /etc/netplan/*.yaml /etc/netplan/01-network-manager-all.yaml.backup || true
touch /etc/netplan/01-network-manager-all.yaml

NETPLAN_CONFIGURED=false
while [ "$NETPLAN_CONFIGURED" = false ]; do
    print_status "Configuring Netplan bridging..."
    print_warning "Available network interfaces on this machine:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo

    print_prompt "Enter the primary network interface name for the bridge (e.g., ens33):"
    read -r PRIMARY_INTERFACE

    print_prompt "Enter the static IP address for the br0 bridge (e.g., 192.168.8.132/24):"
    read -r BR0_IP

    print_prompt "Enter the default gateway for br0 (e.g., 192.168.8.2):"
    read -r BR0_GATEWAY

    print_prompt "Enter DNS servers for br0 (comma-separated, e.g., 8.8.8.8,8.8.4.4):"
    read -r BR0_DNS
    BR0_DNS1=$(echo "$BR0_DNS" | cut -d',' -f1 | tr -d ' ')
    BR0_DNS2=$(echo "$BR0_DNS" | cut -d',' -f2 | tr -d ' ')

    print_prompt "Do you want to configure a secondary interface? (y/n):"
    read -r CONFIGURE_SECONDARY

    # Start building netplan configuration
    cat > /etc/netplan/01-network-manager-all.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: no
EOF

    # Add secondary interface configuration if requested
    if [[ "$CONFIGURE_SECONDARY" == "y" ]] || [[ "$CONFIGURE_SECONDARY" == "Y" ]]; then
        print_prompt "Enter the secondary network interface name (e.g., ens34):"
        read -r SECONDARY_INTERFACE
        
        print_prompt "Enter the IP address for $SECONDARY_INTERFACE (e.g., 192.168.1.104/24):"
        read -r SECONDARY_IP
        
        print_prompt "Enter the default gateway for $SECONDARY_INTERFACE (e.g., 192.168.1.1):"
        read -r SECONDARY_GATEWAY
        
        print_prompt "Enter the route metric for $SECONDARY_INTERFACE (e.g., 100):"
        read -r SECONDARY_METRIC
        
        print_prompt "Enter DNS servers for $SECONDARY_INTERFACE (comma-separated, e.g., 8.8.8.8,8.8.4.4):"
        read -r SECONDARY_DNS
        SECONDARY_DNS1=$(echo "$SECONDARY_DNS" | cut -d',' -f1 | tr -d ' ')
        SECONDARY_DNS2=$(echo "$SECONDARY_DNS" | cut -d',' -f2 | tr -d ' ')
        
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
    $SECONDARY_INTERFACE:
      addresses:
        - $SECONDARY_IP
EOF
        
        if [[ -n "$SECONDARY_DNS2" ]]; then
            cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $SECONDARY_DNS1
          - $SECONDARY_DNS2
EOF
        else
            cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $SECONDARY_DNS1
EOF
        fi
        
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      routes:
        - to: default
          via: $SECONDARY_GATEWAY
          metric: $SECONDARY_METRIC
EOF
    fi

    # Add OVS bridge configuration
    cat >> /etc/netplan/01-network-manager-all.yaml << EOF
  bridges:
    br0:
      interfaces: [$PRIMARY_INTERFACE]
      addresses:
        - $BR0_IP
EOF

    if [[ -n "$BR0_DNS2" ]]; then
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $BR0_DNS1
          - $BR0_DNS2
EOF
    else
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $BR0_DNS1
EOF
    fi

    cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      routes:
        - to: default
          via: $BR0_GATEWAY
      parameters:
        stp: false
        forward-delay: 0
      openvswitch:
        fail-mode: standalone
        controller:
          addresses:
            - tcp:127.0.0.1:6653
EOF

    echo ""
    print_status "Generated Netplan Configuration:"
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
        print_warning "Configuration rejected. Restarting netplan configuration prompt..."
        echo ""
    fi
done

# Set correct permission and apply Netplan
chmod 600 /etc/netplan/*yaml
print_status "Applying Netplan configuration..."
systemctl restart systemd-networkd || true
netplan apply || true

# 11. Configure Open vSwitch protocols
print_status "Configuring Open vSwitch Bridge br0..."
systemctl restart openvswitch-switch
ovs-vsctl --may-exist add-br br0
ovs-vsctl set bridge br0 protocols=OpenFlow13
ovs-vsctl set-controller br0 tcp:127.0.0.1:6653 || true

# Restart dnsmasq and interfaces
print_status "Restarting network interfaces and dnsmasq..."
systemctl restart dnsmasq || true
dhclient veth1 || print_warning "dhclient veth1 failed, continuing..."
dhcpcd my-bridge || true

# 12. PostgreSQL Database setup
print_status "Configuring local PostgreSQL database (fallback/testing support)..."
systemctl enable postgresql
systemctl start postgresql

sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='security_db'" | grep -q 1 || \
sudo -u postgres createdb security_db

sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='data_user'" | grep -q 1 || \
sudo -u postgres psql -c "CREATE USER data_user WITH PASSWORD '1234567890';"

sudo -u postgres psql -c "ALTER USER data_user WITH PASSWORD '1234567890';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE security_db TO data_user;"

sudo -u postgres psql -d security_db << EOF
CREATE TABLE IF NOT EXISTS incoming_commands (
    id SERIAL PRIMARY KEY,
    src_ip TEXT,
    dst_ip TEXT,
    command_text TEXT,
    predicted_label TEXT,
    risk_level TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

GRANT ALL PRIVILEGES ON TABLE incoming_commands TO data_user;
GRANT USAGE, SELECT ON SEQUENCE incoming_commands_id_seq TO data_user;
EOF

# 13. Docker custom mock servers and network
print_status "Creating Docker network..."
docker network create -d ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64 \
    --ipam-driver null \
    -o bridge=my-bridge \
    my-dhcp-net || print_warning "Docker network my-dhcp-net already exists or net-dhcp plugin skipped"

print_status "Configuring custom mock HTML pages for Normal Server and Honeypot..."
export DOCKER_API_VERSION=1.41

docker rm -f normal-server honeypot 2>/dev/null

mkdir -p /root/normal-web /root/honeypot-web
echo "NORMAL SERVER" > /root/normal-web/index.html
echo "HONEYPOT SERVER" > /root/honeypot-web/index.html

print_status "Starting custom volume-mounted Nginx containers..."
docker run -d --name normal-server -p 9090:80 -v /root/normal-web:/usr/share/nginx/html:ro nginx
docker run -d --name honeypot -p 8080:80 -v /root/honeypot-web:/usr/share/nginx/html:ro nginx

print_status "========================================================="
print_status "NetDefender Ryu VM Setup Completed Successfully!"
print_status "========================================================="
print_status "To run your Ryu controller, use:"
echo "    python3.9 -m ryu.cmd.manager ovs.py"
print_status "To connect to PostgreSQL manually, use:"
echo "    psql -h localhost -U data_user -d security_db"
print_status "========================================================="