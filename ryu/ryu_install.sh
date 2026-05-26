#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Installing Ryu + PostgreSQL + Docker demo services"

apt update
apt upgrade -y

apt install -y \
    openvswitch-switch \
    vim \
    net-tools \
    screen \
    git \
    curl \
    docker.io \
    postgresql \
    postgresql-contrib \
    python3 \
    python3-pip \
    python3-dev

print_status "Installing Python packages"

pip3 uninstall -y ryu os-ken eventlet dnspython setuptools || true

pip3 install "setuptools==67.6.1" wheel
pip3 install "dnspython==1.16.0"
pip3 install "eventlet==0.30.2"
pip3 install --no-build-isolation "ryu==4.34"
pip3 install psycopg2-binary requests six scapy docker tabulate

print_status "Configuring Open vSwitch"

systemctl restart openvswitch-switch

ovs-vsctl --may-exist add-br br0
ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
ovs-vsctl set bridge br0 protocols=OpenFlow13

print_status "Starting PostgreSQL"

systemctl enable postgresql
systemctl start postgresql

print_status "Creating database and table"

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

print_status "Starting Docker normal server and honeypot"

docker rm -f normal-server honeypot >/dev/null 2>&1 || true

docker run -d --name normal-server -p 9090:80 nginx
docker run -d --name honeypot -p 8080:80 nginx

print_status "Testing Docker services"

curl -s http://127.0.0.1:9090 >/dev/null && print_status "normal-server OK"
curl -s http://127.0.0.1:8080 >/dev/null && print_status "honeypot OK"

print_status "Ryu setup completed"
print_status "Start Ryu with:"
echo "cd $(pwd)"
echo "ryu-manager ovs.py"