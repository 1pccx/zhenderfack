#!/bin/bash

# NetDefender High-Speed CLI DB Synchronization Script
# This script handles the pipeline transfer between Ryu VM Local DB and Remote Rack DB.

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# 1. Configuration
LOCAL_SQL_FILE="/root/packets.sql"
REMOTE_SSH_USER="lab"
REMOTE_SSH_IP="140.130.34.85"
REMOTE_SSH_PORT="52739"
REMOTE_DB_USER="postgres"
REMOTE_DB_NAME="security_db"
REMOTE_DB_PASS="1234567890"  # Remote rack database password

LOCAL_DB_USER="data_user"
LOCAL_DB_NAME="security_db"
LOCAL_DB_PASS="1234567890"   # Local Ryu database password


print_status "Starting DB Sync Pipeline..."

# 2. Step A: Upload packets log to Rack DB
if [ -f "$LOCAL_SQL_FILE" ] && [ -s "$LOCAL_SQL_FILE" ]; then
    print_status "Found new packet logs in local cache. Uploading to remote Rack DB..."
    
    # Temporarily rename to prevent concurrent writes from writing to the file we are uploading
    mv "$LOCAL_SQL_FILE" "${LOCAL_SQL_FILE}.tmp"
    
    # Upload via SSH pipeline (establishing the master connection) - ONLY uploading the last log statement
    if tac "${LOCAL_SQL_FILE}.tmp" | sed -n '1,/INSERT INTO/p' | tac | ssh -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPath=/tmp/ssh_mux_%h_%p_%r -o ControlPersist=10 -p "$REMOTE_SSH_PORT" "${REMOTE_SSH_USER}@${REMOTE_SSH_IP}" "PGPASSWORD=$REMOTE_DB_PASS psql -h localhost -U $REMOTE_DB_USER -d $REMOTE_DB_NAME" >/dev/null; then
        print_status "Successfully uploaded packet logs to Rack DB."
        rm -f "${LOCAL_SQL_FILE}.tmp"
    else
        print_error "Failed to upload packet logs. Restoring cache..."
        cat "${LOCAL_SQL_FILE}.tmp" >> "$LOCAL_SQL_FILE"
        rm -f "${LOCAL_SQL_FILE}.tmp"
    fi
else
    print_warning "No new packet logs to upload."
fi

# 3. Step B: Download ML Predictions from Rack DB and import into Local DB
print_status "Pulling ML prediction results from Remote Rack DB..."

# This SQL dynamically generates UPDATE commands on the rack and pipes them straight into the local Postgres CLI
SYNC_SQL="SELECT 'UPDATE incoming_commands SET predicted_label = ''' || predicted_label || ''', risk_level = ''' || risk_level || ''' WHERE src_ip = ''' || src_ip || ''';' FROM incoming_commands WHERE predicted_label IS NOT NULL AND created_at >= NOW() - INTERVAL '1 day';"

if ssh -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPath=/tmp/ssh_mux_%h_%p_%r -p "$REMOTE_SSH_PORT" "${REMOTE_SSH_USER}@${REMOTE_SSH_IP}" "PGPASSWORD=$REMOTE_DB_PASS psql -h localhost -U $REMOTE_DB_USER -d $REMOTE_DB_NAME -t -A -c \"$SYNC_SQL\"" | PGPASSWORD=$LOCAL_DB_PASS psql -h localhost -U $LOCAL_DB_USER -d $LOCAL_DB_NAME >/dev/null; then
    print_status "Successfully synchronized ML predictions into local DB!"
else
    print_error "Failed to pull prediction results from remote DB."
fi

print_status "Sync completed successfully."
