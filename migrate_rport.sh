#!/bin/bash

# OpenRPort to RPort Migration Script
# This script automates the migration from old openrport to new rport version
# Usage: ./migrate_rport.sh /path/to/new/rportd [--dry-run] [--backup-dir /path/to/backup]

set -euo pipefail

# Script configuration
SCRIPT_VERSION="1.0.0"
LOG_FILE="/tmp/rport_migration_$(date +%Y%m%d_%H%M%S).log"
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default paths (can be overridden)
RPORTD_BINARY_PATH="/usr/local/bin/rportd"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/rportd.service"
DATA_DIR="/var/lib/rport"
CONFIG_FILE="/etc/rport/rportd.conf"
API_AUTH_FILE="$DATA_DIR/api-auth.json"
BACKUP_DIR="/tmp/rport_migration_backup_$BACKUP_TIMESTAMP"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
DRY_RUN=false
FORCE_BACKUP=false

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case $level in
        "ERROR")   echo -e "${RED}[ERROR] $message${NC}" >&2 ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS] $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}[WARNING] $message${NC}" ;;
        "INFO")    echo -e "${BLUE}[INFO] $message${NC}" ;;
    esac
}

# Usage function
usage() {
    cat << EOF
OpenRPort to RPort Migration Script v$SCRIPT_VERSION

USAGE:
    $0 /path/to/new/rportd [OPTIONS]

DESCRIPTION:
    Automates migration from old openrport to new rport version.
    Handles binary replacement, configuration updates, and service management.

ARGUMENTS:
    /path/to/new/rportd    Path to the new rportd binary

OPTIONS:
    --dry-run              Show what would be done without making changes
    --backup-dir DIR       Custom backup directory (default: /tmp/rport_migration_backup_TIMESTAMP)
    --data-dir DIR         Custom data directory (default: /var/lib/rport)
    --config-file FILE     Custom config file path (default: /etc/rport/rportd.conf)
    --api-auth-file FILE   Custom API auth file path (default: \$DATA_DIR/api-auth.json)
    --service-file FILE    Custom systemd service file (default: /etc/systemd/system/rportd.service)
    --force-backup         Create backup even if service is not running
    --help, -h             Show this help message

EXAMPLES:
    # Basic migration
    sudo $0 ./new_rportd

    # Dry run to see what would happen
    sudo $0 ./new_rportd --dry-run

    # Migration with custom backup location
    sudo $0 ./new_rportd --backup-dir /home/admin/rport_backup

REQUIREMENTS:
    - Must be run as root
    - systemctl must be available
    - Current rportd service should exist

EOF
}

# Parse command line arguments
parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --data-dir)
                DATA_DIR="$2"
                API_AUTH_FILE="$DATA_DIR/api-auth.json"
                shift 2
                ;;
            --config-file)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --api-auth-file)
                API_AUTH_FILE="$2"
                shift 2
                ;;
            --service-file)
                SYSTEMD_SERVICE_FILE="$2"
                shift 2
                ;;
            --force-backup)
                FORCE_BACKUP=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "${NEW_BINARY_PATH:-}" ]]; then
                    NEW_BINARY_PATH="$1"
                else
                    log "ERROR" "Multiple binary paths specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [[ -z "${NEW_BINARY_PATH:-}" ]]; then
        log "ERROR" "New rportd binary path is required"
        usage
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi

    # Check if new binary exists and is executable
    if [[ ! -f "$NEW_BINARY_PATH" ]]; then
        log "ERROR" "New binary not found at: $NEW_BINARY_PATH"
        exit 1
    fi

    if [[ ! -x "$NEW_BINARY_PATH" ]]; then
        log "ERROR" "New binary is not executable: $NEW_BINARY_PATH"
        exit 1
    fi

    # Check if systemctl is available
    if ! command -v systemctl &> /dev/null; then
        log "ERROR" "systemctl not found. This script requires systemd."
        exit 1
    fi

    # Check if current binary exists
    if [[ ! -f "$RPORTD_BINARY_PATH" ]]; then
        log "WARNING" "Current rportd binary not found at: $RPORTD_BINARY_PATH"
        log "WARNING" "This might be a fresh installation"
    fi

    # Verify new binary version
    local new_version
    if new_version=$("$NEW_BINARY_PATH" --version 2>&1); then
        log "INFO" "New binary version: $new_version"
    else
        log "WARNING" "Could not determine new binary version"
    fi

    # Check current binary version if it exists
    if [[ -f "$RPORTD_BINARY_PATH" ]]; then
        local current_version
        if current_version=$("$RPORTD_BINARY_PATH" --version 2>&1); then
            log "INFO" "Current binary version: $current_version"
        else
            log "WARNING" "Could not determine current binary version"
        fi
    fi

    log "SUCCESS" "Prerequisites check completed"
}

# Create backup
create_backup() {
    log "INFO" "Creating backup in: $BACKUP_DIR"

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would create backup directory: $BACKUP_DIR"
        return 0
    fi

    mkdir -p "$BACKUP_DIR"

    # Backup current binary
    if [[ -f "$RPORTD_BINARY_PATH" ]]; then
        log "INFO" "Backing up current binary..."
        cp "$RPORTD_BINARY_PATH" "$BACKUP_DIR/rportd.backup"
        log "SUCCESS" "Binary backed up"
    else
        log "WARNING" "No current binary to backup"
    fi

    # Backup systemd service file
    if [[ -f "$SYSTEMD_SERVICE_FILE" ]]; then
        log "INFO" "Backing up systemd service file..."
        cp "$SYSTEMD_SERVICE_FILE" "$BACKUP_DIR/rportd.service.backup"
        log "SUCCESS" "Service file backed up"
    else
        log "WARNING" "No systemd service file to backup"
    fi

    # Backup configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Backing up configuration file..."
        cp "$CONFIG_FILE" "$BACKUP_DIR/rportd.conf.backup"
        log "SUCCESS" "Configuration backed up"
    else
        log "WARNING" "No configuration file to backup"
    fi

    # Backup API auth file
    if [[ -f "$API_AUTH_FILE" ]]; then
        log "INFO" "Backing up API auth file..."
        cp "$API_AUTH_FILE" "$BACKUP_DIR/api-auth.json.backup"
        log "SUCCESS" "API auth file backed up"
    else
        log "WARNING" "No API auth file to backup"
    fi

    # Backup critical database files specifically
    if [[ -f "$DATA_DIR/clients.db" ]]; then
        log "INFO" "Backing up clients database..."
        cp "$DATA_DIR/clients.db" "$BACKUP_DIR/clients.db.backup"
        log "SUCCESS" "Clients database backed up"
    else
        log "INFO" "No clients database to backup"
    fi

    # Backup other data directory files (excluding large DB temp files for safety)
    if [[ -d "$DATA_DIR" ]]; then
        log "INFO" "Backing up other data directory files..."
        rsync -av --exclude='*.db-shm' --exclude='*.db-wal' "$DATA_DIR/" "$BACKUP_DIR/data/" || log "WARNING" "Some data files may not have been backed up"
        log "SUCCESS" "Data directory backed up"
    else
        log "WARNING" "No data directory to backup"
    fi

    # Create backup info file
    cat > "$BACKUP_DIR/migration_info.txt" << EOF
RPort Migration Backup
Created: $(date)
Script Version: $SCRIPT_VERSION
Original Binary: $RPORTD_BINARY_PATH
New Binary: $NEW_BINARY_PATH
Data Directory: $DATA_DIR
Config File: $CONFIG_FILE
API Auth File: $API_AUTH_FILE
Service File: $SYSTEMD_SERVICE_FILE
EOF

    log "SUCCESS" "Backup completed in: $BACKUP_DIR"
}

# Check if service is running
check_service_status() {
    if systemctl is-active --quiet rportd; then
        log "INFO" "RPort service is currently running"
        return 0
    else
        log "INFO" "RPort service is not running"
        return 1
    fi
}

# Stop rport service
stop_service() {
    log "INFO" "Stopping rport service..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would stop rportd service"
        return 0
    fi

    if systemctl is-active --quiet rportd; then
        systemctl stop rportd
        log "SUCCESS" "RPort service stopped"
        
        # Wait for service to fully stop
        local count=0
        while systemctl is-active --quiet rportd && [[ $count -lt 30 ]]; do
            sleep 1
            ((count++))
        done
        
        if systemctl is-active --quiet rportd; then
            log "WARNING" "Service may not have stopped completely"
        fi
    else
        log "INFO" "Service was not running"
    fi
}

# Replace binary
replace_binary() {
    log "INFO" "Replacing rportd binary..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would replace $RPORTD_BINARY_PATH with $NEW_BINARY_PATH"
        return 0
    fi

    # Ensure directory exists
    mkdir -p "$(dirname "$RPORTD_BINARY_PATH")"

    # Copy new binary
    cp "$NEW_BINARY_PATH" "$RPORTD_BINARY_PATH"
    chmod +x "$RPORTD_BINARY_PATH"

    log "SUCCESS" "Binary replaced successfully"
}

# Set binary capabilities for port binding
set_binary_capabilities() {
    log "INFO" "Setting binary capabilities for port binding..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would set cap_net_bind_service capability on $RPORTD_BINARY_PATH"
        return 0
    fi

    # Check if setcap is available
    if ! command -v setcap &>/dev/null; then
        log "WARNING" "setcap not available, binary may need to run as root for privileged ports"
        return 0
    fi

    # Set capability to bind to privileged ports (< 1024) without root
    if setcap 'cap_net_bind_service=+ep' "$RPORTD_BINARY_PATH"; then
        log "SUCCESS" "Set cap_net_bind_service capability on binary"
        log "INFO" "Binary can now bind to privileged ports without running as root"
    else
        log "WARNING" "Failed to set capabilities, binary may need to run as root for privileged ports"
    fi
}

# Convert API auth file format or handle database auth
convert_api_auth() {
    log "INFO" "Checking API authentication method..."

    # Check if using file-based auth
    if [[ -f "$API_AUTH_FILE" ]]; then
        log "INFO" "File-based API authentication detected"
    else
        log "INFO" "File-based API auth not found - likely using database authentication"
        
        # Check if database authentication is configured
        if [[ -f "$CONFIG_FILE" ]]; then
            if grep -q "api-auth-user-table\|api_auth_user_table" "$CONFIG_FILE"; then
                log "SUCCESS" "Database-based API authentication detected - no file conversion needed"
                return 0
            fi
        fi
        
        log "INFO" "No API auth file to convert - this is normal for database-based authentication"
        return 0
    fi

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would check and convert API auth file format"
        return 0
    fi

    # Read the current file
    local content
    if ! content=$(cat "$API_AUTH_FILE"); then
        log "ERROR" "Failed to read API auth file"
        return 1
    fi

    # Check if it's already in array format
    if echo "$content" | jq -e 'type == "array"' &>/dev/null; then
        log "INFO" "API auth file is already in correct array format"
        
        # Check and fix bcrypt prefixes
        local needs_fix=false
        if echo "$content" | jq -r '.[].password' | grep -q '^\$2a\$'; then
            needs_fix=true
        fi
        
        if [[ $needs_fix == true ]]; then
            log "INFO" "Converting bcrypt prefixes from \$2a\$ to \$2y\$..."
            local temp_file=$(mktemp)
            echo "$content" | jq '.[].password |= sub("^\\$2a\\$"; "$2y$")' > "$temp_file"
            mv "$temp_file" "$API_AUTH_FILE"
            log "SUCCESS" "Bcrypt prefixes updated"
        fi
        
        return 0
    fi

    # Check if it's in object format
    if echo "$content" | jq -e 'type == "object"' &>/dev/null; then
        log "INFO" "Converting API auth file from object to array format..."
        
        local temp_file=$(mktemp)
        
        # Convert from object format to array format
        echo "$content" | jq -r 'to_entries | map({
            "username": .key,
            "password": (.value | sub("^\\$2a\\$"; "$2y$")),
            "groups": ["Administrators"]
        })' > "$temp_file"
        
        if [[ $? -eq 0 ]]; then
            mv "$temp_file" "$API_AUTH_FILE"
            log "SUCCESS" "API auth file converted to array format with fixed bcrypt prefixes"
        else
            rm -f "$temp_file"
            log "ERROR" "Failed to convert API auth file"
            return 1
        fi
    else
        log "ERROR" "API auth file format not recognized"
        return 1
    fi
}

# Fix database schema for regexp compatibility
fix_database_schema() {
    log "INFO" "Fixing database schema for regexp compatibility..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would fix database schema for regexp compatibility"
        return 0
    fi

    # Check if clients database exists
    local clients_db="$DATA_DIR/clients.db"
    if [[ ! -f "$clients_db" ]]; then
        log "INFO" "Clients database not found, skipping schema fix"
        return 0
    fi

    # Check if python3 is available for the fix
    if ! command -v python3 &>/dev/null; then
        log "WARNING" "python3 not available, skipping database schema fix"
        log "WARNING" "The database may have regexp compatibility issues"
        return 0
    fi

    # Check if there are any records with details to potentially fix
    local records_with_details
    if command -v sqlite3 &>/dev/null; then
        records_with_details=$(sqlite3 "$clients_db" "SELECT COUNT(*) FROM clients WHERE details IS NOT NULL AND details != '';" 2>/dev/null || echo "0")
        
        if [[ "$records_with_details" -eq 0 ]]; then
            log "INFO" "No client records with configuration found, skipping schema fix"
            return 0
        fi
        
        log "INFO" "Found $records_with_details client records to analyze"
    fi

    log "INFO" "Using Python-based fix for regexp compatibility (works with older SQLite)"
    
    # Create Python script to fix the database
    local temp_py=$(mktemp --suffix=.py)
    cat > "$temp_py" << 'EOF'
#!/usr/bin/env python3
import sqlite3
import json
import sys

def fix_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, details FROM clients WHERE details IS NOT NULL AND details != ''")
    records = cursor.fetchall()
    
    fixed_count = 0
    total_with_remote_commands = 0
    
    for record_id, details_json in records:
        try:
            details = json.loads(details_json)
            
            if ('client_configuration' in details and 
                'remote_commands' in details['client_configuration']):
                
                total_with_remote_commands += 1
                remote_commands = details['client_configuration']['remote_commands']
                needs_fix = False
                
                # Fix allow_regexp - convert string to array for new RPort version
                if 'allow_regexp' in remote_commands:
                    allow_regexp = remote_commands['allow_regexp']
                    if isinstance(allow_regexp, str):
                        # Convert string to array of strings (new format)
                        remote_commands['allow_regexp'] = [allow_regexp]
                        needs_fix = True
                    elif isinstance(allow_regexp, dict):
                        # Handle object case
                        if 'pattern' in allow_regexp:
                            remote_commands['allow_regexp'] = [allow_regexp['pattern']]
                        else:
                            remote_commands['allow_regexp'] = [".*"]
                        needs_fix = True
                
                # Fix deny_regexp - remove empty objects and ensure proper format
                if 'deny_regexp' in remote_commands:
                    deny_regexp = remote_commands['deny_regexp']
                    if isinstance(deny_regexp, list):
                        new_deny_list = []
                        for item in deny_regexp:
                            if isinstance(item, dict):
                                if item:  # non-empty dict
                                    if 'pattern' in item:
                                        new_deny_list.append(item['pattern'])
                                    else:
                                        new_deny_list.append(str(item))
                                # skip empty dicts {}
                                needs_fix = True
                            else:
                                new_deny_list.append(item)
                        if needs_fix:
                            remote_commands['deny_regexp'] = new_deny_list
                
                if needs_fix:
                    new_details_json = json.dumps(details, separators=(',', ':'))
                    cursor.execute("UPDATE clients SET details = ? WHERE id = ?", 
                                 (new_details_json, record_id))
                    fixed_count += 1
                    
        except (json.JSONDecodeError, Exception):
            continue
    
    conn.commit()
    conn.close()
    
    return fixed_count, total_with_remote_commands

if __name__ == "__main__":
    db_path = sys.argv[1]
    fixed, total = fix_database(db_path)
    print(f"{fixed},{total}")
EOF

    # Apply the fix
    local result
    if result=$(python3 "$temp_py" "$clients_db" 2>/dev/null); then
        local fixed_count=$(echo "$result" | cut -d',' -f1)
        local total_count=$(echo "$result" | cut -d',' -f2)
        
        rm -f "$temp_py"
        
        if [[ "$total_count" -eq 0 ]]; then
            log "INFO" "No remote command configurations found to fix"
        elif [[ "$fixed_count" -eq 0 ]]; then
            log "SUCCESS" "All remote command configurations are already in correct format"
        else
            log "SUCCESS" "Fixed $fixed_count out of $total_count remote command configurations"
            log "INFO" "Converted allow_regexp strings to arrays and removed empty deny_regexp objects"
        fi
        
        # Verify database integrity
        if command -v sqlite3 &>/dev/null; then
            if sqlite3 "$clients_db" "PRAGMA integrity_check;" | grep -q "ok"; then
                log "SUCCESS" "Database integrity verified"
            else
                log "WARNING" "Database integrity check inconclusive"
            fi
        fi
        
    else
        log "ERROR" "Failed to apply database schema fix"
        rm -f "$temp_py"
        return 1
    fi
}

# Validate configuration and database compatibility
validate_config() {
    log "INFO" "Validating configuration and database compatibility..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would validate configuration and database compatibility"
        return 0
    fi

    # Test the new binary with configuration
    if "$RPORTD_BINARY_PATH" -c "$CONFIG_FILE" --help &>/dev/null; then
        log "SUCCESS" "New binary accepts configuration format"
    else
        log "WARNING" "Could not validate configuration with new binary"
    fi

    # Validate API auth file format if it exists
    if [[ -f "$API_AUTH_FILE" ]]; then
        if cat "$API_AUTH_FILE" | jq empty 2>/dev/null; then
            log "SUCCESS" "API auth file has valid JSON format"
        else
            log "ERROR" "API auth file has invalid JSON format"
            return 1
        fi
    fi

    # Check database files exist and are accessible
    if [[ -f "$CONFIG_FILE" ]]; then
        local db_files
        db_files=$(grep -oP '(?<=db_file\s=\s")[^"]*' "$CONFIG_FILE" 2>/dev/null || true)
        
        if [[ -n "$db_files" ]]; then
            log "INFO" "Found SQLite database configuration"
            while IFS= read -r db_file; do
                if [[ -f "$db_file" ]]; then
                    log "SUCCESS" "Database file exists: $db_file"
                    
                    # Check if database is accessible
                    if command -v sqlite3 &>/dev/null; then
                        if sqlite3 "$db_file" "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1;" &>/dev/null; then
                            log "SUCCESS" "Database is accessible and contains tables"
                        else
                            log "WARNING" "Database exists but may not be properly initialized"
                        fi
                    else
                        log "INFO" "sqlite3 not available for database validation"
                    fi
                else
                    log "WARNING" "Database file not found: $db_file (may be created on startup)"
                fi
            done <<< "$db_files"
        fi
    fi

    log "SUCCESS" "Configuration validation completed"
}

# Start service
start_service() {
    log "INFO" "Starting rport service..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would start rportd service"
        return 0
    fi

    systemctl daemon-reload
    systemctl start rportd

    # Wait for service to start
    local count=0
    while ! systemctl is-active --quiet rportd && [[ $count -lt 30 ]]; do
        sleep 1
        ((count++))
    done

    if systemctl is-active --quiet rportd; then
        log "SUCCESS" "RPort service started successfully"
    else
        log "ERROR" "Failed to start RPort service"
        return 1
    fi
}

# Check service health
check_service_health() {
    log "INFO" "Checking service health..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would check service health"
        return 0
    fi

    # Check if service is active
    if ! systemctl is-active --quiet rportd; then
        log "ERROR" "Service is not active"
        return 1
    fi

    # Check service logs for errors
    local recent_logs
    recent_logs=$(journalctl -u rportd --since="1 minute ago" --no-pager)
    
    if echo "$recent_logs" | grep -q "error\|ERROR\|failed\|FAILED"; then
        log "WARNING" "Found error messages in recent logs:"
        echo "$recent_logs" | grep -i "error\|failed" | tail -5
    fi

    # Try to connect to the service (if ports are configured)
    if [[ -f "$CONFIG_FILE" ]]; then
        local api_port
        api_port=$(grep -oP 'address\s*=\s*"[^"]*:(\d+)"' "$CONFIG_FILE" | grep -oP '\d+$' | head -1)
        
        if [[ -n "$api_port" ]]; then
            if curl -s --max-time 5 "http://localhost:$api_port/api/v1/status" &>/dev/null; then
                log "SUCCESS" "API endpoint is responding"
            else
                log "INFO" "API endpoint test inconclusive (may require authentication)"
            fi
        fi
    fi

    log "SUCCESS" "Service health check completed"
}

# Rollback function
rollback() {
    log "ERROR" "Migration failed. Attempting rollback..."

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "[DRY-RUN] Would perform rollback"
        return 0
    fi

    # Stop the service
    systemctl stop rportd || true

    # Restore binary
    if [[ -f "$BACKUP_DIR/rportd.backup" ]]; then
        cp "$BACKUP_DIR/rportd.backup" "$RPORTD_BINARY_PATH"
        log "INFO" "Binary restored from backup"
    fi

    # Restore API auth file
    if [[ -f "$BACKUP_DIR/api-auth.json.backup" ]]; then
        cp "$BACKUP_DIR/api-auth.json.backup" "$API_AUTH_FILE"
        log "INFO" "API auth file restored from backup"
    fi

    # Restore database
    if [[ -f "$BACKUP_DIR/clients.db.backup" ]]; then
        cp "$BACKUP_DIR/clients.db.backup" "$DATA_DIR/clients.db"
        log "INFO" "Clients database restored from backup"
    fi

    # Start service
    systemctl start rportd || true

    log "WARNING" "Rollback completed. Please check service status manually."
}

# Main migration function
main() {
    local start_time=$(date +%s)
    
    log "INFO" "Starting RPort migration process..."
    log "INFO" "Log file: $LOG_FILE"

    # Set trap for rollback on error
    trap 'rollback' ERR

    # Parse arguments
    parse_args "$@"

    # Show configuration
    log "INFO" "Migration Configuration:"
    log "INFO" "  New binary: $NEW_BINARY_PATH"
    log "INFO" "  Target binary path: $RPORTD_BINARY_PATH"
    log "INFO" "  Data directory: $DATA_DIR"
    log "INFO" "  Config file: $CONFIG_FILE"
    log "INFO" "  API auth file: $API_AUTH_FILE"
    log "INFO" "  Service file: $SYSTEMD_SERVICE_FILE"
    log "INFO" "  Backup directory: $BACKUP_DIR"
    log "INFO" "  Dry run mode: $DRY_RUN"

    # Check prerequisites
    check_prerequisites

    # Check if service is running
    local service_was_running=false
    if check_service_status; then
        service_was_running=true
    fi

    # Create backup
    if [[ $service_was_running == true ]] || [[ $FORCE_BACKUP == true ]]; then
        create_backup
    else
        log "INFO" "Skipping backup (service not running and --force-backup not specified)"
    fi

    # Stop service if running
    if [[ $service_was_running == true ]]; then
        stop_service
    fi

    # Replace binary
    replace_binary

    # Set binary capabilities for privileged port binding
    set_binary_capabilities

    # Convert API auth file
    convert_api_auth

    # Fix database schema for regexp compatibility
    fix_database_schema

    # Validate configuration
    validate_config

    # Start service if it was running before
    if [[ $service_was_running == true ]]; then
        start_service
        check_service_health
    else
        log "INFO" "Service was not running before migration, not starting it"
    fi

    # Remove trap
    trap - ERR

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log "SUCCESS" "Migration completed successfully in ${duration} seconds!"
    log "INFO" "Backup location: $BACKUP_DIR"
    log "INFO" "Log file: $LOG_FILE"

    if [[ $DRY_RUN == true ]]; then
        log "INFO" "This was a dry run. No actual changes were made."
    else
        log "INFO" "Migration completed successfully. Changes made:"
        log "INFO" "  - Binary updated: $RPORTD_BINARY_PATH"
        log "INFO" "  - Capabilities set: cap_net_bind_service for privileged port binding"
        log "INFO" "  - API auth file converted (if needed)"
        log "INFO" "  - Database regexp fields fixed for compatibility"
        log "INFO" ""
        log "INFO" "To rollback if needed:"
        log "INFO" "  1. Stop service: sudo systemctl stop rportd"
        log "INFO" "  2. Restore binary: sudo cp $BACKUP_DIR/rportd.backup $RPORTD_BINARY_PATH"
        if [[ -f "$BACKUP_DIR/api-auth.json.backup" ]]; then
            log "INFO" "  3. Restore API auth: sudo cp $BACKUP_DIR/api-auth.json.backup $API_AUTH_FILE"
        fi
        if [[ -f "$BACKUP_DIR/clients.db.backup" ]]; then
            log "INFO" "  4. Restore database: sudo cp $BACKUP_DIR/clients.db.backup $DATA_DIR/clients.db"
        fi
        log "INFO" "  5. Start service: sudo systemctl start rportd"
    fi
}

# Run main function with all arguments
main "$@"
