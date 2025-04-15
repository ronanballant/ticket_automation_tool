#!/bin/bash

# -------------------- CONFIG --------------------
SOURCE_FILE="sps_processed_tickets.json"
DEST_USER="rballant"
DEST_HOST="prod-galaxy-t4tools.dfw02.corp.akamai.com"
DEST_PATH="/u0/rballant/sps_processed_tickets.json"
LOG_FILE="sync_sps_tickets.log"
LOCK_FILE="/tmp/sync_sps_tickets.lock"
SSH_KEY="/home/rballant/.ssh/internal/rballant-internal-2025-03-20"  # <-- Update this if using a different key
# ------------------------------------------------

# 🛡 Prevent overlapping runs using flock
exec 200>"$LOCK_FILE"
flock -n 200 || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Another instance is running. Exiting." >> "$LOG_FILE"
    exit 1
}

# 🛡 Start SSH Agent and add key
eval "$(ssh-agent -s)" >> "$LOG_FILE" 2>&1
ssh-add "$SSH_KEY" >> "$LOG_FILE" 2>&1

# 🛡 Check if the file exists
if [[ ! -f "$SOURCE_FILE" ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: File '$SOURCE_FILE' not found." >> "$LOG_FILE"
    exit 1
fi

# ✅ Perform the rsync
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting rsync..." >> "$LOG_FILE"
rsync -azv "$SOURCE_FILE" "${DEST_USER}@${DEST_HOST}:${DEST_PATH}" >> "$LOG_FILE" 2>&1

if [[ $? -eq 0 ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ✅ rsync completed successfully." >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ❌ rsync failed." >> "$LOG_FILE"
fi

# Kill ssh-agent
eval "$(ssh-agent -k)" >> "$LOG_FILE" 2>&1
