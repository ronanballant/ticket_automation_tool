#!/bin/bash

# -------------------- CONFIG --------------------
SRC_FILE="/u0/rballant/sps_processed_tickets.json"
DEST_FILE="/app01/secops_code/ticket_automation/ticket_automation_tool/sps_processed_tickets.json"
PYTHON_SCRIPT="/app01/secops_code/ticket_automation/ticket_automation_tool/time_collector.py"
LOG_FILE="/app01/secops_code/ticket_automation/ticket_automation_tool/run_time_collector.log"
LOCK_FILE="/app01/secops_code/ticket_automation/ticket_automation_tool/run_time_collector.lock"
PYTHON_BIN="/app01/secops_code/ticket_automation/ticket_automation_tool/venv/bin/python3"
DASHBOARD_FILE="/app01/secops_code/ticket_automation/ticket_automation_tool/dashboard_tickets.json"
T3_PATH="rballant@t3tools.akamai.com:/app01/opt/splunk/var/log/ticket_automation/processed_ticket_data.json"
# ------------------------------------------------

# Locking to prevent overlapping runs
exec 200>"$LOCK_FILE"
flock -n 200 || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Another instance is already running. Exiting." >> "$LOG_FILE"
    exit 1
}

# Copy the file
if [[ -f "$SRC_FILE" ]]; then
    cp "$SRC_FILE" "$DEST_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - File copied to $DEST_FILE" >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Source file not found: $SRC_FILE" >> "$LOG_FILE"
    exit 1
fi

# Run the Python script
echo "$(date '+%Y-%m-%d %H:%M:%S') - ▶️ Running Python script: $PYTHON_SCRIPT" >> "$LOG_FILE"
$PYTHON_BIN "$PYTHON_SCRIPT" >> "$LOG_FILE" 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') - ▶️ Running rsync" >> "$LOG_FILE"
rsync -azq "$DASHBOARD_FILE" "$T3_PATH" >> "$LOG_FILE" 2>&1

if [[ $? -eq 0 ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Python script finished successfully." >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Python script failed." >> "$LOG_FILE"
    exit 1
fi