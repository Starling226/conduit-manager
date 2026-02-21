#!/bin/bash

# Default values
STATS_FILE="/var/lib/conduit/stats.json"
MONITOR_ID=""
TAG_BASE="conduit-monitor"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --stats-file) STATS_FILE="$2"; shift ;;
        --id) MONITOR_ID="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Concatenate ID to the tag if provided
FINAL_TAG="${TAG_BASE}${MONITOR_ID}"

echo "Starting monitor on $STATS_FILE with tag $FINAL_TAG..."

while true; do
  if [ -f "$STATS_FILE" ]; then
    # Read the file, remove newlines to keep it on one log line, and log it
    DATA=$(jq -r '"clients=\(.connectedClients),up=\(.totalBytesUp),down=\(.totalBytesDown),uptime=\(.uptimeSeconds)"' "$STATS_FILE")
    echo "CONDUIT_JSON: $DATA"
  fi
  sleep 10
done | logger -t "$FINAL_TAG"
