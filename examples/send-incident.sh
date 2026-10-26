#!/bin/sh
# Send an incident to Healer from any monitor that can run a script or call a webhook.
#   HEALER_URL=http://healer.lan:3050 HEALER_TOKEN=... ./send-incident.sh incident.example.json
curl -fsS -X POST "${HEALER_URL:-http://127.0.0.1:3050}/incident" \
  -H "X-Healer-Token: $HEALER_TOKEN" -H "Content-Type: application/json" \
  --data-binary @"${1:-incident.example.json}"
