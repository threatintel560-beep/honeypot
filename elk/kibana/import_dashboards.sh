#!/usr/bin/env bash
# Import HoneyForge Kibana dashboards
# Run from the controller Mac after Kibana is up.
set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

echo "Importing HoneyForge dashboards to $KIBANA_URL..."

# Create data view first
curl -s -X POST "$KIBANA_URL/api/data_views/data_view" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "data_view": {
      "title": "honeypot-events-*",
      "name": "HoneyForge Events",
      "timeFieldName": "@timestamp"
    }
  }' > /dev/null 2>&1 || true

echo "  ✓ Data view created"

# Import saved objects
curl -s -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  --form file=@"$(dirname "$0")/saved_objects.ndjson" \
  > /dev/null 2>&1

echo "  ✓ Dashboards imported"
echo ""
echo "  Open: $KIBANA_URL/app/dashboards"
