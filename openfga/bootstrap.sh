#!/bin/sh
# Idempotent OpenFGA bootstrap via the HTTP API (no fga CLI / no distroless
# shell needed). Creates the store, uploads the authorization model, and seeds
# example tuples — only if a store with this name does not already exist.
#
# Runs from curlimages/curl (busybox sh + sed + grep). The gateway resolves the
# store id + latest model id by name at startup, so no IDs need writing back.
set -eu

API="${OPENFGA_API_URL:-http://openfga:8080}"
NAME="${OPENFGA_STORE_NAME:-llmops}"

if curl -sf "$API/stores" | grep -q "\"name\":\"$NAME\""; then
  echo "openfga: store '$NAME' already exists; skipping bootstrap"
  exit 0
fi

echo "openfga: creating store '$NAME'"
RESP=$(curl -sf -X POST "$API/stores" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$NAME\"}")
STORE_ID=$(echo "$RESP" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
if [ -z "$STORE_ID" ]; then
  echo "openfga: failed to create store: $RESP" >&2
  exit 1
fi
echo "openfga: store id = $STORE_ID"

echo "openfga: writing authorization model"
curl -sf -X POST "$API/stores/$STORE_ID/authorization-models" \
  -H 'content-type: application/json' \
  -d @/work/model.json >/dev/null

echo "openfga: seeding tuples"
curl -sf -X POST "$API/stores/$STORE_ID/write" \
  -H 'content-type: application/json' \
  -d @/work/tuples.json >/dev/null

echo "openfga: bootstrap complete"
