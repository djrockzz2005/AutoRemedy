#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICES=(
  api-gateway
  user-service
  order-service
  inventory-service
  payment-service
  recommendation-service
  telemetry-bridge
  anomaly-detector
  decision-engine
  recovery-engine
  chaos-engine
  dashboard
)

for service in "${SERVICES[@]}"; do
  "${ROOT_DIR}/.bin/kind" load docker-image "chaos/${service}:local" --name chaos-loop
done

