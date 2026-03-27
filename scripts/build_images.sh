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
  echo "Building ${service}"
  docker build \
    -f "${ROOT_DIR}/docker/service.Dockerfile" \
    --build-arg SERVICE_DIR="services/${service}" \
    --build-arg SERVICE_PORT=8000 \
    -t "chaos/${service}:local" \
    "${ROOT_DIR}"
done

