#!/usr/bin/env bash
set -euo pipefail

KUBECTL=".bin/kubectl"
NAMESPACE="chaos-loop"

${KUBECTL} -n ${NAMESPACE} port-forward svc/dashboard 8080:8000 >/tmp/dashboard-pf.log 2>&1 &
PF_PID=$!
trap 'kill ${PF_PID}' EXIT

echo "Dashboard: http://localhost:8080"
sleep 3
curl -s -X POST http://localhost:8080/api/chaos/pod-crash -H 'Content-Type: application/json' -d '{"target":"order-service"}'
sleep 20
curl -s -X POST http://localhost:8080/api/chaos/network-partition -H 'Content-Type: application/json' -d '{"target":"payment-service"}'
sleep 20
curl -s -X POST http://localhost:8080/api/chaos/latency -H 'Content-Type: application/json' -d '{"target":"api-gateway","latency_ms":1500}'
wait

