#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/namespace.yaml"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/observability.yaml"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/platform.yaml"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/app.yaml"

DEPLOYMENTS="$("${ROOT_DIR}/.bin/kubectl" -n chaos-loop get deployments -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"

for deployment in ${DEPLOYMENTS}; do
  echo "Waiting for deployment/${deployment}"
  "${ROOT_DIR}/.bin/kubectl" -n chaos-loop rollout status "deploy/${deployment}" --timeout=180s
done
