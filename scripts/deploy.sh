#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/namespace.yaml"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/observability.yaml"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/platform.yaml"
"${ROOT_DIR}/.bin/kubectl" apply -f "${ROOT_DIR}/k8s/base/app.yaml"
"${ROOT_DIR}/.bin/kubectl" -n chaos-loop rollout status deploy/api-gateway --timeout=180s
"${ROOT_DIR}/.bin/kubectl" -n chaos-loop rollout status deploy/dashboard --timeout=180s

