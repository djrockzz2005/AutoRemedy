#!/usr/bin/env bash
set -euo pipefail

KIND_VERSION="${KIND_VERSION:-v0.27.0}"
KUBECTL_VERSION="${KUBECTL_VERSION:-v1.33.0}"

mkdir -p .bin
if [[ ! -x .bin/kind ]]; then
  curl -Lo .bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
  chmod +x .bin/kind
fi
if [[ ! -x .bin/kubectl ]]; then
  curl -Lo .bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  chmod +x .bin/kubectl
fi

.bin/kind create cluster --name chaos-loop --config k8s/kind-config.yaml || true
.bin/kubectl cluster-info

