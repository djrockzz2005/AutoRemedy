# Autonomous Chaos Engineering and Self-Healing Platform

This repository deploys a production-style microservice application on Kubernetes and wraps it with an autonomous control loop:

1. `chaos-engine` injects Kubernetes-native failures.
2. `telemetry-bridge` pulls live metrics from Prometheus and error signals from Loki.
3. `anomaly-detector` scores live telemetry with an `IsolationForest`.
4. `decision-engine` maps anomalies to remediation plans.
5. `recovery-engine` executes recovery through the Kubernetes API.
6. `dashboard` visualizes anomaly scores, decisions, and recovery timelines in real time.

## Microservices

- `api-gateway`: public checkout API
- `user-service`: user profile source of truth in PostgreSQL
- `order-service`: order orchestration, HTTP + gRPC client
- `inventory-service`: gRPC stock manager backed by Redis
- `payment-service`: payment authorizer in PostgreSQL
- `recommendation-service`: Redis-backed product recommendations

## Failure modes

- Pod crashes via pod deletion
- Resource pressure via Kubernetes `Job`
- Network partitions via `NetworkPolicy`
- Latency injection via deployment patch and rolling restart

## Recovery actions

- Deployment restart
- Manual scale-out, designed to coexist with HPA
- Service selector rerouting
- Cache restore and warmup
- Network policy rollback
- Latency reset

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./scripts/bootstrap_kind.sh
./scripts/build_images.sh
./scripts/load_images.sh
./scripts/deploy.sh
./scripts/demo.sh
```

The bootstrap script downloads `kind` and `kubectl` into `.bin/`. The deploy path expects Docker access and outbound network access to fetch base container images.

## Dashboard

Port-forward the dashboard after deployment:

```bash
.bin/kubectl -n chaos-loop port-forward svc/dashboard 8080:8000
```

Then open `http://localhost:8080`.

## Notes

- The detector uses `IsolationForest` because it is lightweight enough to run continuously in-cluster.
- Loki ingestion is performed directly from the services through a lightweight HTTP log handler, which keeps the local setup smaller than a full Promtail deployment.
- The reroute action is implemented as a Kubernetes `Service` selector patch and is ready for blue/green or shadow lanes.

