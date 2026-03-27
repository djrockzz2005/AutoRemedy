# Autonomous Chaos Engineering and Self-Healing Platform

This repository deploys a production-style microservice application on Kubernetes and wraps it with an autonomous control loop:

1. `chaos-engine` injects Kubernetes-native failures.
2. `telemetry-bridge` pulls live metrics from Prometheus and error signals from Loki.
3. `anomaly-detector` scores live telemetry with a cached `IsolationForest` and classifies incidents with a learned decision tree when enough labeled samples exist.
4. `decision-engine` maps anomalies to remediation plans with dynamic fault attribution and anti-flapping cooldowns.
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

## Telemetry APIs

- `GET /features/latest`: latest aggregate sample
- `GET /features/history`: rolling aggregate history
- `GET /features/per-service`: latest metrics broken down by service label

Each telemetry sample now includes a `per_service` object so the anomaly detector and decision engine can attribute failures to the most degraded workload.

## Dynamic Attribution And Cooldowns

- The decision engine derives targets from per-service telemetry:
  - `pod_instability`: highest restart count
  - `latency_spike`: highest p95 latency
  - `availability_regression`: highest error rate or lowest availability
  - `application_error_burst`: most Loki errors
- If per-service data is missing, the original hardcoded fallbacks are still used.
- Repeated recoveries are suppressed for the same `(classification, target)` pair during `COOLDOWN_SECONDS` seconds. Default: `60`.

## ML Classification And Persistence

- The anomaly detector still uses rule-based classification on cold start.
- Once at least `CLASSIFIER_MIN_SAMPLES` labeled anomalies are available, it trains a lightweight `DecisionTreeClassifier` and uses that in preference to the rules.
- The `IsolationForest` is cached in memory and only retrained when at least `RETRAIN_INTERVAL` new samples have been added since the last training run.
- Models are persisted with `joblib` by default:
  - anomaly model: `/tmp/model.pkl`
  - classifier model: `/tmp/classifier.pkl`
- If model loading fails, the detector falls back to in-memory retraining and rule-based classification.

## Environment Variables

- `COLLECT_INTERVAL_SECONDS`: telemetry scrape cadence. Default: `2`
- `DETECT_INTERVAL_SECONDS`: anomaly detection cadence. Default: `2`
- `DECISION_INTERVAL_SECONDS`: decision loop cadence. Default: `2`
- `COOLDOWN_SECONDS`: per-target anti-flapping cooldown in the decision engine. Default: `60`
- `RETRAIN_INTERVAL`: minimum new samples before retraining cached models. Default: `10`
- `CLASSIFIER_MIN_SAMPLES`: labeled anomaly count required before ML classification is used. Default: `30`
- `MODEL_PATH`: persisted anomaly model path. Default: `/tmp/model.pkl`
- `CLASSIFIER_MODEL_PATH`: persisted classifier model path. Default: `/tmp/classifier.pkl`
- `TARGET_NAMESPACES`: namespaces monitored by the operator console and control plane. Default: `chaos-loop`

## Dashboard

Port-forward the dashboard after deployment:

```bash
.bin/kubectl -n chaos-loop port-forward svc/dashboard 8080:8000
```

Then open `http://localhost:8080`.

## Notes

- The detector uses `IsolationForest` because it is lightweight enough to run continuously in-cluster.
- The detector caches and persists models so it does not retrain from scratch on every cycle.
- Loki ingestion is performed directly from the services through a lightweight HTTP log handler, which keeps the local setup smaller than a full Promtail deployment.
- The reroute action is implemented as a Kubernetes `Service` selector patch and is ready for blue/green or shadow lanes.

## Tests

Run the basic logic tests with:

```bash
python3 -m unittest discover -s tests
```
