from __future__ import annotations

import asyncio
import math
import os
from collections import deque

import httpx
import numpy as np
from fastapi import FastAPI
from sklearn.ensemble import IsolationForest

from services.shared.observability import install_observability

app = FastAPI(title="anomaly-detector")
logger = install_observability(app, "anomaly-detector")

TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://telemetry-bridge:8000")
WINDOW = int(os.getenv("MODEL_WINDOW", "80"))
THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.58"))

feature_window: deque[dict] = deque(maxlen=WINDOW)
scores: deque[dict] = deque(maxlen=200)
events: deque[dict] = deque(maxlen=100)
last_event_ts = ""

FEATURE_KEYS = [
    "request_rate",
    "error_rate",
    "latency_p95",
    "restarts",
    "cpu",
    "memory",
    "loki_errors",
    "availability",
]


def build_vector(sample: dict) -> list[float]:
    return [float(sample.get(key, 0.0)) for key in FEATURE_KEYS]


def classify(sample: dict) -> str:
    if sample.get("error_rate", 0) > 0.5 or sample.get("availability", 1) < 0.9:
        return "availability_regression"
    if sample.get("latency_p95", 0) > 1.2:
        return "latency_spike"
    if sample.get("restarts", 0) > 0:
        return "pod_instability"
    if sample.get("loki_errors", 0) > 4:
        return "application_error_burst"
    return "unknown_anomaly"


async def detect_loop() -> None:
    global last_event_ts
    while True:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(f"{TELEMETRY_URL}/features/latest")
                response.raise_for_status()
                sample = response.json()
        except Exception as exc:
            logger.warning("Detector fetch failed", extra={"error": str(exc)})
            await asyncio.sleep(10)
            continue

        if not sample or sample.get("ts") == last_event_ts:
            await asyncio.sleep(10)
            continue

        feature_window.append(sample)
        matrix = np.array([build_vector(item) for item in feature_window])
        anomaly_score = 0.0
        if len(feature_window) >= 20:
            contamination = min(0.2, max(0.05, 4.0 / len(feature_window)))
            model = IsolationForest(random_state=42, contamination=contamination)
            model.fit(matrix)
            decision = model.decision_function(matrix)[-1]
            anomaly_score = 1 / (1 + math.exp(decision * 3))
        else:
            anomaly_score = min(1.0, sample.get("error_rate", 0) + sample.get("latency_p95", 0))

        score = {"ts": sample["ts"], "score": round(float(anomaly_score), 4), "sample": sample}
        scores.append(score)
        if anomaly_score >= THRESHOLD:
            event = {
                "ts": sample["ts"],
                "score": round(float(anomaly_score), 4),
                "classification": classify(sample),
                "sample": sample,
            }
            events.append(event)
            logger.warning("Anomaly detected", extra=event)
        last_event_ts = sample["ts"]
        await asyncio.sleep(10)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(detect_loop())


@app.get("/status")
async def status() -> dict:
    return {"window": len(feature_window), "last_score": scores[-1] if scores else None}


@app.get("/scores")
async def score_history() -> dict:
    return {"items": list(scores)}


@app.get("/events")
async def event_history() -> dict:
    return {"items": list(events)}

