from __future__ import annotations

import asyncio
import json
import math
import os
from collections import deque
from pathlib import Path
from typing import Any

import httpx
import joblib
import numpy as np
from fastapi import FastAPI
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier

from services.shared.observability import install_observability

app = FastAPI(title="anomaly-detector")
logger = install_observability(app, "anomaly-detector")

TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://telemetry-bridge:8000")
WINDOW = int(os.getenv("MODEL_WINDOW", "80"))
THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.58"))
DETECT_INTERVAL = float(os.getenv("DETECT_INTERVAL_SECONDS", "2"))
RETRAIN_INTERVAL = int(os.getenv("RETRAIN_INTERVAL", "10"))
CLASSIFIER_MIN_SAMPLES = int(os.getenv("CLASSIFIER_MIN_SAMPLES", "30"))
MODEL_PATH = Path(os.getenv("MODEL_PATH", "/tmp/model.pkl"))
CLASSIFIER_MODEL_PATH = Path(os.getenv("CLASSIFIER_MODEL_PATH", "/tmp/classifier.pkl"))

feature_window: deque[dict] = deque(maxlen=WINDOW)
scores: deque[dict] = deque(maxlen=200)
events: deque[dict] = deque(maxlen=100)
labeled_samples: deque[dict] = deque(maxlen=500)
last_event_ts = ""
isolation_model: IsolationForest | None = None
classifier_model: DecisionTreeClassifier | None = None
last_model_train_size = 0
last_classifier_train_size = 0

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


def rule_based_classify(sample: dict) -> str:
    if sample.get("error_rate", 0) > 0.5 or sample.get("availability", 1) < 0.9:
        return "availability_regression"
    if sample.get("latency_p95", 0) > 1.2:
        return "latency_spike"
    if sample.get("restarts", 0) > 0:
        return "pod_instability"
    if sample.get("loki_errors", 0) > 4:
        return "application_error_burst"
    return "unknown_anomaly"


def should_retrain(current_size: int, last_size: int, minimum_size: int) -> bool:
    return current_size >= minimum_size and (last_size == 0 or current_size - last_size >= RETRAIN_INTERVAL)


def load_models() -> None:
    global isolation_model, classifier_model
    if MODEL_PATH.exists():
        try:
            isolation_model = joblib.load(MODEL_PATH)
        except Exception:
            isolation_model = None
    if CLASSIFIER_MODEL_PATH.exists():
        try:
            classifier_model = joblib.load(CLASSIFIER_MODEL_PATH)
        except Exception:
            classifier_model = None


def train_isolation_model() -> None:
    global isolation_model, last_model_train_size
    matrix = np.array([build_vector(item) for item in feature_window])
    contamination = min(0.2, max(0.05, 4.0 / len(feature_window)))
    isolation_model = IsolationForest(random_state=42, contamination=contamination)
    isolation_model.fit(matrix)
    last_model_train_size = len(feature_window)
    try:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(isolation_model, MODEL_PATH)
    except Exception:
        logger.warning("Failed to persist isolation model", extra={"path": str(MODEL_PATH)})


def train_classifier_model() -> None:
    global classifier_model, last_classifier_train_size
    features = np.array([item["vector"] for item in labeled_samples])
    labels = np.array([item["label"] for item in labeled_samples])
    classifier_model = DecisionTreeClassifier(max_depth=5, random_state=42)
    classifier_model.fit(features, labels)
    last_classifier_train_size = len(labeled_samples)
    try:
        CLASSIFIER_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(classifier_model, CLASSIFIER_MODEL_PATH)
    except Exception:
        logger.warning("Failed to persist classifier model", extra={"path": str(CLASSIFIER_MODEL_PATH)})


def classify(sample: dict) -> str:
    vector = np.array([build_vector(sample)])
    if classifier_model is not None and len(labeled_samples) >= CLASSIFIER_MIN_SAMPLES:
        try:
            return str(classifier_model.predict(vector)[0])
        except Exception:
            logger.warning("Classifier inference failed; falling back to rules")
    return rule_based_classify(sample)


def annotate_per_service(sample: dict) -> dict[str, Any]:
    per_service = sample.get("per_service", {}) or {}
    if not isinstance(per_service, dict):
        return {}
    ranked = {}
    for metric in ("restarts", "latency_p95", "error_rate", "availability", "loki_errors"):
        if metric == "availability":
            sort_key = lambda item: item[1].get(metric, 1.0)
            reverse = False
        else:
            sort_key = lambda item: item[1].get(metric, 0.0)
            reverse = True
        ranked[metric] = sorted(per_service.items(), key=sort_key, reverse=reverse)[:3]
    return {
        "services": per_service,
        "top_restart_services": ranked["restarts"],
        "top_latency_services": ranked["latency_p95"],
        "top_error_services": ranked["error_rate"],
        "lowest_availability_services": ranked["availability"],
        "top_loki_error_services": ranked["loki_errors"],
    }


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
            await asyncio.sleep(DETECT_INTERVAL)
            continue

        if not sample or sample.get("ts") == last_event_ts:
            await asyncio.sleep(DETECT_INTERVAL)
            continue

        feature_window.append(sample)
        vector = build_vector(sample)
        anomaly_score = 0.0
        if should_retrain(len(feature_window), last_model_train_size, 20):
            train_isolation_model()
        if isolation_model is not None and len(feature_window) >= 20:
            decision = isolation_model.decision_function(np.array([vector]))[0]
            anomaly_score = 1 / (1 + math.exp(decision * 3))
        else:
            anomaly_score = min(1.0, sample.get("error_rate", 0) + sample.get("latency_p95", 0))

        score = {"ts": sample["ts"], "score": round(float(anomaly_score), 4), "sample": sample}
        scores.append(score)
        if anomaly_score >= THRESHOLD:
            classification = classify(sample)
            event = {
                "ts": sample["ts"],
                "score": round(float(anomaly_score), 4),
                "classification": classification,
                "sample": sample,
                "per_service": annotate_per_service(sample),
            }
            events.append(event)
            labeled_samples.append({"vector": vector, "label": classification})
            if should_retrain(len(labeled_samples), last_classifier_train_size, CLASSIFIER_MIN_SAMPLES):
                train_classifier_model()
            logger.warning("Anomaly detected", extra=event)
        last_event_ts = sample["ts"]
        await asyncio.sleep(DETECT_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    load_models()
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
