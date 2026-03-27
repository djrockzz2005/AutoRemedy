from __future__ import annotations

import asyncio
import json
import os
import socket
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from kubernetes import client, config

from services.shared.observability import install_observability

app = FastAPI(title="dashboard")
logger = install_observability(app, "dashboard")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://anomaly-detector:8000")
DECISION_URL = os.getenv("DECISION_URL", "http://decision-engine:8000")
RECOVERY_URL = os.getenv("RECOVERY_URL", "http://recovery-engine:8000")
CHAOS_URL = os.getenv("CHAOS_URL", "http://chaos-engine:8000")
PLATFORM_NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
TARGET_NAMESPACES = [item.strip() for item in os.getenv("TARGET_NAMESPACES", PLATFORM_NAMESPACE).split(",") if item.strip()]
DOCKER_SOCKET_PATH = os.getenv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")


HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ChaosLoop Operator Console</title>
    <style>
      :root { color-scheme: light; --bg:#eef2f5; --panel:#fbfcfd; --ink:#16212c; --muted:#6d7782; --line:rgba(22,33,44,.08); --accent:#ff6b35; --danger:#df3f54; --ok:#23967f; --warn:#f4a261; --glow:rgba(255,107,53,.18); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans",sans-serif; color:var(--ink); background:
        radial-gradient(circle at 0% 0%, rgba(255,176,77,.24), transparent 28%),
        radial-gradient(circle at 100% 0%, rgba(67,97,238,.14), transparent 24%),
        linear-gradient(145deg, #f7efe2 0%, #e7eef4 54%, #edf3f7 100%); }
      .wrap { max-width:1500px; margin:0 auto; padding:24px; }
      .hero, .top-grid, .main-grid, .bottom-grid { display:grid; gap:18px; }
      .hero { grid-template-columns: 1.2fr .8fr; margin-bottom:18px; }
      .top-grid { grid-template-columns: repeat(4, 1fr); margin-bottom:18px; }
      .main-grid { grid-template-columns: 1.15fr .85fr; margin-bottom:18px; }
      .bottom-grid { grid-template-columns: 1fr 1fr; }
      .stack { display:grid; gap:18px; }
      .card { background:rgba(251,252,253,.84); backdrop-filter: blur(18px); border:1px solid var(--line); border-radius:28px; padding:18px; box-shadow:0 20px 50px rgba(17,24,39,.08); min-width:0; }
      .hero-main { padding:28px; min-height:210px; position:relative; overflow:hidden; }
      .hero-main::after { content:""; position:absolute; inset:auto -40px -60px auto; width:240px; height:240px; background: radial-gradient(circle, rgba(255,107,53,.22), transparent 65%); }
      .eyebrow { color:var(--muted); font-size:15px; margin-bottom:8px; }
      h1 { font-family:"Space Grotesk",sans-serif; font-size: clamp(38px, 5vw, 64px); line-height:.94; margin:0 0 16px; max-width:8ch; }
      h3 { margin:0; font-size:18px; }
      .note, .micro { color:var(--muted); font-size:13px; }
      .statusbar, .pill-row, .toolbar, .form-grid { display:flex; flex-wrap:wrap; gap:10px; }
      .chip, .pill { display:inline-flex; align-items:center; gap:8px; padding:10px 14px; border-radius:999px; background:#fff; border:1px solid var(--line); font-size:14px; }
      .pill { padding:6px 10px; font-size:12px; }
      .pill.good { background:#edf9f6; color:#1f7f72; }
      .pill.bad { background:#fff0f0; color:#bd3030; }
      .dot { width:10px; height:10px; border-radius:50%; background:var(--ok); box-shadow:0 0 0 8px rgba(42,157,143,.12); animation:pulse 1.2s infinite; }
      .kpi { font-size:40px; line-height:1; font-weight:700; letter-spacing:-.04em; margin-top:8px; }
      .metric-label { color:var(--muted); font-size:14px; }
      .control-grid, .list { display:grid; gap:12px; }
      .list { max-height:520px; overflow:auto; }
      .row-card { padding:14px; border-radius:18px; border:1px solid var(--line); background:#fff; cursor:pointer; transition:border-color .15s ease, transform .15s ease, box-shadow .15s ease; }
      .row-card.active { border-color:rgba(255,107,53,.55); box-shadow:0 10px 24px rgba(255,107,53,.12); transform:translateY(-1px); }
      .row-head { display:flex; justify-content:space-between; gap:10px; }
      .row-title { font-weight:700; }
      .row-sub { color:var(--muted); font-size:13px; margin-top:4px; }
      select, input, textarea { width:100%; border-radius:14px; border:1px solid var(--line); padding:12px 14px; font:inherit; background:#fff; color:var(--ink); }
      textarea { min-height:220px; resize:vertical; }
      button { border:none; border-radius:16px; padding:12px 14px; font:inherit; cursor:pointer; color:white; background:linear-gradient(135deg,#ec5a29,#ff7b3d); box-shadow:0 14px 30px var(--glow); transition:transform .16s ease, filter .16s ease; }
      button:hover { transform:translateY(-1px); filter:brightness(1.03); }
      button:active { transform:translateY(1px); }
      canvas { width:100%; height:240px; display:block; background:linear-gradient(180deg, rgba(255,107,53,.04), transparent 45%); border-radius:18px; }
      table { width:100%; border-collapse:collapse; font-size:14px; }
      th, td { padding:10px 6px; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }
      th { color:var(--muted); font-weight:600; }
      .events { display:grid; gap:10px; max-height:280px; overflow:auto; }
      .event { display:flex; justify-content:space-between; align-items:start; gap:12px; padding:12px 14px; border-radius:16px; background:#fff; border:1px solid var(--line); }
      .event strong { display:block; font-size:15px; }
      .event small { color:var(--muted); display:block; margin-top:4px; }
      .split { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
      .empty { color:var(--muted); padding:16px 0; }
      @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.55; } }
      @media (max-width: 1180px) {
        .hero, .main-grid, .bottom-grid { grid-template-columns:1fr; }
        .top-grid { grid-template-columns:repeat(2, 1fr); }
      }
      @media (max-width: 700px) {
        .top-grid { grid-template-columns:1fr; }
        .split { grid-template-columns:1fr; }
        .wrap { padding:16px; }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="hero">
        <section class="card hero-main">
          <div class="eyebrow">Autonomous chaos engineering and self-healing</div>
          <h1>ChaosLoop Operator Console</h1>
          <div class="statusbar">
            <div class="chip"><span class="dot"></span><span id="liveState">Streaming live from the cluster</span></div>
            <div class="chip">Last sample <strong id="sampleTime">--:--:--</strong></div>
            <div class="chip">Signal <strong id="signalState">Nominal</strong></div>
          </div>
        </section>
        <section class="card">
          <h3>Operator Actions</h3>
          <div class="note" style="margin:8px 0 12px">Pick any discovered workload and inject chaos or trigger healing.</div>
          <div class="control-grid">
            <select id="workloadSelect"></select>
            <div class="split">
              <input id="latencyInput" type="number" min="50" step="50" value="1500" placeholder="Latency ms" />
              <input id="scaleInput" type="number" min="1" step="1" value="3" placeholder="Replica count" />
            </div>
            <div class="toolbar">
              <button onclick="triggerSelected('pod-crash')">Crash Pod</button>
              <button onclick="triggerSelected('network-partition')">Partition</button>
              <button onclick="triggerSelected('latency')">Inject Latency</button>
              <button onclick="recoverSelected('restart_deployment')">Restart</button>
              <button onclick="recoverSelected('scale_deployment')">Scale</button>
              <button onclick="recoverSelected('reset_latency')">Reset Latency</button>
            </div>
          </div>
        </section>
      </div>

      <section class="top-grid">
        <div class="card"><div class="metric-label">Anomaly score</div><div id="score" class="kpi">0.00</div><div class="micro" id="scoreMeta">IsolationForest signal</div></div>
        <div class="card"><div class="metric-label">Classification</div><div id="classification" class="kpi">steady</div><div class="micro" id="classificationMeta">No active anomaly</div></div>
        <div class="card"><div class="metric-label">Recovery action</div><div id="recovery" class="kpi">none</div><div class="micro" id="recoveryMeta">Autonomous remediation idle</div></div>
        <div class="card"><div class="metric-label">Latency p95</div><div id="latency" class="kpi">0ms</div><div class="micro" id="latencyMeta">Live request path health</div></div>
      </section>

      <section class="main-grid">
        <div class="stack">
          <section class="card">
            <div class="row-head">
              <div>
                <h3>Anomaly Signal</h3>
                <div class="note">Every point is streamed from the control loop as soon as it changes.</div>
              </div>
              <div class="chip">Window <strong id="windowSize">0</strong></div>
            </div>
            <canvas id="scoreChart" height="160"></canvas>
          </section>
          <section class="card">
            <h3>Kubernetes Explorer</h3>
            <div class="note">Live view of deployments, pods, readiness, restarts, and health across monitored namespaces.</div>
            <div id="workloads" class="list" style="margin-top:12px"></div>
          </section>
        </div>
        <div class="stack">
          <section class="card">
            <h3>Selected Workload Health</h3>
            <div id="detailSummary" class="note" style="margin:8px 0 12px">Select a workload to inspect its pods, events, and logs.</div>
            <div id="podPills" class="pill-row"></div>
            <div class="split" style="margin-top:14px">
              <div>
                <h3 style="font-size:16px">Recent Events</h3>
                <table id="eventsTable"></table>
              </div>
              <div>
                <h3 style="font-size:16px">Pod Inventory</h3>
                <table id="podsTable"></table>
              </div>
            </div>
          </section>
          <section class="card">
            <h3>Pod Logs</h3>
            <div class="note">Latest container logs for the selected workload.</div>
            <textarea id="logsView" readonly></textarea>
          </section>
        </div>
      </section>

      <section class="bottom-grid">
        <div class="stack">
          <section class="card">
            <h3>Incident Feed</h3>
            <div class="note">Latest anomalies, decisions, and recovery actions in one stream.</div>
            <div id="feed" class="events" style="margin-top:12px"></div>
          </section>
          <section class="card">
            <h3>Recovery Timeline</h3>
            <table id="timeline"></table>
          </section>
          <section class="card">
            <h3>Decision Log</h3>
            <table id="decisions"></table>
          </section>
        </div>
        <div class="stack">
          <section class="card">
            <h3>Docker Runtime</h3>
            <div id="dockerSummary" class="note" style="margin:8px 0 12px">Inspecting host Docker when the API is reachable.</div>
            <div id="dockerContainers" class="list"></div>
          </section>
        </div>
      </section>
    </div>
    <script>
      const canvas = document.getElementById('scoreChart');
      const ctx = canvas.getContext('2d');
      let lastStreamAt = Date.now();
      let selectedWorkloadKey = '';
      let workloadMap = {};

      function draw(values) {
        const w = canvas.width = canvas.clientWidth * devicePixelRatio;
        const h = canvas.height = canvas.clientHeight * devicePixelRatio;
        ctx.clearRect(0, 0, w, h);
        ctx.strokeStyle = 'rgba(255,107,53,.22)';
        ctx.lineWidth = 1 * devicePixelRatio;
        for (let i = 0; i <= 4; i++) {
          const y = 12 * devicePixelRatio + (i / 4) * (h - 24 * devicePixelRatio);
          ctx.beginPath();
          ctx.moveTo(12 * devicePixelRatio, y);
          ctx.lineTo(w - 12 * devicePixelRatio, y);
          ctx.stroke();
        }
        ctx.strokeStyle = '#ff6b35';
        ctx.lineWidth = 3 * devicePixelRatio;
        ctx.beginPath();
        values.forEach((v, idx) => {
          const x = (idx / Math.max(values.length - 1, 1)) * (w - 24 * devicePixelRatio) + 12 * devicePixelRatio;
          const y = h - ((Math.max(0, Math.min(1, v))) * (h - 24 * devicePixelRatio) + 12 * devicePixelRatio);
          if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();
      }

      function workloadKey(item) {
        return `${item.namespace}/${item.name}`;
      }

      function renderWorkloads(items) {
        workloadMap = {};
        if (!selectedWorkloadKey || !items.find(item => workloadKey(item) === selectedWorkloadKey)) {
          selectedWorkloadKey = items[0] ? workloadKey(items[0]) : '';
        }
        const select = document.getElementById('workloadSelect');
        select.innerHTML = items.map(item => `<option value="${workloadKey(item)}">${item.namespace} / ${item.name}</option>`).join('');
        if (selectedWorkloadKey) {
          select.value = selectedWorkloadKey;
        }
        document.getElementById('workloads').innerHTML = items.map(item => {
          const key = workloadKey(item);
          workloadMap[key] = item;
          const healthy = item.ready === item.desired && item.desired > 0;
          const restarts = (item.pods || []).reduce((sum, pod) => sum + (pod.restarts || 0), 0);
          const namespace = item.namespace;
          return `
            <div class="row-card ${selectedWorkloadKey === key ? 'active' : ''}" onclick="selectWorkload('${key}')">
              <div class="row-head">
                <div>
                  <div class="row-title">${item.name}</div>
                  <div class="row-sub">${namespace} · ${item.containers.join(', ')}</div>
                </div>
                <div class="pill ${healthy ? 'good' : 'bad'}">${item.ready}/${item.desired} ready</div>
              </div>
              <div class="pill-row">
                <span class="pill">${item.available} available</span>
                <span class="pill ${restarts > 0 ? 'bad' : 'good'}">${restarts} restarts</span>
                <span class="pill">${(item.pods || []).length} pods</span>
              </div>
            </div>`;
        }).join('') || '<div class="empty">No deployments discovered.</div>';
      }

      function renderSnapshot(data) {
        lastStreamAt = Date.now();
        document.getElementById('liveState').textContent = 'Streaming live from the cluster';
        const scores = data.scores || [];
        draw(scores.map(item => item.score));
        const latest = scores[scores.length - 1];
        const latestSample = latest && latest.sample ? latest.sample : {};
        const latestEvent = (data.events || []).slice(-1)[0];
        const latestRecovery = (data.timeline || []).slice(-1)[0];
        document.getElementById('score').textContent = latest ? latest.score.toFixed(2) : '0.00';
        document.getElementById('classification').textContent = latestEvent ? latestEvent.classification : 'steady';
        document.getElementById('recovery').textContent = latestRecovery ? latestRecovery.action : 'none';
        document.getElementById('latency').textContent = `${Math.round((latestSample.latency_p95 || 0) * 1000)}ms`;
        document.getElementById('scoreMeta').textContent = latest ? `Updated ${latest.ts.slice(11,19)}` : 'IsolationForest signal';
        document.getElementById('classificationMeta').textContent = latestEvent ? `Score ${latestEvent.score.toFixed(2)}` : 'No active anomaly';
        document.getElementById('recoveryMeta').textContent = latestRecovery ? `${latestRecovery.status} at ${latestRecovery.ts.slice(11,19)}` : 'Autonomous remediation idle';
        document.getElementById('latencyMeta').textContent = `Availability ${(latestSample.availability || 1).toFixed(2)}`;
        document.getElementById('sampleTime').textContent = latest ? latest.ts.slice(11,19) : '--:--:--';
        document.getElementById('windowSize').textContent = String(scores.length);
        document.getElementById('signalState').textContent = latest && latest.score >= 0.58 ? 'Active incident' : 'Nominal';
        const timelineRows = (data.timeline || []).slice(-8).reverse().map(i => `<tr><td>${i.ts.slice(11,19)}</td><td>${i.namespace || '-'}</td><td>${i.action}</td><td>${i.status}</td></tr>`).join('');
        const decisionRows = (data.decisions || []).slice(-8).reverse().map(i => `<tr><td>${i.event.classification}</td><td>${i.actions.map(a => a.action).join(', ')}</td></tr>`).join('');
        document.getElementById('timeline').innerHTML = '<tr><th>Time</th><th>NS</th><th>Action</th><th>Status</th></tr>' + (timelineRows || '<tr><td colspan="4" class="empty">No recovery actions yet.</td></tr>');
        document.getElementById('decisions').innerHTML = '<tr><th>Event</th><th>Actions</th></tr>' + (decisionRows || '<tr><td colspan="2" class="empty">No decisions yet.</td></tr>');
        const feed = [];
        (data.events || []).slice(-4).reverse().forEach(item => feed.push(`<div class="event"><div><strong>${item.classification}</strong><small>${item.ts.slice(11,19)} | score ${item.score.toFixed(2)}</small></div><div class="pill">detect</div></div>`));
        (data.decisions || []).slice(-4).reverse().forEach(item => feed.push(`<div class="event"><div><strong>${item.event.classification}</strong><small>${item.actions.map(a => a.action).join(', ')}</small></div><div class="pill">decide</div></div>`));
        (data.timeline || []).slice(-4).reverse().forEach(item => feed.push(`<div class="event"><div><strong>${item.action}</strong><small>${item.namespace || '-'} | ${item.status}</small></div><div class="pill">recover</div></div>`));
        document.getElementById('feed').innerHTML = feed.join('') || '<div class="empty">No incidents yet. Trigger a scenario to watch the closed loop react.</div>';
      }

      function renderDocker(data) {
        const items = data.items || [];
        document.getElementById('dockerSummary').textContent = data.available
          ? `Connected to Docker. ${items.length} containers discovered.`
          : (data.message || 'Docker API is not exposed to the dashboard.');
        document.getElementById('dockerContainers').innerHTML = items.map(item => `
          <div class="row-card">
            <div class="row-head">
              <div>
                <div class="row-title">${item.name}</div>
                <div class="row-sub">${item.image}</div>
              </div>
              <div class="pill ${item.health === 'healthy' || item.state === 'running' ? 'good' : 'bad'}">${item.health || item.state}</div>
            </div>
            <div class="pill-row">
              <span class="pill">${item.status}</span>
              <span class="pill">${item.ports || 'no ports'}</span>
            </div>
          </div>`).join('') || '<div class="empty">No Docker containers visible from the dashboard. Mount or expose the Docker API to enable this panel.</div>';
      }

      function renderDetails(data) {
        if (!data || !data.workload) {
          document.getElementById('detailSummary').textContent = 'No workload selected.';
          document.getElementById('podPills').innerHTML = '';
          document.getElementById('eventsTable').innerHTML = '';
          document.getElementById('podsTable').innerHTML = '';
          document.getElementById('logsView').value = '';
          return;
        }
        const workload = data.workload;
        document.getElementById('detailSummary').textContent = `${workload.namespace} / ${workload.name} · ${workload.ready}/${workload.desired} ready · ${workload.available} available`;
        document.getElementById('podPills').innerHTML = (workload.pods || []).map(pod => `<span class="pill ${pod.restarts > 0 ? 'bad' : 'good'}">${pod.name} · ${pod.phase} · ${pod.restarts} restarts</span>`).join('') || '<span class="empty">No pods.</span>';
        const eventsRows = (data.events || []).map(item => `<tr><td>${item.time}</td><td>${item.reason}</td><td>${item.message}</td></tr>`).join('');
        const podRows = (workload.pods || []).map(item => `<tr><td>${item.name}</td><td>${item.phase}</td><td>${item.ready}</td><td>${item.restarts}</td></tr>`).join('');
        document.getElementById('eventsTable').innerHTML = '<tr><th>Time</th><th>Reason</th><th>Message</th></tr>' + (eventsRows || '<tr><td colspan="3" class="empty">No recent events.</td></tr>');
        document.getElementById('podsTable').innerHTML = '<tr><th>Pod</th><th>Phase</th><th>Ready</th><th>Restarts</th></tr>' + (podRows || '<tr><td colspan="4" class="empty">No pods.</td></tr>');
        document.getElementById('logsView').value = data.logs || 'No logs available.';
      }

      function selectedPayload() {
        const key = document.getElementById('workloadSelect').value || selectedWorkloadKey;
        selectedWorkloadKey = key;
        const workload = workloadMap[key];
        if (!workload) throw new Error('No workload selected');
        return { target: workload.name, namespace: workload.namespace, container_name: (workload.containers || [])[0] || null };
      }

      async function refreshSnapshot() {
        const payload = await fetch('/api/snapshot').then(r => r.json());
        renderSnapshot(payload);
        renderWorkloads(payload.workloads || []);
      }

      async function refreshDetails() {
        const workload = workloadMap[selectedWorkloadKey];
        if (!workload) return;
        const params = new URLSearchParams({ namespace: workload.namespace, name: workload.name });
        const payload = await fetch(`/api/kube/workload?${params}`).then(r => r.json());
        renderDetails(payload);
      }

      async function refreshDocker() {
        const payload = await fetch('/api/docker/containers').then(r => r.json());
        renderDocker(payload);
      }

      function startStream() {
        const stream = new EventSource('/api/live');
        stream.onmessage = event => {
          const payload = JSON.parse(event.data);
          renderSnapshot(payload);
          renderWorkloads(payload.workloads || []);
        };
        stream.onerror = () => {
          document.getElementById('liveState').textContent = 'Reconnecting live stream';
          stream.close();
          setTimeout(startStream, 1000);
        };
      }

      async function triggerSelected(scenario) {
        const payload = selectedPayload();
        payload.latency_ms = Number(document.getElementById('latencyInput').value || 1500);
        await fetch(`/api/chaos/${scenario}`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        await refreshSnapshot();
        await refreshDetails();
      }

      async function recoverSelected(action) {
        const payload = selectedPayload();
        payload.action = action;
        if (action === 'scale_deployment') payload.replicas = Number(document.getElementById('scaleInput').value || 3);
        await fetch('/api/recover', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        await refreshSnapshot();
        await refreshDetails();
      }

      async function selectWorkload(key) {
        selectedWorkloadKey = key;
        renderWorkloads(Object.values(workloadMap));
        document.getElementById('workloadSelect').value = key;
        await refreshDetails();
      }

      document.addEventListener('DOMContentLoaded', async () => {
        await refreshSnapshot();
        await refreshDocker();
        await refreshDetails();
        startStream();
        document.getElementById('workloadSelect').addEventListener('change', async event => selectWorkload(event.target.value));
        setInterval(() => {
          if (Date.now() - lastStreamAt > 2500) {
            refreshSnapshot();
          }
        }, 1000);
        setInterval(refreshDetails, 4000);
        setInterval(refreshDocker, 5000);
        window.addEventListener('resize', refreshSnapshot);
      });
    </script>
  </body>
</html>
"""


def load_k8s() -> tuple[client.AppsV1Api, client.CoreV1Api]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.AppsV1Api(), client.CoreV1Api()


def target_namespaces(core_api: client.CoreV1Api) -> list[str]:
    if TARGET_NAMESPACES == ["*"] or TARGET_NAMESPACES == ["all"]:
        return [item.metadata.name for item in core_api.list_namespace().items]
    return TARGET_NAMESPACES


def deployment_summary(deployment: client.V1Deployment, pods: list[client.V1Pod]) -> dict[str, Any]:
    pod_items = []
    for pod in pods:
        container_statuses = pod.status.container_statuses or []
        pod_items.append(
            {
                "name": pod.metadata.name,
                "phase": pod.status.phase,
                "ready": f"{sum(1 for item in container_statuses if item.ready)}/{len(container_statuses)}",
                "restarts": sum(item.restart_count for item in container_statuses),
                "ip": pod.status.pod_ip,
            }
        )
    return {
        "namespace": deployment.metadata.namespace,
        "name": deployment.metadata.name,
        "kind": "deployment",
        "ready": deployment.status.ready_replicas or 0,
        "desired": deployment.spec.replicas or 0,
        "available": deployment.status.available_replicas or 0,
        "containers": [container.name for container in deployment.spec.template.spec.containers],
        "pods": pod_items,
        "labels": deployment.metadata.labels or {},
    }


def list_workloads() -> list[dict[str, Any]]:
    apps_api, core_api = load_k8s()
    items: list[dict[str, Any]] = []
    for namespace in target_namespaces(core_api):
        deployments = apps_api.list_namespaced_deployment(namespace).items
        pods = core_api.list_namespaced_pod(namespace).items
        by_app: dict[str, list[client.V1Pod]] = {}
        for pod in pods:
            app_label = (pod.metadata.labels or {}).get("app")
            if app_label:
                by_app.setdefault(app_label, []).append(pod)
        for deployment in deployments:
            app_label = (deployment.spec.selector.match_labels or {}).get("app", deployment.metadata.name)
            items.append(deployment_summary(deployment, by_app.get(app_label, [])))
    items.sort(key=lambda item: (item["namespace"], item["name"]))
    return items


def recent_events(core_api: client.CoreV1Api, namespace: str, name: str) -> list[dict[str, str]]:
    events = core_api.list_namespaced_event(namespace, field_selector=f"involvedObject.name={name}").items
    items = []
    for event in sorted(events, key=lambda item: item.last_timestamp or item.event_time or item.metadata.creation_timestamp, reverse=True)[:8]:
        timestamp = event.last_timestamp or event.event_time or event.metadata.creation_timestamp
        items.append(
            {
                "time": timestamp.strftime("%H:%M:%S") if timestamp else "--:--:--",
                "reason": event.reason or "",
                "message": event.message or "",
            }
        )
    return items


def pod_logs(core_api: client.CoreV1Api, namespace: str, pod_name: str, container_name: str | None) -> str:
    try:
        return core_api.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=container_name,
            tail_lines=120,
        )
    except Exception as exc:
        return f"Unable to fetch logs: {exc}"


def docker_get(path: str) -> tuple[int, str]:
    if not os.path.exists(DOCKER_SOCKET_PATH):
        raise FileNotFoundError(f"Docker socket not found at {DOCKER_SOCKET_PATH}")
    request = f"GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n".encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(DOCKER_SOCKET_PATH)
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.splitlines()[0].decode()
    status_code = int(status_line.split()[1])
    return status_code, body.decode(errors="replace")


def docker_containers() -> dict[str, Any]:
    try:
        status, body = docker_get(f"/containers/json?{urlencode({'all': 1})}")
        if status >= 400:
            return {"available": False, "message": f"Docker API returned HTTP {status}", "items": []}
        payload = json.loads(body)
        items = []
        for item in payload:
            ports = ", ".join(
                f"{entry.get('IP', '')}:{entry.get('PublicPort', '')}->{entry.get('PrivatePort', '')}/{entry.get('Type', '')}".strip(":")
                for entry in item.get("Ports", [])
            )
            labels = item.get("Labels", {})
            items.append(
                {
                    "id": item.get("Id", "")[:12],
                    "name": (item.get("Names") or ["/unknown"])[0].lstrip("/"),
                    "image": item.get("Image", ""),
                    "state": item.get("State", ""),
                    "status": item.get("Status", ""),
                    "health": labels.get("health", item.get("State", "")),
                    "ports": ports,
                }
            )
        return {"available": True, "items": items}
    except Exception as exc:
        return {"available": False, "message": f"Docker is unavailable to the dashboard: {exc}", "items": []}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return HTML


async def proxy(url: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as http_client:
        response = await http_client.get(url)
        response.raise_for_status()
        return response.json()


async def snapshot_payload() -> dict:
    async with httpx.AsyncClient(timeout=5.0) as http_client:
        scores_response, events_response, decisions_response, timeline_response = await asyncio.gather(
            http_client.get(f"{DETECTOR_URL}/scores"),
            http_client.get(f"{DETECTOR_URL}/events"),
            http_client.get(f"{DECISION_URL}/decisions"),
            http_client.get(f"{RECOVERY_URL}/timeline"),
        )
        for response in (scores_response, events_response, decisions_response, timeline_response):
            response.raise_for_status()
        return {
            "scores": scores_response.json().get("items", []),
            "events": events_response.json().get("items", []),
            "decisions": decisions_response.json().get("items", []),
            "timeline": timeline_response.json().get("items", []),
            "workloads": list_workloads(),
        }


@app.get("/api/snapshot")
async def snapshot() -> dict:
    return await snapshot_payload()


@app.get("/api/live")
async def live() -> StreamingResponse:
    async def event_stream():
        previous = ""
        while True:
            payload = await snapshot_payload()
            encoded = json.dumps(payload, separators=(",", ":"))
            if encoded != previous:
                previous = encoded
                yield f"data: {encoded}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/kube/workload")
async def kube_workload(namespace: str = Query(...), name: str = Query(...)) -> dict:
    apps_api, core_api = load_k8s()
    try:
        deployment = apps_api.read_namespaced_deployment(name, namespace)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    selector = deployment.spec.selector.match_labels or {}
    label_selector = ",".join(f"{key}={value}" for key, value in selector.items())
    pods = core_api.list_namespaced_pod(namespace, label_selector=label_selector).items
    workload = deployment_summary(deployment, pods)
    logs = ""
    if pods:
        logs = pod_logs(core_api, namespace, pods[0].metadata.name, workload["containers"][0] if workload["containers"] else None)
    return {"workload": workload, "events": recent_events(core_api, namespace, name), "logs": logs}


@app.get("/api/docker/containers")
async def docker_inventory() -> dict:
    return docker_containers()


@app.post("/api/chaos/{scenario}")
async def chaos(scenario: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=8.0) as http_client:
        response = await http_client.post(f"{CHAOS_URL}/scenarios/{scenario}", json=payload)
        response.raise_for_status()
        return response.json()


@app.post("/api/recover")
async def recover(payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=8.0) as http_client:
        response = await http_client.post(f"{RECOVERY_URL}/recover", json=payload)
        response.raise_for_status()
        return response.json()
