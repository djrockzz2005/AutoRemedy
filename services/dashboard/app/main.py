from __future__ import annotations

import asyncio
import json
import os

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse

from services.shared.observability import install_observability

app = FastAPI(title="dashboard")
logger = install_observability(app, "dashboard")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://anomaly-detector:8000")
DECISION_URL = os.getenv("DECISION_URL", "http://decision-engine:8000")
RECOVERY_URL = os.getenv("RECOVERY_URL", "http://recovery-engine:8000")
CHAOS_URL = os.getenv("CHAOS_URL", "http://chaos-engine:8000")


HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Chaos Loop Dashboard</title>
    <style>
      :root { color-scheme: light; --bg:#eef2f5; --panel:#fbfcfd; --panel-strong:#101923; --ink:#16212c; --muted:#6d7782; --line:rgba(22,33,44,.08); --accent:#ff6b35; --danger:#e63946; --ok:#2a9d8f; --warn:#f4a261; --glow:rgba(255,107,53,.18); }
      * { box-sizing:border-box; }
      body { margin:0; font-family: "IBM Plex Sans", sans-serif; color:var(--ink); background:
        radial-gradient(circle at 0% 0%, rgba(255,176,77,.24), transparent 28%),
        radial-gradient(circle at 100% 0%, rgba(67,97,238,.14), transparent 24%),
        linear-gradient(145deg, #f7efe2 0%, #e7eef4 54%, #edf3f7 100%); }
      .wrap { max-width: 1380px; margin: 0 auto; padding: 28px; }
      .hero { display:grid; grid-template-columns: 1.3fr .9fr; gap:20px; margin-bottom:20px; }
      .hero-main, .hero-side, .card { background:rgba(251,252,253,.82); backdrop-filter: blur(18px); border:1px solid var(--line); border-radius:28px; box-shadow: 0 20px 50px rgba(17,24,39,.08); }
      .hero-main { padding:28px; min-height: 210px; position:relative; overflow:hidden; }
      .hero-main::after { content:""; position:absolute; inset:auto -40px -60px auto; width:240px; height:240px; background: radial-gradient(circle, rgba(255,107,53,.22), transparent 65%); }
      .eyebrow { color:var(--muted); font-size:15px; margin-bottom:8px; }
      h1 { font-family: "Space Grotesk", sans-serif; font-size: clamp(38px, 5vw, 64px); line-height: .94; margin:0 0 16px; max-width: 8ch; }
      .statusbar { display:flex; flex-wrap:wrap; gap:10px; }
      .chip { display:inline-flex; align-items:center; gap:8px; padding:10px 14px; border-radius:999px; background:#fff; border:1px solid var(--line); font-size:14px; }
      .dot { width:10px; height:10px; border-radius:50%; background:var(--ok); box-shadow:0 0 0 8px rgba(42,157,143,.12); animation:pulse 1.2s infinite; }
      .hero-side { padding:18px; display:grid; gap:12px; }
      .hero-side h3, .card h3 { margin:0; font-size:18px; }
      .button-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }
      button { border:none; border-radius:18px; padding:14px 12px; font:inherit; cursor:pointer; color:white; background:linear-gradient(135deg,#ec5a29,#ff7b3d); box-shadow:0 14px 30px var(--glow); transition:transform .16s ease, filter .16s ease; }
      button:hover { transform:translateY(-1px); filter:brightness(1.03); }
      button:active { transform:translateY(1px); }
      .layout { display:grid; grid-template-columns: 1.2fr .9fr; gap:18px; }
      .stack { display:grid; gap:18px; }
      .metrics { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; }
      .card { padding:18px; min-width:0; }
      .metric-label { color:var(--muted); font-size:14px; margin-bottom:8px; }
      .kpi { font-size:40px; line-height:1; font-weight:700; letter-spacing:-.04em; }
      .micro { margin-top:8px; color:var(--muted); font-size:13px; }
      .chart-card { padding:20px; }
      .chart-head { display:flex; justify-content:space-between; align-items:end; margin-bottom:10px; gap:12px; }
      .chart-note { color:var(--muted); font-size:13px; }
      canvas { width:100%; height:240px; display:block; background:linear-gradient(180deg, rgba(255,107,53,.04), transparent 45%); border-radius:18px; }
      .events { display:grid; gap:10px; max-height: 250px; overflow:auto; }
      .event { display:flex; justify-content:space-between; align-items:start; gap:12px; padding:12px 14px; border-radius:16px; background:white; border:1px solid var(--line); }
      .event strong { display:block; font-size:15px; }
      .event small { color:var(--muted); display:block; margin-top:4px; }
      .event .badge { padding:6px 10px; border-radius:999px; font-size:12px; background:#fff3ee; color:#bf4d23; white-space:nowrap; }
      table { width:100%; border-collapse:collapse; font-size:14px; }
      th, td { padding:10px 6px; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }
      th { color:var(--muted); font-weight:600; }
      .empty { color:var(--muted); padding:22px 0 6px; }
      @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.55; } }
      @media (max-width: 1080px) {
        .hero, .layout { grid-template-columns:1fr; }
        .metrics { grid-template-columns:repeat(2,1fr); }
        .button-grid { grid-template-columns:1fr; }
      }
      @media (max-width: 640px) {
        .wrap { padding:16px; }
        .metrics { grid-template-columns:1fr; }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="hero">
        <section class="hero-main">
          <div class="eyebrow">Autonomous chaos engineering and self-healing</div>
          <h1>ChaosLoop Live Control Room</h1>
          <div class="statusbar">
            <div class="chip"><span class="dot"></span><span id="liveState">Streaming live from the cluster</span></div>
            <div class="chip">Last sample <strong id="sampleTime">--:--:--</strong></div>
            <div class="chip">Signal <strong id="signalState">Nominal</strong></div>
          </div>
        </section>
        <section class="hero-side">
          <div>
            <h3>Chaos Scenarios</h3>
            <div class="chart-note">Trigger a failure and watch detection and recovery update immediately.</div>
          </div>
          <div class="button-grid">
            <button onclick="trigger('pod-crash','order-service')">Crash Order Pod</button>
            <button onclick="trigger('network-partition','payment-service')">Partition Payment</button>
            <button onclick="trigger('latency','api-gateway')">Inject Latency</button>
          </div>
        </section>
      </div>
      <section class="metrics">
        <div class="card"><div class="metric-label">Anomaly score</div><div id="score" class="kpi">0.00</div><div class="micro" id="scoreMeta">IsolationForest signal</div></div>
        <div class="card"><div class="metric-label">Classification</div><div id="classification" class="kpi">steady</div><div class="micro" id="classificationMeta">No active anomaly</div></div>
        <div class="card"><div class="metric-label">Recovery action</div><div id="recovery" class="kpi">none</div><div class="micro" id="recoveryMeta">Autonomous remediation idle</div></div>
        <div class="card"><div class="metric-label">Latency p95</div><div id="latency" class="kpi">0ms</div><div class="micro" id="latencyMeta">Live request path health</div></div>
      </section>
      <div class="layout" style="margin-top:18px">
        <div class="stack">
          <section class="card chart-card">
            <div class="chart-head">
              <div>
                <h3>Anomaly Signal</h3>
                <div class="chart-note">Every point is streamed from the control loop as soon as it changes.</div>
              </div>
              <div class="chip">Window <strong id="windowSize">0</strong></div>
            </div>
            <canvas id="scoreChart" height="160"></canvas>
          </section>
          <section class="card">
            <h3>Incident Feed</h3>
            <div class="chart-note">Latest anomalies, decisions, and recovery actions in one stream.</div>
            <div id="feed" class="events"></div>
          </section>
        </div>
        <div class="stack">
          <section class="card">
            <h3>Recovery Timeline</h3>
            <table id="timeline"></table>
          </section>
          <section class="card">
            <h3>Decision Log</h3>
            <table id="decisions"></table>
          </section>
        </div>
      </div>
    </div>
    <script>
      const canvas = document.getElementById('scoreChart');
      const ctx = canvas.getContext('2d');
      let lastStreamAt = Date.now();
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
        if (values.length) {
          const latest = values[values.length - 1];
          const x = w - 18 * devicePixelRatio;
          const y = h - ((Math.max(0, Math.min(1, latest))) * (h - 24 * devicePixelRatio) + 12 * devicePixelRatio);
          ctx.fillStyle = '#ff6b35';
          ctx.beginPath();
          ctx.arc(x, y, 5 * devicePixelRatio, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      function render(data) {
        lastStreamAt = Date.now();
        document.getElementById('liveState').textContent = 'Streaming live from the cluster';
        const items = data.scores || [];
        draw(items.map(i => i.score));
        const latest = items[items.length - 1];
        document.getElementById('score').textContent = latest ? latest.score.toFixed(2) : '0.00';
        const latestSample = latest && latest.sample ? latest.sample : {};
        const lastEvent = (data.events || []).slice(-1)[0];
        document.getElementById('classification').textContent = lastEvent ? lastEvent.classification : 'steady';
        document.getElementById('classificationMeta').textContent = lastEvent ? `Score ${lastEvent.score.toFixed(2)}` : 'No active anomaly';
        const lastRecovery = (data.timeline || []).slice(-1)[0];
        document.getElementById('recovery').textContent = lastRecovery ? lastRecovery.action : 'none';
        document.getElementById('recoveryMeta').textContent = lastRecovery ? `${lastRecovery.status} at ${lastRecovery.ts.slice(11,19)}` : 'Autonomous remediation idle';
        document.getElementById('latency').textContent = `${Math.round((latestSample.latency_p95 || 0) * 1000)}ms`;
        document.getElementById('latencyMeta').textContent = `Availability ${(latestSample.availability || 1).toFixed(2)}`;
        document.getElementById('sampleTime').textContent = latest ? latest.ts.slice(11,19) : '--:--:--';
        document.getElementById('windowSize').textContent = String(items.length);
        document.getElementById('signalState').textContent = latest && latest.score >= 0.58 ? 'Active incident' : 'Nominal';
        document.getElementById('scoreMeta').textContent = latest ? `Updated ${latest.ts.slice(11,19)}` : 'IsolationForest signal';
        const timelineRows = (data.timeline || []).slice(-8).reverse().map(i => `<tr><td>${i.ts.slice(11,19)}</td><td>${i.action}</td><td>${i.status}</td></tr>`).join('');
        const decisionRows = (data.decisions || []).slice(-8).reverse().map(i => `<tr><td>${i.event.classification}</td><td>${i.actions.map(a => a.action).join(', ')}</td></tr>`).join('');
        document.getElementById('timeline').innerHTML = '<tr><th>Time</th><th>Action</th><th>Status</th></tr>' + (timelineRows || '<tr><td colspan="3" class="empty">No recovery actions yet.</td></tr>');
        document.getElementById('decisions').innerHTML = '<tr><th>Event</th><th>Actions</th></tr>' + (decisionRows || '<tr><td colspan="2" class="empty">No decisions yet.</td></tr>');
        const feed = [];
        (data.events || []).slice(-4).reverse().forEach(item => feed.push(
          `<div class="event"><div><strong>${item.classification}</strong><small>${item.ts.slice(11,19)} | score ${item.score.toFixed(2)}</small></div><div class="badge">detect</div></div>`
        ));
        (data.decisions || []).slice(-4).reverse().forEach(item => feed.push(
          `<div class="event"><div><strong>${item.event.classification}</strong><small>${item.actions.map(a => a.action).join(', ')}</small></div><div class="badge">decide</div></div>`
        ));
        (data.timeline || []).slice(-4).reverse().forEach(item => feed.push(
          `<div class="event"><div><strong>${item.action}</strong><small>${item.ts.slice(11,19)} | ${item.status}</small></div><div class="badge">recover</div></div>`
        ));
        document.getElementById('feed').innerHTML = feed.slice(0, 10).join('') || '<div class="empty">No incidents yet. Trigger a scenario to watch the closed loop react.</div>';
      }
      async function load() {
        const payload = await fetch('/api/snapshot').then(r => r.json());
        render(payload);
      }
      function startStream() {
        const stream = new EventSource('/api/live');
        stream.onmessage = event => render(JSON.parse(event.data));
        stream.onerror = () => {
          document.getElementById('liveState').textContent = 'Reconnecting live stream';
          stream.close();
          setTimeout(startStream, 1000);
        };
      }
      async function trigger(scenario, target) {
        await fetch(`/api/chaos/${scenario}`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ target, latency_ms:1500 })});
        load();
      }
      load();
      startStream();
      setInterval(() => {
        if (Date.now() - lastStreamAt > 2500) {
          load();
        }
      }, 1000);
      window.addEventListener('resize', () => {
        fetch('/api/snapshot').then(r => r.json()).then(render);
      });
    </script>
  </body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return HTML


async def proxy(url: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def snapshot_payload() -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        scores_response, events_response, decisions_response, timeline_response = await asyncio.gather(
            client.get(f"{DETECTOR_URL}/scores"),
            client.get(f"{DETECTOR_URL}/events"),
            client.get(f"{DECISION_URL}/decisions"),
            client.get(f"{RECOVERY_URL}/timeline"),
        )
        for response in (scores_response, events_response, decisions_response, timeline_response):
            response.raise_for_status()
        return {
            "scores": scores_response.json().get("items", []),
            "events": events_response.json().get("items", []),
            "decisions": decisions_response.json().get("items", []),
            "timeline": timeline_response.json().get("items", []),
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


@app.get("/api/scores")
async def scores() -> dict:
    return await proxy(f"{DETECTOR_URL}/scores")


@app.get("/api/events")
async def events() -> dict:
    return await proxy(f"{DETECTOR_URL}/events")


@app.get("/api/decisions")
async def decisions() -> dict:
    return await proxy(f"{DECISION_URL}/decisions")


@app.get("/api/timeline")
async def timeline() -> dict:
    return await proxy(f"{RECOVERY_URL}/timeline")


@app.post("/api/chaos/{scenario}")
async def chaos(scenario: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=8.0) as client:
        response = await client.post(f"{CHAOS_URL}/scenarios/{scenario}", json=payload)
        response.raise_for_status()
        return response.json()
