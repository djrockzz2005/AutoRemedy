from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

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
    <title>Chaos Loop Dashboard</title>
    <style>
      :root { color-scheme: light; --bg:#f4efe8; --card:#fffdf9; --ink:#17212b; --accent:#d14d2f; --muted:#69717c; }
      body { margin:0; font-family: "IBM Plex Sans", sans-serif; background: radial-gradient(circle at top left,#fff7ea,transparent 35%), linear-gradient(135deg,#f4efe8,#e6edf2); color:var(--ink); }
      .wrap { max-width: 1240px; margin: 0 auto; padding: 24px; }
      .hero { display:flex; justify-content:space-between; gap:24px; align-items:end; margin-bottom:24px; }
      h1 { font-family: "Space Grotesk", sans-serif; font-size: 40px; margin:0; }
      .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(300px,1fr)); gap:18px; }
      .card { background:var(--card); border:1px solid rgba(23,33,43,.08); border-radius:20px; padding:18px; box-shadow:0 12px 30px rgba(23,33,43,.06); }
      .kpi { font-size:28px; font-weight:700; }
      .muted { color:var(--muted); }
      table { width:100%; border-collapse: collapse; font-size:14px; }
      th, td { padding:8px; text-align:left; border-bottom:1px solid rgba(23,33,43,.08); }
      button { background:var(--accent); color:white; border:none; padding:12px 14px; border-radius:999px; cursor:pointer; margin-right:8px; }
      canvas { width:100%; height:220px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="hero">
        <div>
          <div class="muted">Autonomous chaos engineering and self-healing</div>
          <h1>Closed-Loop Incident Lab</h1>
        </div>
        <div>
          <button onclick="trigger('pod-crash','order-service')">Crash Order Pod</button>
          <button onclick="trigger('network-partition','payment-service')">Partition Payment</button>
          <button onclick="trigger('latency','api-gateway')">Inject Latency</button>
        </div>
      </div>
      <div class="grid">
        <div class="card"><div class="muted">Latest anomaly score</div><div id="score" class="kpi">0.00</div></div>
        <div class="card"><div class="muted">Last classification</div><div id="classification" class="kpi">steady</div></div>
        <div class="card"><div class="muted">Latest recovery action</div><div id="recovery" class="kpi">none</div></div>
      </div>
      <div class="grid" style="margin-top:18px">
        <div class="card"><canvas id="scoreChart" height="120"></canvas></div>
        <div class="card"><h3>Recovery Timeline</h3><table id="timeline"></table></div>
        <div class="card"><h3>Decision Log</h3><table id="decisions"></table></div>
      </div>
    </div>
    <script>
      const canvas = document.getElementById('scoreChart');
      const ctx = canvas.getContext('2d');
      function draw(values) {
        const w = canvas.width = canvas.clientWidth * devicePixelRatio;
        const h = canvas.height = canvas.clientHeight * devicePixelRatio;
        ctx.clearRect(0, 0, w, h);
        ctx.strokeStyle = '#d14d2f';
        ctx.lineWidth = 3 * devicePixelRatio;
        ctx.beginPath();
        values.forEach((v, idx) => {
          const x = (idx / Math.max(values.length - 1, 1)) * (w - 24 * devicePixelRatio) + 12 * devicePixelRatio;
          const y = h - ((Math.max(0, Math.min(1, v))) * (h - 24 * devicePixelRatio) + 12 * devicePixelRatio);
          if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();
      }
      async function load() {
        const [scores, decisions, timeline, events] = await Promise.all([
          fetch('/api/scores').then(r => r.json()),
          fetch('/api/decisions').then(r => r.json()),
          fetch('/api/timeline').then(r => r.json()),
          fetch('/api/events').then(r => r.json())
        ]);
        const items = scores.items || [];
        draw(items.map(i => i.score));
        const latest = items[items.length - 1];
        document.getElementById('score').textContent = latest ? latest.score.toFixed(2) : '0.00';
        const lastEvent = (events.items || []).slice(-1)[0];
        document.getElementById('classification').textContent = lastEvent ? lastEvent.classification : 'steady';
        const lastRecovery = (timeline.items || []).slice(-1)[0];
        document.getElementById('recovery').textContent = lastRecovery ? lastRecovery.action : 'none';
        document.getElementById('timeline').innerHTML = '<tr><th>Time</th><th>Action</th><th>Status</th></tr>' +
          (timeline.items || []).slice(-8).reverse().map(i => `<tr><td>${i.ts.slice(11,19)}</td><td>${i.action}</td><td>${i.status}</td></tr>`).join('');
        document.getElementById('decisions').innerHTML = '<tr><th>Event</th><th>Actions</th></tr>' +
          (decisions.items || []).slice(-8).reverse().map(i => `<tr><td>${i.event.classification}</td><td>${i.actions.map(a => a.action).join(', ')}</td></tr>`).join('');
      }
      async function trigger(scenario, target) {
        await fetch(`/api/chaos/${scenario}`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ target, latency_ms:1500 })});
        setTimeout(load, 2000);
      }
      load();
      setInterval(load, 5000);
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
