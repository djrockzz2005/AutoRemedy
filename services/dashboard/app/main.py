from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from kubernetes import client, config

from services.shared.audit import audit_event
from services.shared.auth import ROLE_ADMIN, ROLE_OPERATOR, bearer_principal_and_role
from services.shared.migrations import migrate
from services.shared.maintenance import prune_tables
from services.shared.notifications import notification_worker
from services.shared.observability import install_observability, traced_get, traced_post
from services.shared.security import get_controls, increment_security_metric, payload_has_xss, record_request, suspicious_embedding_request
from services.shared.store import ensure_table, pg_conn

app = FastAPI(title="dashboard")
logger = install_observability(app, "dashboard")

DETECTOR_URL = os.getenv("DETECTOR_URL", "http://anomaly-detector:8000")
DECISION_URL = os.getenv("DECISION_URL", "http://decision-engine:8000")
RECOVERY_URL = os.getenv("RECOVERY_URL", "http://recovery-engine:8000")
CHAOS_URL = os.getenv("CHAOS_URL", "http://chaos-engine:8000")
TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://telemetry-bridge:8000")
PLATFORM_NAMESPACE = os.getenv("PLATFORM_NAMESPACE", "chaos-loop")
TARGET_NAMESPACES = [item.strip() for item in os.getenv("TARGET_NAMESPACES", PLATFORM_NAMESPACE).split(",") if item.strip()]
DOCKER_SOCKET_PATH = os.getenv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
OPERATOR_API_KEY = os.getenv("DASHBOARD_OPERATOR_API_KEY", "")
ADMIN_API_KEY = os.getenv("DASHBOARD_ADMIN_API_KEY", "")
STARTUP_DB_RETRY_SECONDS = float(os.getenv("STARTUP_DB_RETRY_SECONDS", "5"))
SESSION_COOKIE_NAME = os.getenv("DASHBOARD_SESSION_COOKIE", "dashboard_session")
SESSION_COOKIE_MAX_AGE = int(os.getenv("DASHBOARD_SESSION_MAX_AGE_SECONDS", "43200"))
SESSION_SECRET = os.getenv("DASHBOARD_SESSION_SECRET", "autoremedy-dashboard-session-secret")
AUTH_MIN_PASSWORD_LENGTH = int(os.getenv("DASHBOARD_MIN_PASSWORD_LENGTH", "8"))
CSRF_COOKIE_NAME = os.getenv("DASHBOARD_CSRF_COOKIE", "dashboard_csrf")
CSRF_TOKEN_TTL_SECONDS = int(os.getenv("CSRF_TOKEN_TTL_SECONDS", "1800"))
ALLOWED_EMBED_HOSTS = [item.strip() for item in os.getenv("DASHBOARD_ALLOWED_HOSTS", "localhost,dashboard").split(",") if item.strip()]


def dashboard_db():
    return pg_conn("postgres")


def ensure_dashboard_auth_table() -> None:
    with dashboard_db() as connection:
        ensure_table(
            connection,
            """
            CREATE TABLE IF NOT EXISTS dashboard_users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """,
        )


def normalize_username(value: str) -> str:
    return value.strip().lower()


def password_hash(password: str, salt: str | None = None) -> str:
    salt_value = salt or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_value.encode(), 120_000)
    return f"{salt_value}${base64.urlsafe_b64encode(digest).decode().rstrip('=')}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected = stored_hash.split("$", 1)
    except ValueError:
        return False
    actual = password_hash(password, salt).split("$", 1)[1]
    return hmac.compare_digest(actual, expected)


def session_cookie_value(username: str) -> str:
    nonce = secrets.token_urlsafe(12)
    payload = f"{username}:{nonce}"
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def username_from_session(value: str | None) -> str | None:
    if not value:
        return None
    try:
        username, issued_at, signature = value.split(":", 2)
    except ValueError:
        return None
    payload = f"{username}:{issued_at}"
    expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return normalize_username(username)


def authenticated_username(request: Request) -> str | None:
    return username_from_session(request.cookies.get(SESSION_COOKIE_NAME))


def csrf_token_value(username: str) -> str:
    issued_at = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    payload = f"{normalize_username(username)}:{issued_at}:{nonce}"
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"


def csrf_token_for_request(request: Request) -> str | None:
    return request.cookies.get(CSRF_COOKIE_NAME)


def validate_csrf_token(request: Request, username: str | None) -> bool:
    token = request.headers.get("x-csrf-token") or request.cookies.get(CSRF_COOKIE_NAME)
    if not token or not username:
        return False
    try:
        token_user, issued_at, nonce, signature = token.split(":", 3)
    except ValueError:
        return False
    if normalize_username(token_user) != normalize_username(username):
        return False
    payload = f"{token_user}:{issued_at}:{nonce}"
    expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    return (int(time.time()) - int(issued_at)) <= CSRF_TOKEN_TTL_SECONDS


def apply_session_cookies(response: Response, username: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_cookie_value(username),
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token_value(username),
        max_age=CSRF_TOKEN_TTL_SECONDS,
        httponly=False,
        samesite="strict",
    )


HTML = r"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="csrf-token" content="__CSRF_TOKEN__" />
    <title>AutoRemedy Operator Console</title>
    <style>
      :root { color-scheme: light; --bg:#edf2f7; --panel:#fcfdff; --panel-strong:#ffffff; --ink:#122033; --muted:#64748b; --line:rgba(15,23,42,.08); --line-strong:rgba(15,23,42,.14); --accent:#ff6b35; --accent-2:#ff9f45; --danger:#df3f54; --ok:#23967f; --warn:#f4a261; --glow:rgba(255,107,53,.18); --shadow:0 18px 40px rgba(15,23,42,.08); }
      * { box-sizing:border-box; }
      body { margin:0; font-family:"IBM Plex Sans",sans-serif; color:var(--ink); background:
        radial-gradient(circle at 0% 0%, rgba(255,176,77,.18), transparent 24%),
        radial-gradient(circle at 100% 0%, rgba(59,130,246,.12), transparent 20%),
        linear-gradient(160deg, #f7f4ee 0%, #edf2f7 42%, #eef5fb 100%); }
      .wrap { max-width:1540px; margin:0 auto; padding:28px 24px 40px; }
      .masthead { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:14px; }
      .brand { display:flex; align-items:center; gap:14px; }
      .brand-mark { width:46px; height:46px; border-radius:14px; background:linear-gradient(135deg,var(--accent),var(--accent-2)); box-shadow:0 12px 30px var(--glow); position:relative; }
      .brand-mark::after { content:""; position:absolute; inset:11px; border-radius:50%; border:3px solid rgba(255,255,255,.75); border-left-color:transparent; transform:rotate(20deg); }
      .brand-copy strong { display:block; font-size:18px; letter-spacing:-.02em; }
      .brand-copy span { color:var(--muted); font-size:13px; }
      html, body { overflow-x:hidden; }
      .hero, .top-grid, .main-grid, .bottom-grid { display:grid; gap:18px; }
      .hero { grid-template-columns: 1.2fr .8fr; margin-bottom:18px; }
      .top-grid { grid-template-columns: repeat(4, 1fr); margin-bottom:18px; }
      .main-grid { grid-template-columns: minmax(0, 1.2fr) minmax(0, .8fr); margin-bottom:18px; }
      .bottom-grid { grid-template-columns: 1fr 1fr; }
      .stack { display:grid; gap:18px; }
      .card { background:rgba(252,253,255,.86); backdrop-filter: blur(18px); border:1px solid var(--line); border-radius:28px; padding:18px; box-shadow:var(--shadow); min-width:0; }
      .hero-main { padding:30px; min-height:220px; position:relative; overflow:hidden; background:
        radial-gradient(circle at 85% 20%, rgba(255,107,53,.16), transparent 18%),
        linear-gradient(135deg, rgba(255,255,255,.95), rgba(249,250,252,.9)); }
      .hero-main::after { content:""; position:absolute; inset:auto -40px -60px auto; width:260px; height:260px; background: radial-gradient(circle, rgba(255,107,53,.18), transparent 68%); }
      .eyebrow { color:var(--muted); font-size:14px; text-transform:uppercase; letter-spacing:.08em; margin-bottom:10px; }
      h1 { font-family:"Space Grotesk",sans-serif; font-size: clamp(38px, 5vw, 64px); line-height:.94; margin:0 0 16px; max-width:8ch; }
      h3 { margin:0; font-size:18px; letter-spacing:-.02em; }
      .note, .micro { color:var(--muted); font-size:13px; }
      .statusbar, .pill-row, .toolbar, .form-grid { display:flex; flex-wrap:wrap; gap:10px; }
      .chip, .pill { display:inline-flex; align-items:center; gap:8px; padding:10px 14px; border-radius:999px; background:#fff; border:1px solid var(--line); font-size:14px; box-shadow: inset 0 1px 0 rgba(255,255,255,.65); }
      .pill { padding:6px 10px; font-size:12px; }
      .pill.good { background:#edf9f6; color:#1f7f72; }
      .pill.bad { background:#fff0f0; color:#bd3030; }
      .notice { display:none; margin:0 0 18px; padding:14px 16px; border-radius:18px; border:1px solid var(--line); background:#fff; box-shadow:var(--shadow); }
      .notice.show { display:block; }
      .notice.success { border-color:rgba(35,150,127,.18); background:#edf9f6; color:#145b4f; }
      .notice.error { border-color:rgba(223,63,84,.18); background:#fff0f0; color:#8a2435; }
      .notice.info { border-color:rgba(244,162,97,.2); background:#fff7ef; color:#8b5c23; }
      .auth-shell { min-height:100vh; display:grid; place-items:center; padding:24px; }
      .auth-frame { width:min(980px, 100%); display:grid; grid-template-columns:1.05fr .95fr; gap:18px; }
      .auth-card { background:rgba(252,253,255,.9); backdrop-filter: blur(18px); border:1px solid var(--line); border-radius:28px; padding:24px; box-shadow:var(--shadow); }
      .auth-stack { display:grid; gap:14px; }
      .auth-grid { display:grid; gap:18px; }
      .auth-card h2 { margin:0; font-family:"Space Grotesk",sans-serif; font-size:30px; letter-spacing:-.03em; }
      .auth-card p { margin:0; color:var(--muted); }
      .auth-actions { display:flex; gap:10px; flex-wrap:wrap; }
      .auth-toggle { display:grid; grid-template-columns:1fr 1fr; gap:10px; padding:6px; border-radius:20px; background:rgba(255,255,255,.8); border:1px solid var(--line); }
      .auth-toggle button { box-shadow:none; }
      .auth-toggle button.active { background:linear-gradient(135deg,#ec5a29,#ff7b3d); color:#fff; }
      .auth-panel { display:none; }
      .auth-panel.active { display:grid; }
      .ghost { background:#fff; color:var(--ink); border:1px solid var(--line); box-shadow:none; }
      .hidden { display:none !important; }
      .dot { width:10px; height:10px; border-radius:50%; background:var(--ok); box-shadow:0 0 0 8px rgba(42,157,143,.12); animation:pulse 1.2s infinite; }
      .hero-stats { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:12px; margin-top:22px; position:relative; z-index:1; }
      .hero-stat { border:1px solid var(--line); border-radius:20px; background:rgba(255,255,255,.72); padding:14px; }
      .hero-stat strong { display:block; font-size:18px; margin-bottom:4px; }
      .hero-stat span { color:var(--muted); font-size:13px; }
      .kpi { font-size:clamp(22px, 2.2vw, 34px); line-height:1.06; font-weight:700; letter-spacing:-.035em; margin-top:8px; overflow-wrap:anywhere; word-break:break-word; hyphens:auto; }
      .metric-label { color:var(--muted); font-size:14px; }
      .metric-card { position:relative; overflow:hidden; background:linear-gradient(180deg, rgba(255,255,255,.95), rgba(248,250,252,.9)); }
      .metric-card::before { content:""; position:absolute; inset:auto auto -22px -22px; width:84px; height:84px; border-radius:50%; background:radial-gradient(circle, rgba(255,107,53,.12), transparent 70%); }
      .control-grid, .list { display:grid; gap:12px; }
      .list { max-height:520px; overflow:auto; min-width:0; padding-right:4px; }
      .row-card { padding:14px; border-radius:18px; border:1px solid var(--line); background:#fff; cursor:pointer; transition:border-color .15s ease, transform .15s ease, box-shadow .15s ease; box-shadow:0 8px 20px rgba(15,23,42,.03); }
      .row-card.active { border-color:rgba(255,107,53,.55); box-shadow:0 10px 24px rgba(255,107,53,.12); transform:translateY(-1px); }
      .row-head { display:flex; justify-content:space-between; gap:10px; min-width:0; }
      .row-title { font-weight:700; }
      .row-sub { color:var(--muted); font-size:13px; margin-top:4px; overflow-wrap:anywhere; word-break:break-word; }
      label { display:grid; gap:6px; font-size:13px; color:var(--muted); }
      .control-panel { position:sticky; top:20px; align-self:start; }
      .toolbar { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); }
      .toolbar button { width:100%; }
      select, input, textarea { width:100%; border-radius:14px; border:1px solid var(--line); padding:12px 14px; font:inherit; background:#fff; color:var(--ink); transition:border-color .15s ease, box-shadow .15s ease; }
      select:focus, input:focus, textarea:focus { outline:none; border-color:rgba(255,107,53,.5); box-shadow:0 0 0 4px rgba(255,107,53,.12); }
      textarea { min-height:220px; resize:vertical; white-space:pre-wrap; overflow-wrap:anywhere; }
      button { border:none; border-radius:16px; padding:12px 14px; font:inherit; cursor:pointer; color:white; background:linear-gradient(135deg,#ec5a29,#ff7b3d); box-shadow:0 14px 30px var(--glow); transition:transform .16s ease, filter .16s ease; font-weight:600; }
      button:hover { transform:translateY(-1px); filter:brightness(1.03); }
      button:active { transform:translateY(1px); }
      canvas { width:100%; height:240px; display:block; background:linear-gradient(180deg, rgba(255,107,53,.04), transparent 45%); border-radius:18px; }
      .table-wrap { overflow-x:hidden; overflow-y:auto; border-radius:18px; border:1px solid var(--line); background:rgba(255,255,255,.66); margin-top:12px; min-width:0; }
      table { width:100%; border-collapse:collapse; font-size:14px; table-layout:fixed; }
      th, td { padding:10px 6px; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }
      th { color:var(--muted); font-weight:600; }
      th:first-child, td:first-child { padding-left:14px; }
      th:last-child, td:last-child { padding-right:14px; }
      td { overflow-wrap:anywhere; word-break:break-word; }
      .events { display:grid; gap:10px; max-height:280px; overflow:auto; }
      .event { display:flex; justify-content:space-between; align-items:start; gap:12px; padding:12px 14px; border-radius:16px; background:#fff; border:1px solid var(--line); }
      .event strong { display:block; font-size:15px; }
      .event small { color:var(--muted); display:block; margin-top:4px; }
      .section-head { display:flex; justify-content:space-between; align-items:end; gap:10px; margin-bottom:6px; }
      .section-kicker { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
      .split { display:grid; grid-template-columns:1fr 1fr; gap:14px; min-width:0; }
      .empty { color:var(--muted); padding:16px 0; }
      @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.55; } }
      @media (max-width: 1380px) {
        .main-grid, .bottom-grid { grid-template-columns:1fr; }
      }
      @media (max-width: 1180px) {
        .hero, .main-grid, .bottom-grid { grid-template-columns:1fr; }
        .top-grid { grid-template-columns:repeat(2, 1fr); }
        .control-panel { position:static; }
        .auth-frame, .auth-grid { grid-template-columns:1fr; }
      }
      @media (max-width: 700px) {
        .top-grid { grid-template-columns:1fr; }
        .split { grid-template-columns:1fr; }
        .hero-stats { grid-template-columns:1fr; }
        .toolbar { grid-template-columns:1fr 1fr; }
        .wrap { padding:16px; }
        .card { padding:16px; border-radius:24px; }
      }
      @media (max-width: 520px) {
        .toolbar { grid-template-columns:1fr; }
        .statusbar { flex-direction:column; align-items:stretch; }
      }
    </style>
  </head>
  <body>
    <div id="authShell" class="auth-shell">
      <div class="auth-frame">
        <section class="auth-card auth-stack">
          <div class="eyebrow">Secure Access</div>
          <h2>Log in to the AutoRemedy console</h2>
          <p>Use a local dashboard account to unlock the live console, chaos controls, and recovery actions.</p>
          <div class="hero-stats">
            <div class="hero-stat"><strong>One login</strong><span>Username and password replace actor names, API keys, and bearer tokens.</span></div>
            <div class="hero-stat"><strong>Session access</strong><span>The dashboard keeps you signed in with a secure cookie on this browser.</span></div>
            <div class="hero-stat"><strong>Shared console</strong><span>Create an account once, then come back directly to the operator view.</span></div>
          </div>
        </section>
        <section class="auth-card auth-stack">
          <div id="authStatus" class="notice" role="status" aria-live="polite"></div>
          <div class="auth-toggle">
            <button id="showLoginBtn" type="button" class="active" onclick="showAuthPanel('login')">Login</button>
            <button id="showSignupBtn" type="button" class="ghost" onclick="showAuthPanel('signup')">Signup</button>
          </div>
          <div class="auth-grid">
            <form id="loginForm" class="auth-stack auth-panel active">
              <div class="section-kicker">Login</div>
              <label>Username
                <input id="loginUsername" type="text" autocomplete="username" placeholder="operator" />
              </label>
              <label>Password
                <input id="loginPassword" type="password" autocomplete="current-password" placeholder="Password" />
              </label>
              <div class="auth-actions">
                <button type="submit">Log In</button>
              </div>
            </form>
            <form id="signupForm" class="auth-stack auth-panel">
              <div class="section-kicker">Signup</div>
              <label>Username
                <input id="signupUsername" type="text" autocomplete="username" placeholder="new operator" />
              </label>
              <label>Password
                <input id="signupPassword" type="password" autocomplete="new-password" placeholder="At least 8 characters" />
              </label>
              <label>Confirm Password
                <input id="signupConfirmPassword" type="password" autocomplete="new-password" placeholder="Repeat your password" />
              </label>
              <div class="auth-actions">
                <button type="submit">Create Account</button>
              </div>
            </form>
          </div>
        </section>
      </div>
    </div>
    <div id="appShell" class="hidden">
    <div class="wrap">
      <div id="actionStatus" class="notice" role="status" aria-live="polite"></div>
      <div class="masthead">
        <div class="brand">
          <div class="brand-mark"></div>
          <div class="brand-copy">
            <strong>AutoRemedy</strong>
            <span>Autonomous chaos engineering and self-healing platform</span>
          </div>
        </div>
        <div class="statusbar">
          <div class="chip">Signed in as <strong id="sessionUser">--</strong></div>
          <button class="ghost" type="button" onclick="logout()">Log Out</button>
        </div>
      </div>
      <div class="hero">
        <section class="card hero-main">
          <div class="eyebrow">Autonomous chaos engineering and self-healing</div>
          <h1>AutoRemedy Operator Console</h1>
          <div class="statusbar">
            <div class="chip"><span class="dot"></span><span id="liveState">Streaming live from the cluster</span></div>
            <div class="chip">Last sample <strong id="sampleTime">--:--:--</strong></div>
            <div class="chip">Signal <strong id="signalState">Nominal</strong></div>
          </div>
          <div class="hero-stats">
            <div class="hero-stat"><strong>Detect</strong><span>Telemetry, anomaly scores, per-service attribution</span></div>
            <div class="hero-stat"><strong>Decide</strong><span>Dynamic recovery planning with cooldown protection</span></div>
            <div class="hero-stat"><strong>Recover</strong><span>Restart, scale, reset latency, and route traffic</span></div>
          </div>
        </section>
        <section class="card control-panel">
          <div class="section-head">
            <div>
              <div class="section-kicker">Control Plane</div>
              <h3>Authenticated Actions</h3>
            </div>
            <div class="pill">Live</div>
          </div>
          <div class="note" style="margin:8px 0 12px">Your signed-in dashboard account is used automatically for access and audit logging.</div>
          <div class="control-grid">
            <label>Target Workload
              <select id="workloadSelect"></select>
            </label>
            <div class="split">
              <label>Injected Latency (ms)
                <input id="latencyInput" type="number" min="50" step="50" value="1500" placeholder="Latency ms" />
              </label>
              <label>Scale Target
                <input id="scaleInput" type="number" min="1" step="1" value="3" placeholder="Replica count" />
              </label>
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
        <div class="card metric-card"><div class="metric-label">Anomaly score</div><div id="score" class="kpi">0.00</div><div class="micro" id="scoreMeta">IsolationForest signal</div></div>
        <div class="card metric-card"><div class="metric-label">Classification</div><div id="classification" class="kpi">steady</div><div class="micro" id="classificationMeta">No active anomaly</div></div>
        <div class="card metric-card"><div class="metric-label">Recovery action</div><div id="recovery" class="kpi">none</div><div class="micro" id="recoveryMeta">Autonomous remediation idle</div></div>
        <div class="card metric-card"><div class="metric-label">Latency p95</div><div id="latency" class="kpi">0ms</div><div class="micro" id="latencyMeta">Live request path health</div></div>
        <div class="card metric-card"><div class="metric-label">SLO compliance</div><div id="sloCompliance" class="kpi">100%</div><div class="micro" id="sloMeta">Error budget healthy</div></div>
        <div class="card metric-card"><div class="metric-label">Security posture</div><div id="securityStatus" class="kpi">Nominal</div><div class="micro" id="securityMeta">No active attack telemetry</div></div>
        <div class="card metric-card"><div class="metric-label">Blocked attempts</div><div id="blockedAttempts" class="kpi">0</div><div class="micro" id="blockedMeta">Gateway and dashboard blocks</div></div>
        <div class="card metric-card"><div class="metric-label">Mitigations</div><div id="activeMitigations" class="kpi">0</div><div class="micro" id="mitigationMeta">Temporary controls inactive</div></div>
      </section>

      <section class="main-grid">
        <div class="stack">
          <section class="card">
            <div class="section-head">
              <div>
                <div class="section-kicker">Analysis</div>
                <h3>Anomaly Signal</h3>
                <div class="note">Every point is streamed from the control loop as soon as it changes.</div>
              </div>
              <div class="chip">Window <strong id="windowSize">0</strong></div>
            </div>
            <canvas id="scoreChart" height="160"></canvas>
          </section>
          <section class="card">
            <div class="section-head">
              <div>
                <div class="section-kicker">Inventory</div>
                <h3>Kubernetes Explorer</h3>
              </div>
              <div class="pill">Cluster</div>
            </div>
            <div class="note">Live view of deployments, pods, readiness, restarts, and health across monitored namespaces.</div>
            <div id="workloads" class="list" style="margin-top:12px"></div>
          </section>
        </div>
        <div class="stack">
          <section class="card">
            <div class="section-head">
              <div>
                <div class="section-kicker">Inspection</div>
                <h3>Selected Workload Health</h3>
              </div>
            </div>
            <div id="detailSummary" class="note" style="margin:8px 0 12px">Select a workload to inspect its pods, events, and logs.</div>
            <div id="podPills" class="pill-row"></div>
            <div class="stack" style="margin-top:14px">
              <div>
                <h3 style="font-size:16px">Recent Events</h3>
                <div class="table-wrap"><table id="eventsTable"></table></div>
              </div>
              <div>
                <h3 style="font-size:16px">Pod Inventory</h3>
                <div class="table-wrap"><table id="podsTable"></table></div>
              </div>
            </div>
          </section>
          <section class="card">
            <div class="section-head">
              <div>
                <div class="section-kicker">Diagnostics</div>
                <h3>Pod Logs</h3>
              </div>
            </div>
            <div class="note">Latest container logs for the selected workload.</div>
            <textarea id="logsView" readonly></textarea>
          </section>
        </div>
      </section>

      <section class="bottom-grid">
        <div class="stack">
          <section class="card">
            <div class="section-head">
              <div>
                <div class="section-kicker">Operations</div>
                <h3>Incident Feed</h3>
              </div>
            </div>
            <div class="note">Latest anomalies, decisions, and recovery actions in one stream.</div>
            <div id="feed" class="events" style="margin-top:12px"></div>
          </section>
          <section class="card">
            <div class="section-head"><div><div class="section-kicker">Closed Loop</div><h3>Recovery Timeline</h3></div></div>
            <div class="table-wrap"><table id="timeline"></table></div>
          </section>
          <section class="card">
            <div class="section-head"><div><div class="section-kicker">Planning</div><h3>Decision Log</h3></div></div>
            <div class="table-wrap"><table id="decisions"></table></div>
          </section>
          <section class="card">
            <div class="section-head"><div><div class="section-kicker">Reliability</div><h3>SLO Status</h3></div></div>
            <div class="table-wrap"><table id="slos"></table></div>
          </section>
        </div>
        <div class="stack">
          <section class="card">
            <div class="section-head"><div><div class="section-kicker">Runtime</div><h3>Docker Runtime</h3></div></div>
            <div id="dockerSummary" class="note" style="margin:8px 0 12px">Inspecting host Docker when the API is reachable.</div>
            <div id="dockerContainers" class="list"></div>
          </section>
          <section class="card">
            <div class="section-head"><div><div class="section-kicker">Validation</div><h3>Chaos Experiments</h3></div></div>
            <div class="table-wrap"><table id="experiments"></table></div>
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
      let actionStatusTimer = null;
      let dashboardBootstrapped = false;
      let currentSession = null;
      let liveStream = null;

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

      function humanize(value) {
        if (!value) return 'None';
        return String(value)
          .replaceAll('_', ' ')
          .replaceAll('-', ' ')
          .replace(/\b\w/g, char => char.toUpperCase());
      }

      function classificationLabel(value) {
        if (!value) return 'Steady';
        if (value === 'unknown_anomaly') return 'Investigating';
        return humanize(value);
      }

      function preferredEvent(events) {
        const items = events || [];
        return [...items].reverse().find(item => item.classification && item.classification !== 'unknown_anomaly') || items[items.length - 1] || null;
      }

      function preferredRecovery(entries) {
        const items = entries || [];
        return [...items].reverse().find(item => item.status === 'completed') || items[items.length - 1] || null;
      }

      function setActionStatus(kind, message, keepVisible = false) {
        const element = document.getElementById('actionStatus');
        element.className = `notice ${kind} show`;
        element.textContent = message;
        if (actionStatusTimer) {
          clearTimeout(actionStatusTimer);
          actionStatusTimer = null;
        }
        if (!keepVisible) {
          actionStatusTimer = setTimeout(() => {
            element.className = 'notice';
            element.textContent = '';
          }, 5000);
        }
      }

      function setAuthStatus(kind, message) {
        const element = document.getElementById('authStatus');
        if (!message) {
          element.className = 'notice';
          element.textContent = '';
          return;
        }
        element.className = `notice ${kind} show`;
        element.textContent = message;
      }

      function showAuthPanel(panel) {
        const loginActive = panel === 'login';
        document.getElementById('loginForm').classList.toggle('active', loginActive);
        document.getElementById('signupForm').classList.toggle('active', !loginActive);
        document.getElementById('showLoginBtn').className = loginActive ? 'active' : 'ghost';
        document.getElementById('showSignupBtn').className = loginActive ? 'ghost' : 'active';
        setAuthStatus('', '');
      }

      function showAuthShell(message = '') {
        if (liveStream) {
          liveStream.close();
          liveStream = null;
        }
        currentSession = null;
        dashboardBootstrapped = false;
        document.getElementById('authShell').classList.remove('hidden');
        document.getElementById('appShell').classList.add('hidden');
        setAuthStatus(message ? 'info' : '', message);
      }

      function showDashboard(session) {
        currentSession = session;
        document.getElementById('sessionUser').textContent = session.username;
        if (session.csrf_token) {
          document.querySelector('meta[name="csrf-token"]').setAttribute('content', session.csrf_token);
        }
        document.getElementById('authShell').classList.add('hidden');
        document.getElementById('appShell').classList.remove('hidden');
        setAuthStatus('', '');
      }

      async function apiJson(url, options = {}) {
        const response = await fetch(url, options);
        let payload = {};
        try {
          payload = await response.json();
        } catch (_) {
          payload = {};
        }
        if (response.status === 401) {
          showAuthShell(payload.detail || 'Please log in to continue.');
        }
        if (!response.ok) {
          const detail = payload.detail || payload.message || `${response.status} ${response.statusText}`;
          throw new Error(detail);
        }
        return payload;
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
        const sloStatus = data.slos || { overall_compliance: 100, items: [] };
        draw(scores.map(item => item.score));
        const latest = scores[scores.length - 1];
        const latestSample = latest && latest.sample ? latest.sample : {};
        const latestEvent = preferredEvent(data.events);
        const latestRecovery = preferredRecovery(data.timeline);
        document.getElementById('score').textContent = latest ? latest.score.toFixed(2) : '0.00';
        document.getElementById('classification').textContent = latestEvent ? classificationLabel(latestEvent.classification) : 'Steady';
        document.getElementById('recovery').textContent = latestRecovery ? humanize(latestRecovery.action) : 'None';
        document.getElementById('latency').textContent = `${Math.round((latestSample.latency_p95 || 0) * 1000)}ms`;
        document.getElementById('sloCompliance').textContent = `${Math.round(sloStatus.overall_compliance || 100)}%`;
        document.getElementById('scoreMeta').textContent = latest ? `Updated ${latest.ts.slice(11,19)}` : 'IsolationForest signal';
        document.getElementById('classificationMeta').textContent = latestEvent
          ? `${latestEvent.classification === 'unknown_anomaly' ? 'Attribution pending' : `Score ${latestEvent.score.toFixed(2)}`}`
          : 'No active anomaly';
        document.getElementById('recoveryMeta').textContent = latestRecovery
          ? `${humanize(latestRecovery.status)} at ${latestRecovery.ts.slice(11,19)}`
          : 'Autonomous remediation idle';
        document.getElementById('latencyMeta').textContent = `Availability ${(latestSample.availability || 1).toFixed(2)}`;
        document.getElementById('sloMeta').textContent = (sloStatus.items || []).some(item => !item.healthy) ? 'SLO violations active' : 'Error budget healthy';
        const activeSecurityEvent = (data.events || []).slice().reverse().find(item => ['ddos_attack', 'mitm_attack', 'xss_attack', 'clickjacking_attack', 'csrf_attack'].includes(item.classification));
        const blockedAttempts = Math.round(latestSample.blocked_attempt_count || 0);
        const activeMitigations = Math.round(latestSample.active_mitigations || 0);
        document.getElementById('securityStatus').textContent = activeSecurityEvent ? classificationLabel(activeSecurityEvent.classification) : 'Nominal';
        document.getElementById('securityMeta').textContent = activeSecurityEvent
          ? `Last seen ${activeSecurityEvent.ts.slice(11,19)}`
          : 'No active attack telemetry';
        document.getElementById('blockedAttempts').textContent = String(blockedAttempts);
        document.getElementById('blockedMeta').textContent = `${Math.round(latestSample.xss_attempt_count || 0)} XSS, ${Math.round(latestSample.csrf_attempt_count || 0)} CSRF`;
        document.getElementById('activeMitigations').textContent = String(activeMitigations);
        document.getElementById('mitigationMeta').textContent = activeMitigations > 0 ? 'Temporary controls active' : 'Temporary controls inactive';
        document.getElementById('sampleTime').textContent = latest ? latest.ts.slice(11,19) : '--:--:--';
        document.getElementById('windowSize').textContent = String(scores.length);
        document.getElementById('signalState').textContent = latest && latest.score >= 0.58 ? 'Active incident' : 'Nominal';
        const timelineRows = (data.timeline || []).slice(-8).reverse().map(i => `<tr><td>${i.ts.slice(11,19)}</td><td>${i.namespace || '-'}</td><td>${humanize(i.action)}</td><td>${humanize(i.status)}</td></tr>`).join('');
        const decisionRows = (data.decisions || []).slice(-8).reverse().map(i => `<tr><td>${classificationLabel(i.event.classification)}</td><td>${i.actions.map(a => humanize(a.action)).join(', ')}</td></tr>`).join('');
        const sloRows = (sloStatus.items || []).map(i => `<tr><td>${i.service}</td><td>${i.compliance}%</td><td>${i.burn_rate}</td><td>${i.violations.join(', ') || 'ok'}</td></tr>`).join('');
        const experimentRows = (data.experiments || []).slice(-8).reverse().map(i => `<tr><td>${i.name}</td><td>${i.target || '-'}</td><td>${i.evaluation && i.evaluation.reason ? humanize(i.evaluation.reason) : humanize(i.status)}</td><td>${i.evaluation && i.evaluation.healed ? 'Healed' : humanize(i.status)}</td></tr>`).join('');
        document.getElementById('timeline').innerHTML = '<tr><th>Time</th><th>NS</th><th>Action</th><th>Status</th></tr>' + (timelineRows || '<tr><td colspan="4" class="empty">No recovery actions yet.</td></tr>');
        document.getElementById('decisions').innerHTML = '<tr><th>Event</th><th>Actions</th></tr>' + (decisionRows || '<tr><td colspan="2" class="empty">No decisions yet.</td></tr>');
        document.getElementById('slos').innerHTML = '<tr><th>Service</th><th>Compliance</th><th>Burn</th><th>Status</th></tr>' + (sloRows || '<tr><td colspan="4" class="empty">No SLOs configured.</td></tr>');
        document.getElementById('experiments').innerHTML = '<tr><th>Name</th><th>Target</th><th>Result</th><th>Status</th></tr>' + (experimentRows || '<tr><td colspan="4" class="empty">No experiments yet.</td></tr>');
        const feed = [];
        (data.events || []).slice(-4).reverse().forEach(item => feed.push(`<div class="event"><div><strong>${classificationLabel(item.classification)}</strong><small>${item.ts.slice(11,19)} | score ${item.score.toFixed(2)}</small></div><div class="pill">detect</div></div>`));
        (data.decisions || []).slice(-4).reverse().forEach(item => feed.push(`<div class="event"><div><strong>${classificationLabel(item.event.classification)}</strong><small>${item.actions.map(a => humanize(a.action)).join(', ')}</small></div><div class="pill">decide</div></div>`));
        (data.timeline || []).slice(-4).reverse().forEach(item => feed.push(`<div class="event"><div><strong>${humanize(item.action)}</strong><small>${item.namespace || '-'} | ${humanize(item.status)}</small></div><div class="pill">recover</div></div>`));
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
        const eventsRows = (data.events || []).map(item => `<tr><td>${item.time}</td><td>${humanize(item.reason)}</td><td>${item.message}</td></tr>`).join('');
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
        const payload = await apiJson('/api/snapshot');
        renderSnapshot(payload);
        renderWorkloads(payload.workloads || []);
      }

      async function refreshDetails() {
        const workload = workloadMap[selectedWorkloadKey];
        if (!workload) return;
        const params = new URLSearchParams({ namespace: workload.namespace, name: workload.name });
        const payload = await apiJson(`/api/kube/workload?${params}`);
        renderDetails(payload);
      }

      async function refreshDocker() {
        const payload = await apiJson('/api/docker/containers');
        renderDocker(payload);
      }

      function startStream() {
        if (liveStream) {
          liveStream.close();
        }
        liveStream = new EventSource('/api/live');
        liveStream.onmessage = event => {
          const payload = JSON.parse(event.data);
          renderSnapshot(payload);
          renderWorkloads(payload.workloads || []);
        };
        liveStream.onerror = () => {
          if (currentSession === null) {
            return;
          }
          document.getElementById('liveState').textContent = 'Reconnecting live stream';
          liveStream.close();
          setTimeout(startStream, 1000);
        };
      }

      function currentCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content') || '';
      }

      function authHeaders() {
        return {'Content-Type':'application/json', 'X-CSRF-Token': currentCsrfToken()};
      }

      async function bootstrapDashboard() {
        showDashboard(currentSession);
        if (dashboardBootstrapped) {
          await refreshSnapshot();
          await refreshDocker();
          await refreshDetails();
          return;
        }
        dashboardBootstrapped = true;
        try {
          await refreshSnapshot();
          await refreshDocker();
          await refreshDetails();
        } catch (error) {
          setActionStatus('error', `Dashboard bootstrap failed: ${error.message}`, true);
        }
        startStream();
        document.getElementById('workloadSelect').addEventListener('change', async event => selectWorkload(event.target.value));
        setInterval(() => {
          if (Date.now() - lastStreamAt > 2500) {
            refreshSnapshot().catch(error => setActionStatus('error', `Snapshot refresh failed: ${error.message}`));
          }
        }, 1000);
        setInterval(() => refreshDetails().catch(error => setActionStatus('error', `Detail refresh failed: ${error.message}`)), 4000);
        setInterval(() => refreshDocker().catch(error => setActionStatus('error', `Docker refresh failed: ${error.message}`)), 5000);
        window.addEventListener('resize', () => refreshSnapshot().catch(() => null));
      }

      async function authenticate(path, username, password) {
        const payload = await apiJson(path, {
          method:'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ username, password }),
        });
        currentSession = payload;
        await bootstrapDashboard();
      }

      async function loadSession() {
        const response = await fetch('/api/auth/session');
        if (response.status === 401) {
          showAuthShell('Log in or create an account to access the dashboard.');
          return;
        }
        if (!response.ok) {
          showAuthShell('Unable to verify your session right now.');
          return;
        }
        currentSession = await response.json();
        await bootstrapDashboard();
      }

      async function logout() {
        try {
          await fetch('/api/auth/logout', { method:'POST' });
        } catch (_) {
          // Ignore network errors and still return to the auth gate.
        }
        showAuthShell('You have been logged out.');
      }

      async function triggerSelected(scenario) {
        const payload = selectedPayload();
        payload.latency_ms = Number(document.getElementById('latencyInput').value || 1500);
        setActionStatus('info', `Running ${humanize(scenario)} on ${payload.namespace} / ${payload.target}...`, true);
        try {
          const result = await apiJson(`/api/chaos/${scenario}`, { method:'POST', headers: authHeaders(), body: JSON.stringify(payload) });
          setActionStatus('success', `${humanize(scenario)} executed for ${result.namespace || payload.namespace} / ${result.target || payload.target}`);
          await refreshSnapshot();
          await refreshDetails();
        } catch (error) {
          setActionStatus('error', `${humanize(scenario)} failed: ${error.message}`, true);
        }
      }

      async function recoverSelected(action) {
        const payload = selectedPayload();
        payload.action = action;
        if (action === 'scale_deployment') payload.replicas = Number(document.getElementById('scaleInput').value || 3);
        setActionStatus('info', `Running ${humanize(action)} on ${payload.namespace} / ${payload.target}...`, true);
        try {
          const result = await apiJson('/api/recover', { method:'POST', headers: authHeaders(), body: JSON.stringify(payload) });
          setActionStatus('success', `${humanize(action)} completed for ${result.namespace || payload.namespace} / ${result.target || payload.target}`);
          await refreshSnapshot();
          await refreshDetails();
        } catch (error) {
          setActionStatus('error', `${humanize(action)} failed: ${error.message}`, true);
        }
      }

      async function selectWorkload(key) {
        selectedWorkloadKey = key;
        renderWorkloads(Object.values(workloadMap));
        document.getElementById('workloadSelect').value = key;
        await refreshDetails();
      }

      document.addEventListener('DOMContentLoaded', async () => {
        document.getElementById('loginForm').addEventListener('submit', async event => {
          event.preventDefault();
          const username = document.getElementById('loginUsername').value.trim();
          const password = document.getElementById('loginPassword').value;
          try {
            await authenticate('/api/auth/login', username, password);
          } catch (error) {
            setAuthStatus('error', `Login failed: ${error.message}`);
          }
        });
        document.getElementById('signupForm').addEventListener('submit', async event => {
          event.preventDefault();
          const username = document.getElementById('signupUsername').value.trim();
          const password = document.getElementById('signupPassword').value;
          const confirmPassword = document.getElementById('signupConfirmPassword').value;
          if (password !== confirmPassword) {
            setAuthStatus('error', 'Signup failed: passwords do not match');
            return;
          }
          try {
            await authenticate('/api/auth/signup', username, password);
          } catch (error) {
            setAuthStatus('error', `Signup failed: ${error.message}`);
          }
        });
        await loadSession();
      });
    </script>
    </div>
    </div>
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
async def index(request: Request) -> str:
    username = authenticated_username(request)
    token = csrf_token_value(username) if username else ""
    return HTML.replace("__CSRF_TOKEN__", token)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(start_background_services())


async def start_background_services() -> None:
    while True:
        try:
            migrate()
            ensure_dashboard_auth_table()
            prune_tables(int(os.getenv("PLATFORM_RETENTION_DAYS", "14")))
            break
        except Exception as exc:
            logger.warning("Dashboard startup DB initialization deferred", extra={"error": str(exc)})
            await asyncio.sleep(STARTUP_DB_RETRY_SECONDS)
    asyncio.create_task(notification_worker())


async def proxy(url: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as http_client:
        response = await traced_get(http_client, url)
        response.raise_for_status()
        return response.json()


async def snapshot_section(
    http_client: httpx.AsyncClient,
    name: str,
    url: str,
    extractor,
    fallback: Any,
) -> tuple[Any, dict[str, str] | None]:
    try:
        response = await traced_get(http_client, url)
        response.raise_for_status()
        return extractor(response.json()), None
    except Exception as exc:
        logger.warning("Snapshot dependency unavailable", extra={"dependency": name, "error": str(exc)})
        return fallback, {"name": name, "message": str(exc)}


async def snapshot_payload() -> dict:
    async with httpx.AsyncClient(timeout=5.0) as http_client:
        snapshot_results = await asyncio.gather(
            snapshot_section(http_client, "scores", f"{DETECTOR_URL}/scores", lambda payload: payload.get("items", []), []),
            snapshot_section(http_client, "events", f"{DETECTOR_URL}/events", lambda payload: payload.get("items", []), []),
            snapshot_section(http_client, "decisions", f"{DECISION_URL}/decisions", lambda payload: payload.get("items", []), []),
            snapshot_section(http_client, "timeline", f"{RECOVERY_URL}/timeline", lambda payload: payload.get("items", []), []),
            snapshot_section(
                http_client,
                "slos",
                f"{TELEMETRY_URL}/slo/status",
                lambda payload: payload,
                {"overall_compliance": 100, "items": []},
            ),
            snapshot_section(http_client, "experiments", f"{CHAOS_URL}/experiments", lambda payload: payload.get("items", []), []),
        )
    unavailable = [issue for _, issue in snapshot_results if issue]
    try:
        workloads = list_workloads()
    except Exception as exc:
        logger.warning("Snapshot workload discovery unavailable", extra={"error": str(exc)})
        workloads = []
        unavailable.append({"name": "workloads", "message": str(exc)})
    return {
        "scores": snapshot_results[0][0],
        "events": snapshot_results[1][0],
        "decisions": snapshot_results[2][0],
        "timeline": snapshot_results[3][0],
        "slos": snapshot_results[4][0],
        "experiments": snapshot_results[5][0],
        "workloads": workloads,
        "unavailable": unavailable,
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


def role_for_api_key(api_key: str | None) -> str | None:
    if api_key and ADMIN_API_KEY and api_key == ADMIN_API_KEY:
        return "admin"
    if api_key and OPERATOR_API_KEY and api_key == OPERATOR_API_KEY:
        return "operator"
    return None


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    request.state.actor = "dashboard-user"
    request.state.role = None
    if suspicious_embedding_request(dict(request.headers), ALLOWED_EMBED_HOSTS):
        increment_security_metric("dashboard", "clickjack_attempt_count")
        record_request("dashboard", getattr(getattr(request, "client", None), "host", "unknown"), request.url.path, blocked=True)
    if not request.url.path.startswith("/api/") or request.url.path.startswith("/api/auth/"):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
    principal = authenticated_username(request)
    role = ROLE_ADMIN if principal else None
    if principal is None and request.method == "POST":
        principal, role = bearer_principal_and_role(request.headers.get("authorization"))
        if role is None:
            role = role_for_api_key(request.headers.get("x-api-key"))
            principal = request.headers.get("x-actor", f"api-key:{role or 'anonymous'}") if role else None
    if principal is None:
        raise HTTPException(status_code=401, detail="login_required")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not validate_csrf_token(request, principal):
        increment_security_metric("dashboard", "csrf_attempt_count")
        audit_event(
            "dashboard",
            "csrf-blocked",
            {"path": request.url.path, "actor": principal},
            severity="warning",
            status="blocked",
            target=request.url.path,
            classification="csrf_attack",
            actor=principal,
        )
        raise HTTPException(status_code=403, detail="invalid_csrf_token")
    request.state.actor = principal
    request.state.role = role or ROLE_ADMIN
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


def validate_credentials(username: str, password: str) -> tuple[str, str]:
    normalized_username = normalize_username(username)
    if len(normalized_username) < 3:
        raise HTTPException(status_code=400, detail="username_too_short")
    if len(password) < AUTH_MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"password_must_be_at_least_{AUTH_MIN_PASSWORD_LENGTH}_characters")
    return normalized_username, password

@app.get("/api/auth/session")
async def session(request: Request) -> dict:
    username = authenticated_username(request)
    if username is None:
        raise HTTPException(status_code=401, detail="login_required")
    token = csrf_token_value(username)
    return {"username": username, "csrf_token": token}


@app.post("/api/auth/signup")
async def signup(payload: dict[str, str], response: Response) -> dict:
    username, password = validate_credentials(payload.get("username", ""), payload.get("password", ""))
    try:
        with dashboard_db() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO dashboard_users(username, password_hash) VALUES (%s, %s)",
                    (username, password_hash(password)),
                )
    except Exception as exc:
        if "duplicate" in str(exc).lower():
            raise HTTPException(status_code=409, detail="username_already_exists")
        raise HTTPException(status_code=500, detail=str(exc))
    apply_session_cookies(response, username)
    return {"username": username, "csrf_token": csrf_token_value(username)}


@app.post("/api/auth/login")
async def login(payload: dict[str, str], response: Response) -> dict:
    username, password = validate_credentials(payload.get("username", ""), payload.get("password", ""))
    with dashboard_db() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT username, password_hash FROM dashboard_users WHERE username = %s", (username,))
            user = cursor.fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid_username_or_password")
    apply_session_cookies(response, username)
    return {"username": username, "csrf_token": csrf_token_value(username)}


@app.post("/api/auth/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(SESSION_COOKIE_NAME, samesite="strict")
    response.delete_cookie(CSRF_COOKIE_NAME, samesite="strict")
    return {"ok": True}


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
async def chaos(scenario: str, payload: dict, request: Request) -> dict:
    async with httpx.AsyncClient(timeout=8.0) as http_client:
        response = await traced_post(http_client, f"{CHAOS_URL}/scenarios/{scenario}", json=payload)
        response.raise_for_status()
        result = response.json()
    audit_event(
        "dashboard",
        "manual-chaos",
        {"scenario": scenario, "payload": payload, "result": result},
        severity="warning",
        status="completed",
        target=payload.get("target"),
        actor=getattr(request.state, "actor", "dashboard-user"),
    )
    return result


@app.post("/api/recover")
async def recover(payload: dict, request: Request) -> dict:
    async with httpx.AsyncClient(timeout=8.0) as http_client:
        response = await traced_post(http_client, f"{RECOVERY_URL}/recover", json=payload)
        response.raise_for_status()
        result = response.json()
    audit_event(
        "dashboard",
        "manual-recovery",
        {"payload": payload, "result": result},
        severity="warning",
        status="completed",
        target=payload.get("target"),
        classification=payload.get("reason"),
        actor=getattr(request.state, "actor", "dashboard-user"),
    )
    return result
