/**
 * Blue Team SOC (Security Operations Center) Dashboard Controller
 * Manages Animated SVG Risk Gauge, Geo-Velocity Visualizer, Real-Time Event Stream, and Defense Controls.
 */

let socPollingInterval = null;
let currentInspectedEvent = null;
let isFetchingSoc = false;
let lastSocEventsSignature = "";

function initSocDashboard() {
  loadSocMetrics();
  loadSecurityEvents(true);
  initGeoFlightCanvas();

  if (!socPollingInterval) {
    socPollingInterval = setInterval(() => {
      if (document.hidden) return;
      if (AppState.currentTab === "soc-dashboard") {
        loadSocMetrics();
        loadSecurityEvents();
      }
    }, 2500);
  }
}

async function loadSocMetrics() {
  const res = await apiFetch("/api/security/stats");
  if (res.ok && res.data) {
    const stats = res.data;
    
    // Update metric counters
    const totEl = document.getElementById("soc-total-events");
    const blkEl = document.getElementById("soc-blocked-events");
    const mfaEl = document.getElementById("soc-mfa-events");
    const nrmEl = document.getElementById("soc-normal-events");

    if (totEl) totEl.textContent = stats.total_analyzed;
    if (blkEl) blkEl.textContent = stats.blocked_hijacks;
    if (mfaEl) mfaEl.textContent = stats.mfa_challenges;
    if (nrmEl) nrmEl.textContent = stats.normal_allowed;

    // Update SVG Risk Gauge
    updateRiskGauge(stats.avg_risk_score || 0);
  }
}

function updateRiskGauge(score) {
  const needle = document.getElementById("gauge-needle");
  const valueDisplay = document.getElementById("gauge-value-number");
  const statusDisplay = document.getElementById("gauge-status-text");

  if (!needle || !valueDisplay || !statusDisplay) return;

  // Rotation: 0 score = -90deg, 100 score = +90deg
  const angle = -90 + (score / 100.0) * 180;
  needle.style.transform = `rotate(${angle}deg)`;
  valueDisplay.textContent = score.toFixed(1);

  if (score < 40) {
    valueDisplay.style.color = "var(--accent-emerald)";
    statusDisplay.textContent = "LOW RISK • NORMAL BEHAVIOR";
    statusDisplay.style.color = "var(--accent-emerald)";
  } else if (score < 70) {
    valueDisplay.style.color = "var(--accent-amber)";
    statusDisplay.textContent = "ELEVATED RISK • MFA ENFORCED";
    statusDisplay.style.color = "var(--accent-amber)";
  } else {
    valueDisplay.style.color = "var(--accent-crimson)";
    statusDisplay.textContent = "CRITICAL THREAT • SESSIONS BLOCKED";
    statusDisplay.style.color = "var(--accent-crimson)";
  }
}

async function loadSecurityEvents(force = false) {
  const tbody = document.getElementById("soc-events-tbody");
  if (!tbody || isFetchingSoc) return;

  isFetchingSoc = true;
  try {
    const res = await apiFetch("/api/security/events?limit=25");
    if (res.ok && res.data?.events) {
      const events = res.data.events;
      const signature = JSON.stringify(events.map(e => [e.event_id, e.risk_score]));
      if (!force && signature === lastSocEventsSignature) {
        return;
      }
      lastSocEventsSignature = signature;

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state-box"><div>No security events recorded yet. Run a simulation to see live detection.</div></td></tr>`;
        return;
      }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-dim);">
          ${new Date(e.timestamp).toLocaleTimeString()}
        </td>
        <td>
          <div style="font-weight: 600;">${e.user_email}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${e.ip_address}</div>
        </td>
        <td>${e.geo?.city || 'Unknown'}, ${e.geo?.country || 'US'}</td>
        <td>
          <span class="badge ${e.risk_score >= 70 ? 'badge-high' : e.risk_score >= 40 ? 'badge-medium' : 'badge-low'}">
            ${e.risk_score}/100
          </span>
        </td>
        <td>
          <span style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: ${e.action_taken === 'BLOCK_SESSION' ? 'var(--accent-crimson)' : e.action_taken === 'STEP_UP_MFA' ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
            ${e.action_taken}
          </span>
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="inspectEvent('${e.event_id}')">
            Inspect
          </button>
        </td>
      </tr>
    `).join("");

    // Update flight visualizer with latest event
    if (events[0]) {
      drawFlightVisualizer(events[0]);
    }
  }
} finally {
  isFetchingSoc = false;
}
}

async function inspectEvent(eventId) {
  const res = await apiFetch("/api/security/events?limit=50");
  if (res.ok && res.data?.events) {
    const event = res.data.events.find(e => e.event_id === eventId);
    if (!event) return;

    currentInspectedEvent = event;
    const body = document.getElementById("modal-event-inspect-body");
    if (body) {
      body.innerHTML = `
        <div style="margin-bottom: 1rem;">
          <span class="badge ${event.risk_score >= 70 ? 'badge-high' : event.risk_score >= 40 ? 'badge-medium' : 'badge-low'}">
            Risk Score: ${event.risk_score}/100 • ${event.risk_level}
          </span>
          <h3 style="margin-top: 0.5rem; color: #fff;">${event.action_taken}</h3>
          <p style="font-size: 0.85rem; color: var(--text-muted);">Event ID: <code>${event.event_id}</code> • User: ${event.user_email}</p>
        </div>

        <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.4rem;">Explainable AI Factor Attribution:</h4>
        <div style="margin-bottom: 1rem;">
          ${(event.factors || []).map(f => `
            <div style="background: rgba(255,255,255,0.04); padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.4rem; border-left: 3px solid ${f.severity === 'CRITICAL' ? 'var(--accent-crimson)' : 'var(--accent-amber)'};">
              <div style="display: flex; justify-content: space-between; font-size: 0.85rem; font-weight: 600;">
                <span>${f.factor}</span>
                <span style="color: var(--accent-amber);">+${f.weight} pts</span>
              </div>
              <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.2rem;">${f.detail}</div>
            </div>
          `).join("") || "<div style='color: var(--text-dim);'>No anomalous factors detected. Normal baseline.</div>"}
        </div>

        <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.4rem;">Deep Autoencoder Reconstruction:</h4>
        <div style="font-family: var(--font-mono); font-size: 0.8rem; background: #050811; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; color: #6ee7b7;">
          MSE Reconstruction Error: ${event.autoencoder_loss || 0.0012} (Anomaly threshold: 0.12)
        </div>

        <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.4rem;">Raw Telemetry Payload:</h4>
        <pre style="background: #050811; padding: 0.75rem; border-radius: 6px; font-size: 0.75rem; color: #94a3b8; overflow-x: auto;">${JSON.stringify(event, null, 2)}</pre>
      `;
    }
    openModal("modal-event-inspect");
  }
}

// Interactive Geo-Velocity Canvas Visualizer
function initGeoFlightCanvas() {
  const canvas = document.getElementById("geo-flight-canvas");
  if (!canvas) return;
  canvas.width = canvas.parentElement.clientWidth || 600;
  canvas.height = 200;
  drawFlightVisualizer({ geo: { city: "Tokyo", country: "Japan" }, risk_score: 88 });
}

function drawFlightVisualizer(event) {
  const canvas = document.getElementById("geo-flight-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;

  // Clear
  ctx.clearRect(0, 0, w, h);

  // Background grid
  ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 40) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += 40) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  // Baseline Point (New York)
  const p1 = { x: w * 0.25, y: h * 0.65, label: "New York (Baseline)" };
  // Target Point
  const isAnom = (event.risk_score || 0) >= 70;
  const p2 = { x: w * 0.75, y: h * 0.35, label: `${event.geo?.city || 'Tokyo'} (${isAnom ? 'Impossible Flight' : 'Normal'})` };

  // Draw Arc
  ctx.beginPath();
  ctx.moveTo(p1.x, p1.y);
  ctx.quadraticCurveTo((p1.x + p2.x) / 2, h * 0.05, p2.x, p2.y);
  ctx.strokeStyle = isAnom ? "#ef4444" : "#10b981";
  ctx.lineWidth = 3;
  ctx.setLineDash([6, 4]);
  ctx.stroke();
  ctx.setLineDash([]);

  // Draw glowing beacons
  [p1, p2].forEach((p, idx) => {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 6, 0, Math.PI * 2);
    ctx.fillStyle = idx === 0 ? "#10b981" : isAnom ? "#ef4444" : "#3b82f6";
    ctx.fill();
    ctx.shadowBlur = 10;
    ctx.shadowColor = ctx.fillStyle;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Label
    ctx.fillStyle = "#fff";
    ctx.font = "11px monospace";
    ctx.fillText(p.label, p.x - 40, p.y + 18);
  });

  // Flight Stats Banner
  ctx.fillStyle = isAnom ? "#ef4444" : "#10b981";
  ctx.font = "bold 12px monospace";
  ctx.fillText(isAnom ? "⚡ IMPOSSIBLE TRAVEL VELOCITY: > 8,500 KM/H" : "✓ COMMUTING VELOCITY: < 50 KM/H", w * 0.28, 25);
}
