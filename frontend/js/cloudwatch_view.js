/**
 * AWS CloudWatch Live Telemetry & Monitoring Panel Controller
 * Displays CloudWatch Metrics, Metric Alarms, and Log Streams.
 */

let cloudwatchPollInterval = null;
let allCloudWatchLogs = [];
let isFetchingCw = false;

function initCloudWatchView() {
  loadCloudWatchTelemetry();

  if (!cloudwatchPollInterval) {
    cloudwatchPollInterval = setInterval(() => {
      if (document.hidden) return;
      if (AppState.currentTab === "cloudwatch-view") {
        loadCloudWatchTelemetry();
      }
    }, 2500);
  }
}

async function loadCloudWatchTelemetry() {
  if (isFetchingCw) return;
  isFetchingCw = true;
  try {
    const res = await apiFetch("/api/monitoring/cloudwatch");
  if (res.ok && res.data) {
    const data = res.data;

    // Metrics Cards
    const m = data.metrics || {};
    setMetricText("cw-invocations", m.Invocations || 0);
    setMetricText("cw-high-risk", m.HighRiskDetections || 0);
    setMetricText("cw-blocked", m.BlockedHijacks || 0);
    setMetricText("cw-mfa", m.StepUpMFAChallenges || 0);
    setMetricText("cw-latency", (m.AvgExecutionLatencyMs || 0) + " ms");
    setMetricText("cw-avg-score", (m.AvgRiskScore || 0) + "/100");

    // Alarms Board
    const alarmsContainer = document.getElementById("cw-alarms-container");
    if (alarmsContainer && data.alarms) {
      alarmsContainer.innerHTML = data.alarms.map(a => `
        <div class="cyber-card" style="border-left: 4px solid ${a.state === 'ALARM' ? 'var(--accent-crimson)' : 'var(--accent-emerald)'}; margin-bottom: 0.75rem; padding: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
            <div style="font-weight: 700; color: #fff; font-family: var(--font-mono); font-size: 0.9rem;">
              ${a.name}
            </div>
            <span class="badge ${a.state === 'ALARM' ? 'badge-critical' : 'badge-low'}">
              ${a.state}
            </span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.3rem;">
            ${a.reason}
          </div>
          <div style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">
            Threshold: >= ${a.threshold} in ${a.period_minutes} min • Metric: ${a.metric}
          </div>
        </div>
      `).join("");
    }

    // Logs Stream
    if (data.recent_logs) {
      allCloudWatchLogs = data.recent_logs;
      filterCloudWatchLogs();
    }
  }
} finally {
  isFetchingCw = false;
}
}

function setMetricText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function filterCloudWatchLogs() {
  const tbody = document.getElementById("cw-logs-tbody");
  const query = (document.getElementById("cw-log-search")?.value || "").toLowerCase();
  const levelFilter = document.getElementById("cw-log-level-filter")?.value || "ALL";

  if (!tbody) return;

  const filtered = allCloudWatchLogs.filter(log => {
    const matchQuery = !query || 
      log.message.toLowerCase().includes(query) || 
      log.log_group.toLowerCase().includes(query) || 
      JSON.stringify(log.payload || {}).toLowerCase().includes(query);
    const matchLevel = levelFilter === "ALL" || log.level === levelFilter;
    return matchQuery && matchLevel;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state-box"><div>No CloudWatch log entries matched your filter.</div></td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(log => `
    <tr>
      <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim); white-space: nowrap;">
        ${new Date(log.timestamp).toLocaleTimeString()}
      </td>
      <td>
        <span class="badge ${log.level === 'WARN' ? 'badge-medium' : log.level === 'ERROR' ? 'badge-high' : 'badge-low'}" style="font-size: 0.7rem;">
          ${log.level}
        </span>
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">
        ${log.log_group}
      </td>
      <td style="font-size: 0.85rem; color: var(--text-main);">
        ${log.message}
        ${log.payload && Object.keys(log.payload).length > 0 ? `<div style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono); margin-top: 0.2rem;">${JSON.stringify(log.payload)}</div>` : ''}
      </td>
    </tr>
  `).join("");
}
