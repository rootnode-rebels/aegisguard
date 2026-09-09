/**
 * Global App State, Router, Offline Listener, and API Client
 */

const AppState = {
  token: localStorage.getItem("cyber_token") || null,
  user: null,
  currentTab: "user-portal",
  isOffline: false,
  fingerprint: null,
  geo: null
};

// Real-Time Sound & Synthesizer State
let soundEnabled = true;
let audioCtx = null;

function toggleSoundAlerts() {
  soundEnabled = !soundEnabled;
  const label = document.getElementById("sound-toggle-label");
  const btn = document.getElementById("btn-sound-toggle");
  if (label) label.textContent = soundEnabled ? "🔊 Sound: ON" : "🔇 Sound: OFF";
  if (btn) {
    btn.classList.toggle("btn-primary", soundEnabled);
    btn.classList.toggle("btn-secondary", !soundEnabled);
  }
  showToast(`Security Sound Sirens ${soundEnabled ? 'Enabled' : 'Muted'}`, "info");
}

function playSecurityAlertSound() {
  if (!soundEnabled) return;
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    if (!audioCtx) audioCtx = new AudioContext();
    if (audioCtx.state === "suspended") {
      audioCtx.resume();
    }
    const now = audioCtx.currentTime;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(880, now); // A5 siren
    osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);
    osc.frequency.exponentialRampToValueAtTime(880, now + 0.3);
    osc.frequency.exponentialRampToValueAtTime(440, now + 0.45);

    gain.gain.setValueAtTime(0.2, now);
    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.5);

    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(now);
    osc.stop(now + 0.5);
  } catch (e) {
    console.log("Audio synthesis notice:", e);
  }
}

// Global Alert Banner Controller
function showSecurityAlertBanner(alert) {
  const banner = document.getElementById("emergency-alert-banner");
  const title = document.getElementById("banner-alert-title");
  const desc = document.getElementById("banner-alert-desc");
  if (!banner) return;

  const isFailedPassword = alert.type === "SUSPICIOUS_FAILED_LOGIN" || alert.type === "REPEATED_FAILED_LOGINS" || alert.type === "BRUTE_FORCE_LOCKOUT";

  if (title) {
    title.textContent = isFailedPassword 
      ? "⚠️ SECURITY WARNING: INCORRECT PASSWORD ATTEMPT DETECTED" 
      : "🚨 SECURITY ALERT: SUSPICIOUS SIGN-IN BLOCKED";
  }
  if (desc) {
    const reason = alert.reason || "Someone tried to sign into your account with an incorrect password.";
    const origin = alert.origin || "Unknown Location";
    const ip = alert.ip || "Unknown IP";
    const dev = alert.device || "Unknown Device";
    desc.innerHTML = `<strong>${reason}</strong> &bull; Device: <span style="color: #fff;">${dev}</span> &bull; Location: <span style="color: #fff;">${origin}</span> (<code>${ip}</code>). Access was blocked.`;
  }

  banner.style.display = "block";
  playSecurityAlertSound();
}

function dismissAlertBanner() {
  const banner = document.getElementById("emergency-alert-banner");
  if (banner) banner.style.display = "none";
}

// Practice Guide Section Switcher
function switchPracticeGuideSection(secId) {
  const sections = ["demo", "buttons", "ml", "aws", "viva"];
  sections.forEach(s => {
    const secEl = document.getElementById(`pg-sec-${s}`);
    const btnEl = document.getElementById(`pg-tab-btn-${s}`);
    if (secEl) secEl.style.display = (s === secId) ? "block" : "none";
    if (btnEl) btnEl.classList.toggle("active", s === secId);
  });
}

// Global API Helper with Correlation ID
async function apiFetch(endpoint, options = {}) {
  const correlationId = "req_" + Math.random().toString(36).substring(2, 10);
  const headers = {
    "Content-Type": "application/json",
    "X-Request-Id": correlationId,
    ...(options.headers || {})
  };

  if (AppState.token) {
    headers["Authorization"] = `Bearer ${AppState.token}`;
  }

  try {
    const res = await fetch(endpoint, { ...options, headers });
    
    // Handle 503 Maintenance
    if (res.status === 503) {
      openModal("modal-maintenance");
      throw new Error("System under maintenance");
    }

    // Handle 401 Session Expired / Revoked
    if (res.status === 401 && AppState.token) {
      handleSessionExpired();
      throw new Error("Session expired");
    }

    // Handle 403 Access Blocked / Account Locked
    if (res.status === 403) {
      const data = await res.json().catch(() => ({}));
      const errCode = data.detail?.error || (typeof data.detail === "object" ? data.detail?.error : null);
      if (errCode === "ACCOUNT_LOCKED") {
        AppState.token = null;
        AppState.user = null;
        localStorage.removeItem("cyber_token");
        openModal("modal-account-locked");
        if (typeof renderUserPortal === "function") renderUserPortal();
      } else {
        showToast(data.detail?.message || (typeof data.detail === "string" ? data.detail : "Access blocked by security policy"), "error");
      }
      return { ok: false, status: 403, data };
    }

    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    if (!navigator.onLine) {
      showToast("Network connection lost. You are currently offline.", "error");
    }
    return { ok: false, status: 0, error: err.message };
  }
}

// Router & Tab Switching
function switchTab(tabId) {
  AppState.currentTab = tabId;
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-view").forEach(view => {
    view.classList.toggle("active", view.id === tabId);
  });

  // Trigger sub-view initializations
  if (tabId === "attack-studio" && typeof initAttackSimulator === "function") {
    initAttackSimulator();
  } else if (tabId === "soc-dashboard" && typeof initSocDashboard === "function") {
    initSocDashboard();
  } else if (tabId === "cloudwatch-view" && typeof initCloudWatchView === "function") {
    initCloudWatchView();
  }
}

// Toast Notifications
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.setAttribute("role", "status");
  toast.innerHTML = `
    <span class="toast-icon">${type === "success" ? "✓" : type === "error" ? "⚠" : "ℹ"}</span>
    <span>${message}</span>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Modal Controls
function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.add("active");
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.remove("active");
}

function handleSessionExpired() {
  AppState.token = null;
  AppState.user = null;
  localStorage.removeItem("cyber_token");
  openModal("modal-session-expired");
  renderUserPortal();
}

// Offline State Detector
window.addEventListener("online", () => {
  AppState.isOffline = false;
  document.getElementById("offline-banner").style.display = "none";
  showToast("Network connection restored.", "success");
});

window.addEventListener("offline", () => {
  fetch("/api/cloudwatch/metrics").then(() => {
    AppState.isOffline = false;
    const banner = document.getElementById("offline-banner");
    if (banner) banner.style.display = "none";
  }).catch(() => {
    AppState.isOffline = true;
    const banner = document.getElementById("offline-banner");
    if (banner) banner.style.display = "block";
    showToast("You are currently offline. Actions may fail.", "warning");
  });
});

// Quick Interactive Demo Helpers (Anyone can test in 1-click)
async function demoSimulateFailedLogin() {
  showToast("Simulating remote attacker guessing wrong password in Edge...", "info");
  await apiFetch("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: (AppState.user?.email || "demo@awssecurity.io"),
      password: "WrongPassword123!",
      geo: { lat: 40.7128, lon: -74.0060, city: "New York", country: "US" },
      fingerprint: {
        browser: "Microsoft Edge",
        browser_id: "bid_remote_edge_attacker",
        os: "Windows NT 10.0",
        screen_resolution: "1920x1080",
        canvas_hash: "canvas_diff_edge_demo"
      }
    })
  });
  if (typeof loadUserAlerts === "function") {
    setTimeout(() => loadUserAlerts(true), 400);
  }
}

async function demoSimulateTokyoAttack() {
  showToast("Launching Tokyo Impossible Travel Scenario (8,500 km/h flight speed)...", "warning");
  const res = await apiFetch("/api/security/simulate-scenario", {
    method: "POST",
    body: JSON.stringify({
      scenario_id: "impossible_travel",
      target_email: (AppState.user?.email || "demo@awssecurity.io")
    })
  });
  if (res.ok) {
    showToast(`🚨 Tokyo Scenario Blocked! Risk Score: ${res.data?.risk_score}/100. Siren active.`, "error");
    if (typeof loadUserAlerts === "function") {
      setTimeout(() => loadUserAlerts(true), 400);
    }
  }
}

// Password Visibility Toggle
function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
    btn.title = "Hide password";
  } else {
    input.type = "password";
    btn.textContent = "👁️";
    btn.title = "Show password";
  }
}
window.togglePasswordVisibility = togglePasswordVisibility;

// App Initialization
document.addEventListener("DOMContentLoaded", async () => {
  // Extract fingerprint and geolocation
  if (typeof generateBrowserFingerprint === "function") {
    AppState.fingerprint = await generateBrowserFingerprint();
    const fpBadge = document.getElementById("client-fp-display");
    if (fpBadge) fpBadge.textContent = `${AppState.fingerprint.os} • ${AppState.fingerprint.screen_resolution}`;
  }
  if (typeof getClientGeolocation === "function") {
    AppState.geo = await getClientGeolocation();
  }

  // Navigation clicks
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Check login state
  if (AppState.token && typeof checkCurrentUser === "function") {
    await checkCurrentUser();
  } else if (typeof renderUserPortal === "function") {
    renderUserPortal();
  }

  // Check maintenance status
  const sysRes = await apiFetch("/api/system/status");
  if (sysRes.ok && sysRes.data?.maintenance_mode) {
    openModal("modal-maintenance");
  }
});
