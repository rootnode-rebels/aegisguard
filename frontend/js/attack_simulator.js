/**
 * Red Team Cyber Attack Simulator Studio
 * Controls safe, controlled simulations of account hijacking vectors.
 */

function initAttackSimulator() {
  const targetEmailInput = document.getElementById("sim-target-email");
  if (targetEmailInput && AppState.user) {
    targetEmailInput.value = AppState.user.email;
  }
}

async function runScenario(attackType) {
  const targetEmailInput = document.getElementById("sim-target-email");
  const targetEmail = targetEmailInput ? targetEmailInput.value.trim() : (AppState.user?.email || "target_user@example.com");

  if (!targetEmail) {
    showToast("Please enter a target account email for the simulation.", "warning");
    return;
  }

  logTerminal(`[RED TEAM] Initiating simulated ${attackType} vector against ${targetEmail}...`, "info");

  let payload = {
    target_email: targetEmail,
    attack_type: attackType
  };

  if (attackType === "CUSTOM") {
    payload.speed_kmh = parseFloat(document.getElementById("custom-speed-slider")?.value || 1200);
    payload.custom_ip = document.getElementById("custom-ip-input")?.value || "198.51.100.1";
  }

  const res = await apiFetch("/api/security/simulate-attack", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  if (res.ok) {
    const d = res.data;
    logTerminal(`[RED TEAM] Payload delivered. HTTP Status: 200 OK`, "info");
    logTerminal(`[DEFENSE RESPONSE] ML Risk Score: ${d.risk_score}/100 (${d.risk_level})`, d.risk_score >= 70 ? "err" : "warn");
    logTerminal(`[POLICY ENFORCEMENT] Action Taken: ${d.action_taken}`, d.action_taken === "BLOCK_SESSION" ? "err" : "warn");
    logTerminal(`[DEEP AUTOENCODER] Reconstruction Loss: ${d.autoencoder?.mse_reconstruction_error} (Threshold: 0.12)`, "info");

    if (d.explainable_factors && d.explainable_factors.length > 0) {
      logTerminal(`[XAI REASONS] ${d.explainable_factors.map(f => f.factor).join(" | ")}`, "warn");
    }

    if (d.action_taken === "BLOCK_SESSION") {
      logTerminal(`[ALERT SYSTEM] 🚨 Legitimate user alerted & session terminated immediately!`, "err");
      showToast(`Simulated Attack Blocked! Risk Score: ${d.risk_score}/100`, "error");
    } else if (d.action_taken === "STEP_UP_MFA") {
      logTerminal(`[ALERT SYSTEM] ⚠️ Step-up MFA challenge enforced for session.`, "warn");
      showToast(`Attack Flagged: Step-Up MFA Challenge Enforced`, "warning");
    } else {
      showToast(`Attack completed (Low Risk Score: ${d.risk_score})`, "info");
    }

    // Refresh active user alerts if target is current user
    if (AppState.user && AppState.user.email === targetEmail) {
      if (typeof loadUserAlerts === "function") loadUserAlerts();
    }
  } else {
    logTerminal(`[SIMULATION ERROR] Request rejected: ${res.data?.detail || res.error}`, "err");
  }
}

function logTerminal(message, type = "info") {
  const terminal = document.getElementById("sim-terminal-output");
  if (!terminal) return;

  const timeStr = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.className = `telemetry-line ${type}`;
  terminal.appendChild(line);
  
  const fullText = `[${timeStr}] ${message}`;
  let i = 0;
  
  function typeWriter() {
    if (i < fullText.length) {
      line.textContent += fullText.charAt(i);
      i++;
      terminal.scrollTop = terminal.scrollHeight;
      setTimeout(typeWriter, 10);
    }
  }
  
  typeWriter();
}

function clearTerminal() {
  const terminal = document.getElementById("sim-terminal-output");
  if (terminal) terminal.innerHTML = `<div class="telemetry-line info">[CONSOLE READY] Awaiting cyber attack simulation command...</div>`;
}
