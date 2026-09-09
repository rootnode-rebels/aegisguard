/**
 * Client-Side Hardware & Browser Fingerprinting Engine.
 * Extracts canvas hashes, hardware concurrency, screen resolution, and platform attributes.
 */

function detectBrowser() {
  const ua = navigator.userAgent;
  if (ua.indexOf("Edg") !== -1) return "Microsoft Edge";
  if (ua.indexOf("Firefox") !== -1) return "Mozilla Firefox";
  if (ua.indexOf("OPR") !== -1 || ua.indexOf("Opera") !== -1) return "Opera";
  if (ua.indexOf("Chrome") !== -1) return "Google Chrome";
  if (ua.indexOf("Safari") !== -1) return "Apple Safari";
  return "Web Browser";
}

function getBrowserProfileId() {
  let id = localStorage.getItem("cyber_browser_id");
  if (!id) {
    id = "bid_" + Math.random().toString(36).substring(2, 11) + "_" + Date.now().toString(36);
    try { localStorage.setItem("cyber_browser_id", id); } catch(e) {}
  }
  return id;
}

async function generateBrowserFingerprint() {
  const fp = {
    os: detectOS(),
    browser: detectBrowser(),
    browser_id: getBrowserProfileId(),
    platform: navigator.platform || "Unknown",
    screen_resolution: `${window.screen.width}x${window.screen.height}`,
    color_depth: window.screen.colorDepth || 24,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    language: navigator.language || "en-US",
    hardware_concurrency: navigator.hardwareConcurrency || 4,
    canvas_hash: await generateCanvasHash()
  };
  return fp;
}

function detectOS() {
  const ua = navigator.userAgent;
  if (ua.indexOf("Win") !== -1) return "Windows NT 10.0";
  if (ua.indexOf("Mac") !== -1) return "macOS";
  if (ua.indexOf("Linux") !== -1) return "Linux x86_64";
  if (ua.indexOf("Android") !== -1) return "Android";
  if (ua.indexOf("like Mac") !== -1) return "iOS";
  return "Unknown OS";
}

async function generateCanvasHash() {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "fallback_canvas_hash";

    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("RootNode-Rebels-CyberSec-2026", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("RootNode-Rebels-CyberSec-2026", 4, 17);

    const dataUrl = canvas.toDataURL();
    // Compute simple DJB2 hash
    let hash = 5381;
    for (let i = 0; i < dataUrl.length; i++) {
      hash = ((hash << 5) + hash) + dataUrl.charCodeAt(i);
      hash = hash & hash;
    }
    return "canvas_" + Math.abs(hash).toString(16);
  } catch (e) {
    return "canvas_err_default";
  }
}

async function getClientGeolocation() {
  return new Promise((resolve) => {
    if ("geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          resolve({
            lat: Number(pos.coords.latitude.toFixed(4)),
            lon: Number(pos.coords.longitude.toFixed(4)),
            city: "Current Location",
            country: "User Region"
          });
        },
        () => {
          // Default fallback (New York, US)
          resolve({ lat: 40.7128, lon: -74.0060, city: "New York", country: "US" });
        },
        { timeout: 3000 }
      );
    } else {
      resolve({ lat: 40.7128, lon: -74.0060, city: "New York", country: "US" });
    }
  });
}
