/**
 * Legal, Privacy, and Security Compliance Views
 * Renders truthful policies derived directly from project data practices.
 */

const LegalDocs = {
  privacy: {
    title: "Privacy Policy",
    effective: "2026-09-07",
    content: `
      <h3>1. Data Inventory & Telemetry Collected</h3>
      <p>This security system processes the following authentication and behavioral telemetry strictly to detect and prevent account hijacking:</p>
      <ul>
        <li><strong>Identity:</strong> Email address and salted cryptographic password hashes (PBKDF2-HMAC-SHA256). Raw passwords are never stored.</li>
        <li><strong>Geographic Data:</strong> Latitude, longitude, and country/city coordinates derived from network access to calculate geo-velocity anomalies.</li>
        <li><strong>Device Fingerprint:</strong> Browser engine, operating system, canvas render hash, screen resolution, and hardware concurrency to detect device spoofing.</li>
        <li><strong>Network Telemetry:</strong> IP addresses to evaluate proxy/Tor exit node reputations and enforce brute force rate limiting.</li>
      </ul>

      <h3>2. Purpose of Processing</h3>
      <p>Data is evaluated exclusively by automated Machine Learning (Isolation Forest & Random Forest) to classify authentication sessions as normal, suspicious, or unauthorized hijacking attempts.</p>

      <h3>3. Retention & Deletion</h3>
      <p>Active session records expire automatically within 24 hours. Users have the absolute right to delete their account and all associated telemetry at any time via the Account Settings portal.</p>
    `
  },
  terms: {
    title: "Terms of Service",
    effective: "2026-09-07",
    content: `
      <h3>1. Authorized Usage</h3>
      <p>This application is provided for authorized account authentication, real-time security alerting, and legitimate defensive cybersecurity research.</p>

      <h3>2. Attack Simulator Safeguards</h3>
      <p>The Red Team Attack Simulator operates within a strictly sandboxed, non-destructive environment. Users must only simulate access patterns against accounts they own or are explicitly authorized to test.</p>

      <h3>3. Automated Mitigation</h3>
      <p>You acknowledge that when an authentication attempt scores above the critical threat threshold (> 70/100), the system will automatically terminate the session and freeze access to safeguard account integrity.</p>
    `
  },
  cookies: {
    title: "Cookie & Local Storage Policy",
    effective: "2026-09-07",
    content: `
      <h3>1. Essential Storage Only</h3>
      <p>This website uses modern browser <code>localStorage</code> solely for essential security functions:</p>
      <ul>
        <li><code>cyber_token</code>: Cryptographically random Bearer token used to authenticate active sessions.</li>
      </ul>
      <h3>2. Zero Third-Party Advertising</h3>
      <p>We do not use advertising trackers, marketing pixels, or third-party behavioral cookies.</p>
    `
  },
  security: {
    title: "Security Architecture & Policy",
    effective: "2026-09-07",
    content: `
      <h3>Defense-in-Depth Implementation</h3>
      <ul>
        <li><strong>Password Hashing:</strong> Industry-standard PBKDF2-HMAC-SHA256 with 200,000 iterations and unique 16-byte cryptographic salts.</li>
        <li><strong>Anti-Enumeration:</strong> Generic error messages on authentication failures ("Invalid credentials or account restricted") preventing user enumeration.</li>
        <li><strong>Brute Force Throttling:</strong> Sliding-window rate limiter blocking abusive IP addresses and usernames after 5 failed attempts.</li>
        <li><strong>Input Sanitization:</strong> Strict Pydantic schema validation and recursive sanitization defending against XSS and NoSQL injection attacks.</li>
        <li><strong>Serverless Isolation:</strong> Cloud execution isolated within AWS Lambda environments with least-privilege IAM roles.</li>
      </ul>
    `
  },
  disclaimer: {
    title: "Defensive Testing Disclaimer",
    effective: "2026-09-07",
    content: `
      <h3>Controlled Cyber Simulation</h3>
      <p>The attack simulation capabilities provided in this platform (Credential Stuffing, Impossible Travel, Device Spoofing) are designed solely for educational demonstration and security defensive validation.</p>
      <p>Any attempt to repurpose these tools against third-party systems without written authorization is strictly prohibited.</p>
    `
  },
  accessibility: {
    title: "Accessibility Statement",
    effective: "2026-09-07",
    content: `
      <h3>Commitment to Accessibility</h3>
      <p>We are dedicated to ensuring our cybersecurity interface is accessible to everyone. Our design system adheres to WCAG 2.1 Level AA targets:</p>
      <ul>
        <li>High contrast visual indicators for threat severities (Green, Amber, Crimson).</li>
        <li>Full keyboard accessibility with visible focus rings across all interactive buttons and modals.</li>
        <li>Screen-reader friendly ARIA landmarks and live alert regions (<code>role="status"</code>).</li>
        <li>Reduced motion support respecting system accessibility preferences.</li>
      </ul>
    `
  },
  acceptable_use: {
    title: "Acceptable Use Policy",
    effective: "2026-09-07",
    content: `
      <h3>Prohibited Conduct</h3>
      <p>Users of this platform must not:</p>
      <ul>
        <li>Launch automated denial of service (DoS) attacks against the API Gateway endpoints.</li>
        <li>Bypass authentication boundaries or tamper with session tokens.</li>
        <li>Extract or scrape telemetry belonging to other accounts.</li>
      </ul>
    `
  },
  disclosure: {
    title: "Responsible Vulnerability Disclosure",
    effective: "2026-09-07",
    content: `
      <h3>Reporting Vulnerabilities</h3>
      <p>If you identify a security flaw or vulnerability in our authentication, ML risk engine, or serverless infrastructure, we welcome your responsible report.</p>
      <p>Please contact our team at <code>security-disclosure@rootnode-rebels.local</code> with a proof-of-concept description. We commit to reviewing reports within 48 hours under Safe Harbor provisions.</p>
    `
  }
};

function showLegalDoc(key) {
  const doc = LegalDocs[key];
  if (!doc) return;

  const titleEl = document.getElementById("legal-modal-title");
  const bodyEl = document.getElementById("legal-modal-body");
  const effEl = document.getElementById("legal-modal-effective");

  if (titleEl) titleEl.textContent = doc.title;
  if (bodyEl) bodyEl.innerHTML = doc.content;
  if (effEl) effEl.textContent = `Effective Date: ${doc.effective}`;

  openModal("modal-legal-doc");
}
