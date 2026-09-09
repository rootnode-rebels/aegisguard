# 🛡️ AWSSecurity AI — Practice, Live Demo & Viva Defense Guide

> **System Title:** Real-Time Account Hijacking Detection and Prevention System  
> **Architecture:** AWS Serverless & Cloud-Native Event-Driven Architecture  
> **Machine Learning Engine:** Scikit-Learn (Random Forest & Isolation Forest) + TensorFlow (Deep Neural Autoencoder)  
> **Runtime Environment:** Python 3.14 (FastAPI REST API Gateway) & Vanilla JS Cyberpunk UI  

---

## 📑 Table of Contents
1. [Project Overview & Core Aim](#1-project-overview--core-aim)
2. [Quick-Start: Running the Project Locally](#2-quick-start-running-the-project-locally)
3. [Two-Browser Localhost Live Demonstration Script](#3-two-browser-localhost-live-demonstration-script)
4. [Exhaustive Button-by-Button Frontend Working Catalog](#4-exhaustive-button-by-button-frontend-working-catalog)
5. [Machine Learning Algorithms, Formulas & Scoring Rules](#5-machine-learning-algorithms-formulas--scoring-rules)
6. [AWS Serverless Cloud Infrastructure Mapping](#6-aws-serverless-cloud-infrastructure-mapping)
7. [Viva & Project Defense Questions & Answers](#7-viva--project-defense-questions--answers)

---

## 1. Project Overview & Core Aim

Traditional web security relies almost entirely on **static perimeter authentication**—if a client provides the correct username and password, access is granted. However, in modern cyber threats, attackers obtain valid user credentials through:
* Phishing campaigns
* Third-party data breaches (credential stuffing)
* Malware / Infostealers (session token and password theft)
* Brute-force password guessing

**AWSSecurity AI** solves this problem by implementing **Continuous Behavioral Authentication**:
1. It monitors incoming authentication telemetry (geographic location, travel velocity, browser hardware canvas fingerprint, IP reputation, failed bursts, and circadian access hours).
2. It processes these features through a hybrid **Machine Learning Risk Engine** (Random Forest + Isolation Forest + Deep Autoencoder MSE loss).
3. If an attacker uses stolen credentials from an anomalous location or device, the system **automatically terminates/blocks the session**, records an immutable security audit event, updates Amazon CloudWatch SIEM telemetry, and sounds an **immediate real-time alert** on the legitimate user's device.

---

## 2. Quick-Start: Running the Project Locally

Open PowerShell or Command Prompt in the repository root (`d:\projects\aegisguard-main`):

```bash
# 1. Run automated verification test suite
python -m unittest tests/test_backend.py

# 2. Launch the standalone application (Zero external AWS or MongoDB config needed)
python run_standalone.py
```

The server will start on: **`http://127.0.0.1:8000`**

---

## 3. Two-Browser Localhost Live Demonstration Script

To convincingly demonstrate real-time account hijacking detection and prevention on a single computer, open **two different browser windows side-by-side**:
* **Browser 1 (Left Screen): Google Chrome** &rarr; *Legitimate User Persona (Sachin)*
* **Browser 2 (Right Screen): Microsoft Edge / Chrome Incognito** &rarr; *Red Team Cyber Attacker Persona*

```
+------------------------------------+------------------------------------+
|   BROWSER 1: CHROME (LEGIT USER)   |   BROWSER 2: EDGE (ATTACKER)       |
|   Account: demo@awssecurity.io      |   Using Stolen Master Credentials  |
|   Location: New York (Baseline)    |   Location: Tokyo (Impossible)     |
|   Status: Logged In & Monitoring   |   Action: Attempting Sign-In       |
+------------------------------------+------------------------------------+
```

### Demonstration Flow:

#### Phase A: Legitimate User Baseline & Primary Device Designation (Browser 1)
1. In **Browser 1 (Chrome)**, go to `http://127.0.0.1:8000`.
2. On the **User Portal** sign-in tab, click **`👤 Fill Demo User (Sachin)`**.
   * Auto-populates `demo@awssecurity.io` and password `AWSSecurity#2026`.
3. Click **`Authenticate & Verify Session`**.
4. **Primary Device Prompt Modal appears**:
   * *"Is this workstation / browser your Primary Security Device?"*
   * Displays detected hardware (e.g., `Chrome on Windows NT 10.0`) and access origin (`New York, US`).
   * Click **`🛡️ Yes, Register as My Primary Device`**.
5. The dashboard loads:
   * Displays profile name: **Sachin (Demo Security Lead)**.
   * Header badge: **`🛡️ Primary Security Portal (Master Device)`**.
   * Active Sessions table shows an active session with **`🟢 Primary Device (This Portal)`**.
   * Top navbar displays `🟢 LIVE SYNC: 2s` and `🔊 Sound: ON`.
6. Keep Browser 1 open on the **User Portal** tab.

##### Phase B: Secondary Device Sign-In & Remote Session Termination (Browser 2)
You can demonstrate multi-device credential usage and cyber attacks in Browser 2:

##### Option 0: Secondary Device Sign-In with Valid Credentials (Legitimate Secondary Workstation)
1. In **Browser 2 (e.g. Edge)**, open `http://127.0.0.1:8000`.
2. Click **`👤 Fill Demo User (Sachin)`** and click **`Authenticate & Verify Session`**.
3. **Continuous Trust Classification**:
   * The backend detects that `demo@awssecurity.io` already has a registered Primary Device.
   * Browser 2 is automatically enrolled as **`📱 Secondary Device Session`**.
   * A warning banner appears in Browser 2: *"You are accessing AWSSecurity from a secondary workstation. Master kill switches and authorizations are governed by your Primary Security Portal."*
4. **Immediate Effect in Browser 1 (Primary Portal)**:
   * Browser 1 receives an instant notification:  
     `ℹ️ Secondary Device Sign-In: Account accessed with valid credentials from Secondary Device (Edge on Windows).`
5. **Session Isolation & Master Authority**:
   * In Browser 2, try to kill the primary session: it is protected and forbidden (HTTP 403).
   * In **Browser 1 (Primary Portal)**, click **`🛡️ Terminate Other Sessions`** (or `Kill Session` on the remote device):
     * Browser 2's session is instantly revoked (subsequent actions return 401 Unauthorized).
     * **Browser 1 (Primary Portal) remains 100% active, authenticated, and NEVER gets logged out!**

##### Option 1: Live Credential Guessing / Failed Logins (Direct on Login Form)
1. In **Browser 2 (e.g., Edge)**, open `http://127.0.0.1:8000`.
2. Notice the clean, authentic enterprise sign-in interface.
3. Type the victim's email: `demo@awssecurity.io`.
4. Type an **incorrect / guessed password** (e.g. `HackedPass123` or `Admin@123`).
5. Click **`Authenticate & Verify Session`**.
   * Status 401: Access denied.
6. Enter another wrong password and click **Authenticate** again.
7. **Immediate Effect in Browser 1 (Legitimate User):**
   * Within 2 seconds, Browser 1 **plays an emergency siren sound**!
   * A crimson alert banner slides down across the top of Browser 1:  
     `🚨 CRITICAL SECURITY ALERT: REPEATED FAILED LOGINS`  
     `⚠️ Repeated Failed Logins: 2 unauthorized attempts with incorrect password from Edge on Windows NT 10.0.`
   * The **Security Alerts Inbox** count badge increments to **`1`** (or updates live), displaying the attacker's device, IP, and timestamp.
   * If the attacker tries 5 times, the system triggers `BRUTE_FORCE_LOCKOUT` and enforces an automated rate-limit lockout!

##### Option 2: Red Team Cyber Attack Studio (`⚡ Attack Simulator` Tab)
1. In **Browser 2**, click **`⚡ Attack Simulator`** in the top navigation bar.
2. In the target email field, ensure `demo@awssecurity.io` is entered.
3. Click **`Launch Scenario`** under **`🎌 Impossible Travel (Tokyo, 8,500 km/h)`**:
   * The live terminal logs: `[RED TEAM] Initiating simulated IMPOSSIBLE_TRAVEL vector against demo@awssecurity.io...`
   * The defense response logs: `[POLICY ENFORCEMENT] Action Taken: BLOCK_SESSION (Risk Score: 88.0/100)`.
   * Deep Autoencoder Reconstruction Loss: `0.18+` (threshold exceeded).
4. **Immediate Effect in Browser 1 (Legitimate User):**
   * Browser 1 immediately triggers the siren chime.
   * The sliding alert banner displays:  
     `🚨 CRITICAL SECURITY ALERT: SIMULATED IMPOSSIBLE_TRAVEL`  
     `Suspicious anomaly detected • Tokyo, Japan • Risk: 88.0/100.`
   * The alert card appears in the Security Alerts Inbox with full XAI factor breakdown.

#### Phase C: Immediate Real-Time Alert & Emergency Kill Switch (Browser 1)
1. **In Browser 1 (Legitimate User):**
   * Notice that without refreshing the page, within 2 seconds:
     * An **audible emergency siren chime** plays via Web Audio API!
     * A pulsing **CRITICAL SECURITY ALERT** banner slides down at the top of the window.
     * The **Security Alerts Inbox** count badge updates with recent threat cards showing IP, device, and XAI risk breakdown.
2. In Browser 1, click **`🚨 Freeze Account`**:
   * A confirmation modal appears. Confirm the action.
   * The account status changes to `LOCKED` and all sessions are terminated.
   * In Browser 2, any further login attempt or action is instantly rejected with `ACCOUNT_LOCKED`.

#### Phase D: Inspecting Defense Telemetry in SOC Blue Team & CloudWatch
1. In Browser 1, switch to the **`🛰️ SOC Blue Team`** tab:
   * Watch the animated **SVG Risk Gauge** needle spike into the crimson danger zone (`88.0`).
   * The **Geo-Velocity Travel Map Visualizer** renders the parabolic flight trajectory from New York to Tokyo with flight speed `> 8,500 KM/H`.
   * Click **`Inspect`** on the top event in the table to show the **Explainable AI (XAI)** factor attribution and Deep Autoencoder MSE reconstruction loss.
2. Switch to the **`📊 Telemetry & SIEM`** tab:
   * Notice that `BlockedHijacks` has incremented.
   * Search `Tokyo` or `AccountHijackRiskEngine` in the structured CloudWatch log stream table.

---

## 4. Exhaustive Button-by-Button Frontend Working Catalog

### Top Navigation Bar

| Element / Button | View / Location | Technical Action | What to Explain to Examiners |
| :--- | :--- | :--- | :--- |
| **AWSSecurity AI Logo** | Top Left Navbar | Triggers `switchTab('user-portal')` | "Returns to the primary security portal view." |
| **`👤 User Portal`** | Navbar Nav Link | Switches active view to User Portal (`#user-portal`) | "The interface used by authentic enterprise users to monitor sessions and security alerts." |
| **`⚡ Attack Simulator`** | Navbar Nav Link | Switches to Red Team Studio (`#attack-studio`) | "The controlled sandbox for demonstrating attacks (Impossible Travel, Tor stuffing, Brute force)." |
| **`🛰️ SOC Blue Team`** | Navbar Nav Link | Switches to SOC Dashboard (`#soc-dashboard`) | "The Blue Team Security Operations Center view with real-time risk gauges, flight vectors, and telemetry." |
| **`📊 Telemetry & SIEM`** | Navbar Nav Link | Switches to CloudWatch SIEM (`#cloudwatch-view`) | "Live AWS CloudWatch metrics, log stream search, and automated alarm threshold monitoring." |
| **`📜 Compliance`** | Navbar Nav Link | Switches to Legal Center (`#compliance-view`) | "Governance documentation (GDPR, ISO 27001, WCAG 2.1 AA accessibility, and security disclosure)." |
| **`🟢 LIVE SYNC: 2s`** | Top Right Navbar | Status indicator | "Indicates active 2-second background polling ensuring instant cross-browser updates." |
| **`🔊 Sound: ON / OFF`** | Top Right Navbar | Toggles `soundEnabled` via Web Audio API synth | "Mutes or activates audio alarm sirens triggered by incoming account hijacking threats." |
| **`📖 Practice Guide`** | Top Right Navbar | Opens `modal-practice-guide` | "Interactive viva guide and button catalog embedded directly in the web UI." |
| **`❓ Help`** | Top Right Navbar | Opens `modal-help` | "User incident response guide answering what to do if an unauthorized login alert is received." |

---

### View 1: Legitimate User Portal (`#user-portal`)

#### Unauthenticated (Sign In & Register)
| Button / Input | Location | Technical Action | What to Explain to Examiners |
| :--- | :--- | :--- | :--- |
| **`Sign In` / `Create Account` Tabs** | Auth Card Header | Switches between login form and registration form | "Allows toggle between authenticating existing users and enrolling new accounts." |
| **`👤 Fill Demo User (Sachin)`** | Above Login Form | Auto-fills `demo@awssecurity.io` and password | "Quick-fill button providing the seeded test account for live evaluations." |
| **`Master Password` Input** | Login Form | Input field (`#login-password`) | "Raw password verified on server using PBKDF2-HMAC-SHA256 with 200,000 iterations and salt." |
| **`Forgot password?` Link** | Above Password | Opens `modal-forgot-password` | "Initiates anti-enumeration password reset flow with time-limited cryptographic token." |
| **`Hardware Fingerprint` Box** | Above Submit | Evaluated via `fingerprint.js` | "Evaluates browser canvas hash, screen resolution, and OS concurrency for device identification." |
| **`Authenticate & Verify Session`** | Login Form | Submits `POST /api/auth/login` | "Submits payload to API Gateway and Lambda Risk Engine for continuous ML assessment." |
| **Password Strength Meter** | Register Form | Evaluates entropy on input | "Live client-side password strength meter enforcing length, uppercase, numbers, and symbols." |

#### Authenticated Dashboard
| Button / Input | Location | Technical Action | What to Explain to Examiners |
| :--- | :--- | :--- | :--- |
| **`📘 System Tour`** | Dashboard Header | Opens `modal-onboarding` | "Explains how the behavioral baseline and Haversine velocity detection work." |
| **`🚨 Freeze Account`** | Dashboard Header | Calls `POST /api/auth/lock-account` | "Emergency kill switch: marks user `LOCKED` in MongoDB and immediately purges all active session tokens." |
| **`Sign Out`** | Dashboard Header | Clears localStorage token and state | "Terminates the local session token cleanly." |
| **`Refresh` (Sessions Table)** | Active Sessions Card | Calls `GET /api/auth/sessions` | "Manually pulls active session records; also refreshed automatically every 2 seconds." |
| **`Kill Session`** | Sessions Row Action | Calls `POST /api/auth/sessions/kill` | "Targeted kill switch: terminates access on a specific device without locking the entire account." |
| **`Check Alerts`** | Alerts Inbox Card | Calls `GET /api/security/user-alerts` | "Pulls recent security detections and threat classifications." |
| **`This was me`** | Alert Item Action | Acknowledges alert | "Confirms the activity was legitimate." |
| **`Not me (Lock Account Now)`** | Alert Item Action | Calls `emergencyLockAccount()` | "Victim response button: immediately locks account and terminates attacker access." |
| **`Rotate Password`** | Dashboard Footer | Opens `modal-reset-password` | "Allows updating password, invalidating previous active tokens for security." |
| **`Delete Account & Telemetry`**| Dashboard Footer | Opens `modal-delete-account` | "GDPR Right to Erasure: purges account, sessions, and audit telemetry upon password re-verification." |

---

### View 2: Red Team Attack Simulator (`#attack-studio`)

| Button / Element | Technical Action | What to Explain to Examiners |
| :--- | :--- | :--- |
| **Target Email Input** | Sets `#sim-target-email` | "Selects which user's learned baseline is targeted by the attack simulation." |
| **`Launch Scenario` (Impossible Travel)** | Calls `POST /api/security/simulate-attack` with `IMPOSSIBLE_TRAVEL` | "Simulates Tokyo login 2 minutes after New York. Tests Haversine speed calculation and automatic blocking." |
| **`Launch Scenario` (Tor Credential Stuffing)** | Calls `POST /api/security/simulate-attack` with `CREDENTIAL_STUFFING` | "Simulates valid password from known Tor exit IP. Tests IP reputation threat intelligence scoring." |
| **`Launch Scenario` (Brute Force Burst)** | Calls `POST /api/security/simulate-attack` with `BRUTE_FORCE` | "Simulates 6 rapid failed attempts. Tests sliding-window rate limiter lockout and CloudWatch alarm." |
| **`Launch Scenario` (Device Spoofing)** | Calls `POST /api/security/simulate-attack` with `DEVICE_SPOOF` | "Simulates unknown hardware canvas signature. Tests Euclidean device distance." |
| **`Clear Console`** | Resets terminal UI | "Clears simulated command line logs in the defense console." |

---

### View 3: Blue Team SOC Dashboard (`#soc-dashboard`)

| Button / Element | Technical Action | What to Explain to Examiners |
| :--- | :--- | :--- |
| **Metric Counters (Total, Blocked, MFA, Normal)** | Polled from `GET /api/security/stats` | "Aggregated high-level event metrics updated in real-time." |
| **Animated SVG Risk Gauge** | `updateRiskGauge(score)` rotates needle (-90° to +90°) | "Visualizes composite risk score: Green (<40), Yellow (40-69 MFA), Crimson (≥70 Block)." |
| **Geo-Velocity Flight Canvas** | HTML5 Canvas drawing arc between origins | "Visualizes Haversine great-circle flight path. Draws crimson arc with velocity label if impossible." |
| **`Refresh Stream`** | Calls `GET /api/security/events?limit=25` | "Refreshes live security event audit stream." |
| **`Inspect` (Event Row)** | Calls `inspectEvent(eventId)` and opens modal | "Explainable AI (XAI) deep dive showing exact feature weights and Autoencoder MSE loss." |

---

### View 4: Telemetry & SIEM (`#cloudwatch-view`)

| Button / Element | Technical Action | What to Explain to Examiners |
| :--- | :--- | :--- |
| **CloudWatch Metric Cards** | `Invocations`, `HighRiskDetections`, `BlockedHijacks`, `LatencyMs` | "Simulates Amazon CloudWatch custom metrics emitted by AWS Lambda handlers." |
| **CloudWatch Alarms Board** | Evaluates `HighRiskRateAlarm` and `BruteForceBurstAlarm` | "Shows alarm state (OK vs ALARM) linked to Amazon SNS notification topics." |
| **Log Stream Search Input** | Filters `allCloudWatchLogs` array in real-time | "Performs instant keyword search on structured JSON log payloads." |
| **Log Level Filter Dropdown** | Filters by `ALL`, `INFO`, `WARN`, `ERROR` | "Filters log severity levels matching AWS CloudWatch Log Insights syntax." |

---

## 5. Machine Learning Algorithms, Formulas & Scoring Rules

AWSSecurity AI implements an **ensemble defense mechanism** combining supervised classification, unsupervised outlier detection, deep neural reconstruction, and explainable rule heuristics:

```
[Incoming Telemetry]
         │
         ├──► 1. Haversine Geo-Velocity (v = d / Δt) ──────► Speed > 900 km/h?
         ├──► 2. Device Fingerprint Distance (Euclidean) ──► Canvas / OS Variance?
         ├──► 3. IP Reputation & Bot Signature ────────────► Tor / Datacenter / Headless?
         │
         ▼
[Feature Vector Extraction]
         │
         ├──► 4. Supervised Random Forest Classifier ──────► P(Hijack) * 60%
         ├──► 5. Unsupervised Isolation Forest Outlier ────► +10 pts if Outlier
         ├──► 6. Deep Neural Autoencoder Loss ─────────────► MSE = (1/n) Σ(x_i - x̂_i)²
         │
         ▼
[Composite Calibrated Risk Score: 0 - 100]
         │
         ├── Score < 40  ──────► [ALLOW] Normal Baseline
         ├── 40 <= Score < 70 ─► [STEP_UP_MFA] Unusual Access, Verification Code Sent
         └── Score >= 70 ──────► [BLOCK_SESSION] Hijacking Blocked, User Alerted Immediately
```

### Key Mathematical Formulas:

#### 1. Haversine Great-Circle Distance & Velocity Formula
Calculates the shortest distance over the Earth's surface between consecutive login coordinates:
$$\Delta\sigma = 2 \arcsin \sqrt{\sin^2\left(\frac{\Delta\phi}{2}\right) + \cos\phi_1 \cos\phi_2 \sin^2\left(\frac{\Delta\lambda}{2}\right)}$$
$$d = R \cdot \Delta\sigma \quad (\text{where } R = 6371 \text{ km})$$
$$\text{Velocity } (v) = \frac{d}{\Delta t} \quad (\text{km/h})$$
* **Rule:** If $v \ge 900\text{ km/h}$, commercial passenger aircraft flight speed is exceeded &rarr; Flagged as **Impossible Travel** (+30 to 45 risk points).

#### 2. Deep Neural Autoencoder Reconstruction Error (MSE Loss)
An unsupervised neural network trained to reconstruct legitimate user behavioral feature vectors:
$$\text{MSE} = \frac{1}{n} \sum_{i=1}^n (x_i - \hat{x}_i)^2$$
* **Rule:** If $\text{MSE} \ge 0.12$, the behavioral pattern cannot be reconstructed by normal user weights &rarr; Flagged as **Zero-Day Behavioral Anomaly**.

#### 3. Composite Ensemble Scoring Equation
$$\text{Score} = \min\Big(100.0, \, \big(P_{\text{RandomForest}} \times 0.60\big) + \big(\text{RuleScore} \times 0.40\big) + \text{Penalty}_{\text{IsolationForest}}\Big)$$

---

## 6. AWS Serverless Cloud Infrastructure Mapping

When deployed to production on AWS using `aws/template.yaml`, the local services map directly to cloud-native managed components:

| Local Component in Demo | AWS Cloud-Native Service | Responsibility |
| :--- | :--- | :--- |
| `FastAPI REST API` | **Amazon API Gateway** | Managed REST API with throttling, CORS, and request schema validation. |
| `backend/security/auth.py` | **AWS Lambda (`AuthHandler`)** | Serverless function executing PBKDF2 verification, tokens, and session kills. |
| `backend/ml/model.py` | **AWS Lambda (`RiskEngine`)** | Containerized Lambda running Scikit-Learn & Autoencoder inference under 20ms. |
| `cloudwatch_service.py` | **Amazon CloudWatch** | Custom CloudWatch metrics, structured CloudWatch Logs, and CloudWatch Alarms. |
| `In-App Audio/Banner Alert` | **Amazon SNS (Simple Notification Service)** | Push notifications and SMS/Email security alerts dispatched to victims. |
| `database/db_manager.py` | **Amazon DynamoDB / DocumentDB** | Managed NoSQL document store with encryption-at-rest for users & active sessions. |
| `aws/template.yaml` | **AWS SAM / CloudFormation** | Infrastructure as Code (IaC) defining the serverless stack with one-click deployment. |

---

## 7. Viva & Project Defense Questions & Answers

### Q1: Why is username and password verification not enough to prevent account hijacking?
> **Answer:** Passwords are static secrets. Once an attacker obtains them through phishing, infostealer malware, or credential stuffing from credential leaks, standard authentication treats the attacker as the legitimate owner. AWSSecurity AI adds **continuous behavioral telemetry** to verify not just *what the user knows*, but *how, when, from where, and on what device* they access the system.

### Q2: What happens if a user is legitimately traveling on an airplane with Wi-Fi?
> **Answer:** In commercial in-flight Wi-Fi, the IP address typically belongs to a known aviation satellite ISP (e.g., Gogo, Viasat, Panasonic Avionics) and the velocity matches aircraft speeds (700–900 km/h). In our system, speed between 250 and 900 km/h triggers **Step-Up MFA** (Medium Risk: 40–69) rather than an outright block. The user verifies an SMS or OTP code and proceeds safely without disruption.

### Q3: How do you prevent timing attacks and account enumeration on the login form?
> **Answer:** In `backend/app.py`, if a user provides an email that does not exist in the database, the server computes a **constant-time dummy PBKDF2 hash calculation** (`verify_password(raw_pw, "0"*64, salt)`) before returning a generic error message (*"Invalid credentials or account restricted"*). This ensures response time is identical whether an account exists or not, defeating timing attacks and user enumeration.

### Q4: Why combine Random Forest with an unsupervised Autoencoder?
> **Answer:** Random Forest is a supervised model trained on known attack patterns (e.g., specific Tor ranges or bot signatures). However, attackers constantly evolve novel, unseen tactics. The **Deep Autoencoder** is unsupervised—it learns the structure of *legitimate* user behavior. Any novel anomaly that deviates from the learned baseline produces a high Mean Squared Error (MSE) reconstruction loss, allowing us to catch zero-day account takeovers.

### Q5: How does the Remote Kill Switch work technically?
> **Answer:** Session tokens are stored in the database with an active status. On every authenticated request or 2-second background poll, the token is verified. When the user clicks **"Kill Session"** or **"Freeze Account"**, the database record is deleted or set to `LOCKED`. The attacker's very next request or heartbeat returns `401 Unauthorized` or `403 Account Locked`, immediately invalidating their browser cookies and kicking them out of the application.

---

*Authored by AWSSecurity AI Cyber Defense Engineering Team • 2026*
