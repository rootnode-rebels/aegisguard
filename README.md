# Real-Time Account Hijacking Detection and Prevention System (AWSSecurity AI)

A cloud-native, Machine Learning-powered cybersecurity web application built on AWS Serverless architecture to detect, analyze, alert, and automatically block unauthorized access and account hijacking attempts in real time.

---

## 1. System Architecture

```
                                      +---------------------------------------------+
                                      |         DUAL-PERSONA CLIENT SUITE           |
                                      |  • Legitimate User Security Portal          |
                                      |  • Red Team Attack Simulator Studio         |
                                      |  • Blue Team SOC & CloudWatch Visualizer    |
                                      +----------------------+----------------------+
                                                             |
                                           HTTPS / JSON REST API (CORS)
                                                             |
                                      +----------------------v----------------------+
                                      |            AMAZON API GATEWAY               |
                                      |  • Pydantic Strict Input Validation         |
                                      |  • XSS / NoSQL Injection Sanitizer          |
                                      |  • Sliding-Window Brute Force Rate Limiter  |
                                      +----------------------+----------------------+
                                                             |
                      +--------------------------------------+--------------------------------------+
                      |                                      |                                      |
       +--------------v---------------+      +---------------v--------------+      +----------------v---------------+
       |    AWS LAMBDA: AUTH & MGT    |      |    AWS LAMBDA: ML ENGINE     |      |   AWS LAMBDA: ALERT NOTIFY     |
       |  • PBKDF2-HMAC-SHA256 Hashing|      |  • Scikit-learn Random Forest|      |  • Amazon SNS Topic Dispatch   |
       |  • Generic Error Messaging   |      |  • Isolation Forest Outliers |      |  • Immediate User In-App Alert |
       |  • Active Session Kill Switch|      |  • Deep DL Neural Autoencoder|      |  • Emergency Lockout Processor |
       +--------------+---------------+      +---------------+--------------+      +----------------+---------------+
                      |                                      |                                      |
                      +--------------------------------------+--------------------------------------+
                                                             |
                                      +----------------------v----------------------+
                                      |       AMAZON CLOUDWATCH & MONGODB           |
                                      |  • CloudWatch Metrics: Invocations, Alarms  |
                                      |  • CloudWatch Log Stream: Structured Audits |
                                      |  • MongoDB: Users, Sessions, Security Events|
                                      +---------------------------------------------+
```

---

## 2. Software Requirements Matrix

| Requirement | Implementation in this Repository |
| :--- | :--- |
| **Python / Node.js** | • Python 3.14 backend runtime (`backend/app.py`, `backend/ml/`, `aws/lambdas/auth_handler.py`, `aws/lambdas/risk_engine.py`).<br>• Node.js Lambda Event Dispatcher (`aws/lambdas/event_dispatcher.js`). |
| **AWS Serverless** | • AWS SAM / CloudFormation template (`aws/template.yaml`) defining API Gateway, Lambda functions, CloudWatch Log Groups, Metric Alarms, and SNS topics.<br>• CloudWatch Dashboard specification (`aws/cloudwatch_dashboard.json`). |
| **TensorFlow / Scikit-learn** | • **Scikit-learn**: Isolation Forest (unsupervised anomaly detection) + Random Forest behavioral risk scoring classifier (`backend/ml/train_model.py`, `backend/ml/risk_model.joblib`).<br>• **TensorFlow/Keras**: Deep Autoencoder neural network (`backend/ml/tf_autoencoder.py`) calculating reconstruction Mean Squared Error (MSE) loss. |
| **CloudWatch Monitoring** | • Real-time CloudWatch custom metrics tracking (`Invocations`, `HighRiskDetections`, `BlockedHijacks`, `LatencyMs`).<br>• CloudWatch Log Stream viewer with live keyword/level search (`/aws/lambda/AccountHijackRiskEngine`).<br>• CloudWatch Metric Alarms (`HighRiskRateAlarm`, `BruteForceBurstAlarm`). |
| **Database (MongoDB)** | • MongoDB collections and indexes (`database/mongo_schema.js`).<br>• Unified DB abstraction layer (`database/db_manager.py`) with zero-config local document store and live MongoDB URI fallback. |

---

## 3. Global Security Policy Adherence

1. **Strict Input Validation**: Pydantic schemas validate all incoming parameters (email regex, password length constraints, IP format).
2. **Server Input Sanitization**: Recursive sanitization neutralizes HTML/script tags (XSS) and NoSQL injection operators (`$where`, `$gt`, `$ne`).
3. **Brute Force Defense**: Sliding-window rate limiting throttles requests and locks out attackers after 5 failed attempts within 10 minutes.
4. **Secure Password Hashing**: Passwords are encrypted with PBKDF2-HMAC-SHA256 using 200,000 iterations and unique 16-byte cryptographic salts.
5. **Generic Error Messages**: Authentication failures always return generic messaging (*"Invalid credentials or account restricted"*) to prevent user enumeration.

---

## 4. Quick Start (Running Locally)

### Prerequisites
- Python 3.10+ (Python 3.14 installed and tested)
- Node.js 18+ (Node v24.16 installed and tested)

### Step 1: Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### Step 2: Run Automated Test Suite
```bash
python -m unittest tests/test_backend.py
```

### Step 3: Launch Local Serverless Application
```bash
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser to: **`http://127.0.0.1:8000`**

---

## 5. Live Demonstration Scenarios

1. **Legitimate User Portal**:
   - Register a new account (note the live password strength meter and hardware fingerprint).
   - Sign in to view your dashboard, active sessions, and security inbox.
2. **Red Team Attack Simulation**:
   - Switch to the **Attack Simulator** tab.
   - Click **Impossible Travel** to simulate access from Tokyo 2 minutes after New York (speed: 8,500 km/h).
   - Click **Tor Credential Stuffing** to simulate login via a known Tor exit relay (185.220.101.45).
   - Observe how the ML Risk Engine flags the threat (> 70/100) and automatically executes `BLOCK_SESSION`.
3. **Blue Team SOC Dashboard**:
   - Switch to **SOC Blue Team** to watch the animated SVG Risk Gauge needle spike into the Crimson zone.
   - Inspect the interactive Geo-Velocity travel visualizer plotting the flight path and velocity between coordinates.
   - Click **Inspect** on any event in the real-time stream to review the Explainable AI (XAI) feature attribution breakdown.
4. **Amazon CloudWatch Panel**:
   - Review live CloudWatch metric counters (`Invocations`, `HighRiskDetections`, `BlockedHijacks`).
   - Monitor the `HighRiskRateAlarm` state and search the real-time CloudWatch log stream.
5. **Instant Session Kill Switch**:
   - In the User Portal, click **Kill Session** on any device to revoke access immediately.
   - Click **Freeze Account** to lock the account and invalidate all tokens.

---

## 6. AWS Cloud Deployment (SAM / CloudFormation)

To deploy to live AWS:
```bash
cd aws
sam build
sam deploy --guided
```
This deploys the complete stack including API Gateway, AWS Lambda handlers, Amazon CloudWatch Alarms, and Amazon SNS Topics.
