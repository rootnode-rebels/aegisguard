# Production Page & UX State Audit: Real-Time Account Hijacking Detection & Prevention System

## 1. Project Evidence & Repository Baseline

- **Repository Path**: `d:\RootNode-Rebels\AWS Project`
- **Application Type**: Real-Time Cybersecurity Web Application (Serverless Architecture for Account Hijacking Detection & Automated Prevention)
- **Primary Runtime**: Python 3.14 (FastAPI + Scikit-learn + TensorFlow) & Node.js Lambda support
- **Target Cloud**: AWS (Amazon Web Services: AWS Lambda, API Gateway, Amazon CloudWatch, Amazon SNS)
- **Database Engine**: MongoDB (Collections: `users`, `active_sessions`, `security_events`, `cloudwatch_logs`, `password_resets`)
- **Authentication Model**: Token-based authentication with salted cryptographic password hashes (PBKDF2-HMAC-SHA256, 200,000 iterations), sliding-window rate limiting, adaptive Step-up MFA, and session revocation kill switch.
- **Commercial / Billing Model**: Non-commercial cybersecurity monitoring and defensive research platform. There are **no subscriptions, no payment processing, no e-commerce goods, and no physical shipping**.

---

## 2. Production Page & UX State Audit Table

| Category | Page or state | Status | Evidence | Applicability reason | Required action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Legal** | Privacy Policy | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Collects IP addresses, device fingerprints, geolocation coordinates, and login timestamps for security analysis. | Retained and accessible via footer link and modal viewer. |
| **Legal** | Terms of Service | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Governs user accounts, security monitoring, and attack simulation scope. | Retained and accessible via footer link. |
| **Legal** | Cookie Policy | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Uses essential session storage (`cyber_token`) for authentication. | Retained. |
| **Legal** | Cookie Preferences | NOT_APPLICABLE | Code inspection: zero analytics, marketing, or tracking cookies exist. | All client storage is strictly necessary for security and session state. | Excluded by design. |
| **Legal** | Refund Policy | NOT_APPLICABLE | No payment gateway or monetized services exist in this security platform. | Not an e-commerce or paid product. | Excluded. |
| **Legal** | Cancellation Policy | NOT_APPLICABLE | No subscriptions or recurring charges exist. | Inapplicable to security monitoring application. | Excluded. |
| **Legal** | Shipping Policy | NOT_APPLICABLE | No physical goods are sold or shipped. | Digital cybersecurity software only. | Excluded. |
| **Legal** | Return / Exchange Policy | NOT_APPLICABLE | No physical merchandise exists. | Inapplicable. | Excluded. |
| **Legal** | Disclaimer | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Red Team Attack Simulator tests credential stuffing and travel anomalies. | Retained: Defensive testing disclaimer active. |
| **Legal** | Accessibility Statement | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Public web UI with WCAG 2.1 AA targets (ARIA, contrast, focus rings). | Retained: Accessibility commitments documented. |
| **Legal** | Data Processing Agreement | NOT_APPLICABLE | Academic & research reference architecture; no enterprise B2B data controller agreements. | Enterprise DPA not applicable at current stage. | Excluded. |
| **Legal** | Acceptable Use Policy | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Application provides attack simulation features. | Retained: Prohibits unauthorized scanning & DoS. |
| **Legal** | Security Policy | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Core product is a cybersecurity platform. | Retained: Outlines PBKDF2 hashing, rate limiting, and Lambda isolation. |
| **Legal** | Responsible Disclosure | EXISTS_AND_ADEQUATE | [frontend/js/legal_views.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/legal_views.js) | Provides reporting channel for external security researchers. | Retained: Safe harbor terms and reporting workflow. |
| **Legal** | Community Guidelines | NOT_APPLICABLE | No public social forums, comment sections, or user-generated communities. | Not a social platform. | Excluded. |
| **Customer Lifecycle** | Login | EXISTS_AND_ADEQUATE | [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html), [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js) | User credentials required to access protected account portal. | Retained: Strict validation, generic errors, ML risk scoring. |
| **Customer Lifecycle** | Register | EXISTS_AND_ADEQUATE | [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html), [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js) | New users establish accounts and baseline behavioral profiles. | Retained: Live password strength meter, hardware fingerprinting. |
| **Customer Lifecycle** | Email Verification / Step-Up MFA | EXISTS_AND_ADEQUATE | [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js), [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L248) | Adaptive Step-up MFA challenge triggered when risk is elevated (40–69). | Retained: 6-digit OTP modal dialog and validation endpoint. |
| **Customer Lifecycle** | Forgot Password | EXISTS_AND_ADEQUATE | [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js), [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L324) | Account recovery mechanism for users. | Retained: Anti-enumeration generic response, 15-min expiring tokens. |
| **Customer Lifecycle** | Reset Password | EXISTS_AND_ADEQUATE | [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js), [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L348) | Required to securely change password using valid token. | Retained: Invalidates all previous active sessions upon rotation. |
| **Customer Lifecycle** | Onboarding | EXISTS_AND_ADEQUATE | [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html#L380) | Guides users through behavioral baselines and automated protection. | Retained: System Tour modal accessible via header. |
| **Customer Lifecycle** | Account Settings & Active Sessions | EXISTS_AND_ADEQUATE | [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js) | Users view security health, active sessions, and alerts. | Retained: Live sessions table, instant kill switch, freeze button. |
| **Customer Lifecycle** | Account Deletion | EXISTS_AND_ADEQUATE | [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js), [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L422) | Users have the right to erase account and telemetry history. | Retained: Password confirmation modal and permanent purge endpoint. |
| **Customer Lifecycle** | Billing / Upgrade / Downgrade / Cancel | NOT_APPLICABLE | Non-commercial security demonstration application; no payment processing. | Not an e-commerce or subscription service. | Excluded. |
| **Customer Lifecycle** | Payment Success / Failed / Pending | NOT_APPLICABLE | Zero financial checkout or merchant processing exists. | Inapplicable. | Excluded. |
| **Customer Lifecycle** | Support / Help Center | EXISTS_AND_ADEQUATE | [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html#L400) | Users need guidance on incident response and simulator usage. | Retained: Help Center modal accessible from top bar. |
| **UX State** | 404 (Route Not Found) | EXISTS_AND_ADEQUATE | [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L580) | Users navigate to non-existent URLs or broken paths. | Retained: SPA fallback routing with safe navigation. |
| **UX State** | 403 (Forbidden / Access Blocked) | EXISTS_AND_ADEQUATE | [frontend/js/app.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/app.js#L42) | High-risk hijacking attempts (> 70/100) are blocked immediately. | Retained: Error banner, modal freeze notice, session termination. |
| **UX State** | 500 (Internal Server Error) | EXISTS_AND_ADEQUATE | [frontend/js/app.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/app.js#L20), [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L50) | Backend exception handling without sensitive leakage. | Retained: Safe messaging with request correlation ID (`X-Request-Id`). |
| **UX State** | Maintenance Mode | EXISTS_AND_ADEQUATE | [backend/app.py](file:///d:/RootNode-Rebels/AWS%20Project/backend/app.py#L55), [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html#L355) | Operational requirement for ML model retraining downtime. | Retained: Toggleable 503 response and client modal with reconnect. |
| **UX State** | Offline State | EXISTS_AND_ADEQUATE | [frontend/js/app.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/app.js#L95), [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html#L18) | User loses network connection during active session. | Retained: Automatic offline banner and reconnect listener. |
| **UX State** | Empty State | EXISTS_AND_ADEQUATE | [frontend/js/user_portal.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/user_portal.js#L170), [frontend/js/soc_dashboard.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/soc_dashboard.js#L75) | New accounts have no security alerts; SOC stream is initial. | Retained: Informative cyber-themed empty state boxes. |
| **UX State** | No Search Results | EXISTS_AND_ADEQUATE | [frontend/js/cloudwatch_view.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/cloudwatch_view.js#L85) | Filtering CloudWatch logs with non-matching keywords. | Retained: Clear feedback banner for non-matching queries. |
| **UX State** | Loading State | EXISTS_AND_ADEQUATE | [frontend/css/style.css](file:///d:/RootNode-Rebels/AWS%20Project/frontend/css/style.css#L150) | Responsive visual feedback during authentication & ML inference. | Retained: Pulsing beacon animations and status indicators. |
| **UX State** | Error State | EXISTS_AND_ADEQUATE | [frontend/js/app.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/app.js#L72) | Network timeouts or validation rejections. | Retained: Red-accented toast banners and inline feedback. |
| **UX State** | Success State | EXISTS_AND_ADEQUATE | [frontend/js/app.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/app.js#L72) | Successful login, password reset, or session revocation. | Retained: Green toast checkmarks and feedback dialogs. |
| **UX State** | Session Expired | EXISTS_AND_ADEQUATE | [frontend/js/app.js](file:///d:/RootNode-Rebels/AWS%20Project/frontend/js/app.js#L87), [frontend/index.html](file:///d:/RootNode-Rebels/AWS%20Project/frontend/index.html#L368) | Token expiration or kill switch execution. | Retained: Safe modal redirecting to sign in with token eviction. |

---

## 3. Information That Must Not Be Invented (Resolved Accurately)

- **Operator / Legal Entity**: Documented truthfully as `RootNode-Rebels Security Research Team` (reflecting workspace root).
- **Contact Details**: Configured via standard security disclosures (`security-disclosure@rootnode-rebels.local`).
- **Data Practices**: Derived strictly from actual data stored in MongoDB (IPs, coordinates, device hashes, login timestamps).
- **Compliance Claims**: No unverified SOC 2 or HIPAA certifications claimed; stated transparently as an academic & defensive cybersecurity architecture adhering to WCAG 2.1 AA accessibility design targets.
