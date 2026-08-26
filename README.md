# AI Network Threat Intelligence Platform — Portfolio Edition

An AI-assisted Security Operations Center (SOC) platform designed to ingest network security events, detect anomalies, classify threats, correlate Indicators of Compromise (IOCs), CVEs, and MITRE ATT&CK techniques, generate explainable AI (XAI) feature attributions (SHAP/LIME), score risk, and recommend incident responses in real time.

Includes an interactive public-facing portfolio showcase with an interactive pipeline flow graph (`@xyflow/react`), force-directed network topology (`react-force-graph-2d`), MITRE ATT&CK heatmap, live threat simulator, EICAR security sandbox, XAI model inspector, and SOC incident management console.

---

## Technical Architecture & Stack

- **Frontend**: React 18, Vite, Tailwind CSS, Framer Motion, `@xyflow/react` (pipeline graph), `react-force-graph-2d` (topology graph), Recharts, Axios, Lucide Icons.
- **Backend**: Python 3.11, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2.0, `slowapi` rate limiting, `python-jose` JWT authentication.
- **Machine Learning & XAI**: `scikit-learn` (Isolation Forest), `xgboost` (Multi-class Classifier), `shap` (TreeExplainer), `lime` (LimeTabularExplainer), `joblib`, `pandas`, `numpy`.
- **Database**: PostgreSQL 16 (via Docker Compose) with dynamic SQLite fallback for zero-friction local development.
- **Threat Intelligence**: 11 evidence-gated MITRE ATT&CK techniques, 12 real CVE mappings, IOC reputation engine.

---

## System Capabilities

### 1. Synthetic Event Generator & Threat Scenarios
- **Port Scan Reconnaissance**: Multi-port scanning behavior (`T1046`).
- **Brute-Force SSH/RDP**: Repeated authentication failures (`T1110`, `T1078`).
- **DNS Tunneling / DGA**: High-entropy long subdomains (`T1071.004`, `T1048.003`).
- **C2 Beaconing**: Regular low-byte encrypted heartbeats (`T1071.001`, `T1041`).
- **Traffic Spike / DoS**: Abnormal traffic volume burst (`T1498`).
- **Data Exfiltration**: High outbound bytes ratio to external IP (`T1048.003`, `T1041`).
- **EICAR Test Artifact**: Standard anti-virus test string handled strictly as **inert text data** (`T1105`, `T1204`).
- **Benign Baseline**: Routine HTTPS & DNS traffic.

### 2. Machine Learning Performance Metrics
- **Isolation Forest Anomaly Detector**:
  - Precision: **0.9320** | Recall: **0.9354** | F1-Score: **0.9337**
- **XGBoost Multi-Class Classifier**:
  - Accuracy: **1.0000** across all 8 threat categories
  - Top Predictive Features: `payload_entropy`, `failed_attempts_log`, `unique_dst_ports_log`, `dns_subdomain_count`, `dns_query_length`.

### 3. XAI (Explainable AI) Engine
- **SHAP (`TreeExplainer`)**: Calculates exact per-feature attributions driving model predictions.
- **LIME (`LimeTabularExplainer`)**: Generates local decision rules.
- **Natural Language Generator**: Converts feature weights into human-readable SOC analyst summaries.

### 4. Incident Response Engine
- **State Machine**: Workflows (`new` → `investigating` → `contained` → `resolved`).
- **Automated Playbooks**: Recommends prioritized actions (e.g. `BLOCK_IP`, `QUARANTINE_HOST`, `LOCK_ACCOUNT`, `DLP_REVIEW`).
- **Audit Trail**: Preserves complete timestamped history of analyst state transitions.

---

## Quickstart Guide

### 1. Run Master System Verification Suite
You can verify the entire platform (ML, threat intel, database, FastAPI server endpoints, and frontend build) with one command:
```bash
python scripts/verify_full_system.py
```

### 2. Local Development Setup

#### Backend (FastAPI + ML)
```bash
cd backend
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
> **Note**: The backend automatically initializes DB tables and seeds sample events & analyst credentials on startup (`analyst@threatintel.io` / `Cyber2026!`).

#### Frontend (React 18 + Vite)
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## Docker Compose Deployment

To build and run the entire stack (PostgreSQL + FastAPI Backend + Nginx Frontend) in production mode:
```bash
docker compose up --build -d
```
Access the application at [http://localhost](http://localhost).

---

## Safety Constraints
- All attack network events are synthetic/simulated behavioral patterns.
- The standard EICAR test string is handled strictly as **inert text data** — never executed as binary code.
- Response actions (IP blocking, host isolation) are **logged recommendations only**.
- Public demo mode provides interactive exploration without modifying production infrastructure.
