# 🛡️ SentinelShield AI: Cloud & AI Threat Detection & Monitoring System

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.143-emerald.svg)
![ML](https://img.shields.io/badge/ML-IsolationForest-indigo.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-v14.1-orange.svg)

**SentinelShield AI** is an enterprise-grade, real-time threat detection, security telemetry monitoring, and automated incident response platform built for multi-cloud environments (AWS, Azure, GCP, Kubernetes) and AI LLM Gateway services.

---

## 🌟 Key Features

1. **Multi-Source Cloud & AI Telemetry Ingestion**:
   - **Cloud Audit Logs**: AWS CloudTrail, Azure Activity, GCP Audit, Kubernetes Audit Logs.
   - **AI Gateway Telemetry**: LLM API key abuse, adversarial prompt injections, token exfiltration, system prompt leakage, and jailbreak attempts.
   - **Network & IAM Telemetry**: Impossible travel access, unauthorized privilege escalations, and bulk data exfiltration.

2. **Hybrid Dual-Detection Engine**:
   - **Signature & Heuristic Rule Engine (MITRE ATT&CK & OWASP LLM Top 10)**: Real-time pattern matching for IAM escalation, S3 public exposure, K8s HostPath container escapes, and secret manager bulk reads.
   - **Machine Learning Anomaly Detector**: Unsupervised `IsolationForest` (scikit-learn) and multi-dimensional feature extraction producing a dynamic 0.0 - 100.0 Anomaly Index Score for every log event.

3. **AI Security Incident Synthesizer**:
   - Automated root-cause analysis, risk confidence scoring, potential impact assessment, and 1-click execution of automated CLI remediation playbooks (`aws iam detach-user-policy`, `kubectl delete pod`, `iptables block`).

4. **Interactive Real-Time SOC Command Dashboard**:
   - **Live Telemetry Stream**: Event stream powered by Server-Sent Events (SSE).
   - **Attack Scenario Simulator**: 1-click injection of live cyber attack vectors to benchmark detection rules.
   - **Threat Analytics Charts**: Attack vector distribution (Chart.js) and MITRE ATT&CK matrix coverage heatmap.

---

## 📁 System Architecture

```
ai-cloud-threat-monitor/
├── app/
│   ├── main.py                   # FastAPI server & SSE stream controller
│   ├── config.py                 # Configuration settings & threat thresholds
│   ├── models/
│   │   └── schemas.py            # Pydantic schemas (LogEvent, SecurityAlert, Metrics)
│   ├── core/
│   │   ├── database.py           # In-memory threat database & seed telemetry
│   │   ├── rules_engine.py       # Signature threat detection engine (MITRE mapped)
│   │   ├── ml_engine.py          # Isolation Forest ML anomaly model
│   │   ├── ai_analyst.py         # AI Root-Cause Synthesis & Remediation generator
│   │   └── simulator.py          # Synthetic telemetry stream & attack injector
│   ├── api/
│   │   ├── dashboard.py          # Dashboard analytics & MITRE endpoints
│   │   ├── logs.py               # Log ingestion & query endpoints
│   │   ├── alerts.py             # Alert lifecycle & mitigation endpoints
│   │   └── simulation.py         # Simulation controls & attack scenario injector
│   └── static/
│       ├── index.html            # Real-Time SOC Command Dashboard UI
│       ├── css/style.css         # Dark theme cybersecurity styling
│       └── js/app.js             # SSE controller, Chart.js & interactive modal handlers
├── tests/                        # Automated unit tests
├── Dockerfile                    # Container configuration
├── docker-compose.yml            # Docker deployment configuration
└── requirements.txt              # Python dependencies
```

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- `pip` package manager

### 1. Installation
Navigate to the project folder:
```bash
cd "C:\Users\ADITYA SINGH\.gemini\antigravity\scratch\ai-cloud-threat-monitor"
```

Install dependencies:
```bash
python -m pip install -r requirements.txt
```

### 2. Launch the Application
Run the FastAPI web server:
```bash
python -m uvicorn app.main:app --reload --port 8000
```

Open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🔌 API Endpoints Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **GET** | `/` | Serves the interactive Web Monitoring Dashboard |
| **GET** | `/api/stream` | Server-Sent Events (SSE) stream for live telemetry |
| **GET** | `/api/dashboard/stats` | System overview stats & anomaly index metrics |
| **GET** | `/api/dashboard/mitre-coverage` | MITRE ATT&CK tactics detection coverage |
| **GET** | `/api/alerts` | Query active security alerts with filters |
| **GET** | `/api/alerts/{id}` | Get full AI analysis & remediation playbook for alert |
| **POST** | `/api/alerts/{id}/mitigate` | Execute 1-click automated mitigation playbook |
| **POST** | `/api/logs/ingest` | Ingest raw CloudTrail/K8s/AI Gateway log payload |
| **POST** | `/api/simulation/inject-attack` | Inject targeted attack scenario into live pipeline |

---

## 🐳 Docker Deployment

To build and run using Docker Compose:
```bash
docker-compose up --build -d
```
Access the application at `http://localhost:8000`.

---

## 🧪 Running Unit Tests

To run the test suite:
```bash
python -m pytest tests/
```

---

## 📄 License
MIT License - Open Source Security Project.
