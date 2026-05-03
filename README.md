🛡️ NIDS — Network Intrusion Detection System

A full-stack cybersecurity platform that monitors network traffic in real-time, detects threats using rule-based logic and AI anomaly detection, and visualizes them on a live SOC-style dashboard.

---

## 🚀 Features

- 🔍 Real-time packet capture (Scapy + Demo Mode)
- 🧠 Dual detection engine:
  - Rule-based detection (Port scan, Brute force, DDoS, etc.)
  - AI anomaly detection (Isolation Forest)
- 📊 Live SOC Dashboard (Chart.js + WebSockets)
- 🌍 Geo-IP attack tracking (Leaflet.js world map)
- ⚡ Attack simulator (Port scan & Brute force)
- 🚫 Auto IP blocking for critical threats
- 🔐 JWT authentication (Admin & Analyst roles)
- 🖧 LAN Network Scanner (Device discovery + port scan)
- 📄 PDF & CSV report generation

---

## 🏗️ Architecture


Network Traffic
↓
Packet Capture (Scapy)
↓
Detection Engine
├── Rule-based
└── AI (Isolation Forest)
↓
Response Engine (Auto Block)
↓
Database (PostgreSQL)
↓
Flask API + WebSockets
↓
Frontend Dashboard


---

## ⚙️ Tech Stack

| Layer | Technology |
|------|-----------|
| Backend | Python, Flask, Flask-SocketIO |
| Database | PostgreSQL, SQLAlchemy |
| Packet Capture | Scapy |
| AI/ML | scikit-learn (Isolation Forest) |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Maps | Leaflet.js |
| Auth | JWT, bcrypt |

---

## 📂 Project Structure


nids/
│
├── backend/
│ ├── app.py
│ ├── auth.py
│ ├── database.py
│ ├── detector.py
│ ├── geoip.py
│ ├── network_mapper.py
│ ├── reporter.py
│ └── sniffer.py
│
├── frontend/
│ ├── templates/
│ │ ├── index.html
│ │ └── login.html
│ └── static/
│ ├── css/
│ └── js/
│
├── requirements.txt
└── README.md


---

## 🚀 Installation & Setup

### 1. Clone Repository

```bash
git clone https://github.com/shivamkushwaha1576/nids-project.git
cd nids-project
2. Create Virtual Environment
python -m venv .venv
.venv\Scripts\activate   # Windows
3. Install Dependencies
pip install -r requirements.txt
4. Setup Database (PostgreSQL)
CREATE DATABASE nids_db;
5. Run Project
cd backend
python app.py
🌍 Deployment
Service	Platform
Backend	Render
Frontend	Netlify
Database	Neon PostgreSQL
🔐 Authentication
Role	Access
Admin	Full access
Analyst	Read-only
🧠 Detection Engine
Rule-Based Detection
Port Scan
Brute Force
DDoS Attack
Payload Injection
AI Detection
Isolation Forest (Unsupervised Learning)
Detects anomalies without labeled data
📊 Reports
CSV Export
PDF Threat Reports
🎯 Key Highlights
Real-time cybersecurity monitoring
AI-powered anomaly detection
Auto-response system (IP blocking)
Full-stack development with live dashboard
💼 Resume Description

Developed a full-stack Network Intrusion Detection System (NIDS) with real-time packet analysis using Scapy, AI-based anomaly detection (Isolation Forest), and automated threat response with IP blocking, visualized through a live SOC dashboard.

🙌 Author

Shivam Kushwaha

GitHub: https://github.com/shivamkushwaha1576
