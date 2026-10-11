# VORTEX-SDN
## AI-Driven Software-Defined Network Controller for Intelligent Network Security & Quality of Service Management

![VORTEX-SDN Architecture](https://img.shields.io/badge/Platform-SDN%20OpenFlow%201.3-00f2fe)
![Security Layer](https://img.shields.io/badge/Security-RandomForest%20%2B%20IsolationForest-ef4444)
![QoS Layer](https://img.shields.io/badge/QoS-Multi--Class%20Priority%20Queues-10b981)
![Backend](https://img.shields.io/badge/Backend-Python%20Flask-38bdf8)
![Frontend](https://img.shields.io/badge/Frontend-Vanilla%20HTML%2FCSS%2FJS-a855f7)

---

## 1. System Overview

**VORTEX-SDN** is an enterprise-grade Software-Defined Networking (SDN) platform combining OpenFlow 1.3 control orchestration, delta-counter telemetry monitoring, dual-layer Machine Learning intelligence (Threat Detection & QoS Classification), automated OpenFlow mitigation, context-aware VORTEX AI assistant, and a Cisco NOC-inspired operations dashboard.

```
                ┌──────────────────────────────────────────────┐
                │          VORTEX-SDN NOC DASHBOARD            │
                │        (HTML5 / Vanilla CSS / JS)            │
                └──────────────────────┬───────────────────────┘
                                       │ REST APIs / Polling
                ┌──────────────────────▼───────────────────────┐
                │         Python Flask Backend Server          │
                │              (127.0.0.1:5000)                │
                └──────────────────────┬───────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
         ▼                             ▼                             ▼
   SDN Controller              Telemetry Engine                  AI Engine
  Ryu (OpenFlow 1.3)          Delta Rate Monitor           Random Forest + IsoForest
         │                             │                             │
         ▼                             ▼                             ▼
      Mininet                   Security Detector             QoS Classifier
 (4 OVS + 4 Hosts)             Threat Risk Scoring           EF / AF / BE Queues
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
                                   Decisions
                                       │
                                       ▼
                     Automated OpenFlow Actions (DROP / RATE_LIMIT)
```

---

## 2. Key Intelligence Layers

### Layer 1: Security Intelligence
- **Threat Categories**: `DDOS`, `PORT_SCAN`, `BRUTE_FORCE`, `FLOOD`, `ANOMALY`, `BENIGN`.
- **Model**: Multi-Class `RandomForestClassifier` + Unsupervised `IsolationForest`.
- **Features**: `packet_rate`, `byte_rate`, `packets`, `bytes`, `flow_duration`, `source_port`, `destination_port`, `protocol_num`, `unique_destinations`, `connection_frequency`, `packet_size`, `destination_frequency`, `source_frequency`.
- **Mitigation Modes**: `LIVE_MITIGATION` and `DRY_RUN`.
- **OpenFlow Actions**: `BLOCK` (Drop rule), `RATE_LIMIT` (OpenFlow meter), `ISOLATE` (Quarantine VLAN), `MONITOR`.

### Layer 2: QoS Intelligence
- **Traffic Classes**: `VOICE` (EF), `VIDEO` (AF), `WEB` (AF), `FILE_TRANSFER` (BE), `EMAIL` (BE), `P2P` (BE), `CRITICAL` (EF), `BEST_EFFORT` (BE).
- **QoS Metrics**: Latency (ms), Jitter (ms), Packet Loss (%), Bandwidth Utilization (%), SLA Violations.
- **Dynamic Policy Enforcement**: Prioritizes latency-sensitive VoIP/Critical flows and rate-limits bulk P2P flows.

---

## 3. Real Telemetry Rate Calculation

OpenFlow cumulative counters are converted to exact live rates using counter deltas:
$$\text{packet\_rate} = \frac{\text{current\_packets} - \text{previous\_packets}}{\text{elapsed\_seconds}}$$
$$\text{byte\_rate} = \frac{\text{current\_bytes} - \text{previous\_bytes}}{\text{elapsed\_seconds}}$$

Telemetry freshness tracking accurately reflects:
- `● TELEMETRY LIVE (2s ago)` when actively updating.
- `● DEMO SIMULATION (2s ago)` in demo mode.
- `● TELEMETRY STALE` if updates pause.
- `● TELEMETRY DISCONNECTED` if the backend is unreachable.

---

## 4. Project Structure

```
VORTEX-SDN/
├── backend/
│   ├── api/
│   │   ├── server.py              # Flask server on 127.0.0.1:5000
│   │   ├── auth.py                # Authentication & session token API
│   │   ├── telemetry_api.py       # Telemetry, flows, and summary API
│   │   ├── topology_api.py        # Topology and devices API
│   │   ├── security_api.py        # Threat feeds and mitigation API
│   │   ├── qos_api.py             # QoS metrics and policies API
│   │   ├── ai_api.py              # AI metrics and predictor sandbox API
│   │   ├── chat_api.py            # VORTEX AI Assistant chatbot API
│   │   ├── incident_api.py        # Incident management lifecycle API
│   │   ├── policy_api.py          # CRUD for QoS and Security rules
│   │   ├── audit_api.py           # Tamper-evident audit trail API
│   │   ├── settings_api.py        # User settings & profile persistence API
│   │   ├── notification_api.py    # System notifications API
│   │   └── demo_api.py            # Simulation scenario control API
│   ├── services/
│   │   ├── telemetry_service.py   # Aggregated KPI calculator
│   │   ├── topology_service.py    # Network graph generator
│   │   ├── incident_service.py    # Incident DB manager
│   │   ├── audit_service.py       # Audit trail recorder
│   │   ├── notification_service.py# Notification dispatcher
│   │   └── demo_engine.py         # 8 stateful simulation scenarios
│   └── models/
│       └── database.py            # SQLite schema (Users, Incidents, Policies, Audit)
│
├── controller/
│   └── vortex_controller.py       # Enterprise Ryu OpenFlow 1.3 controller app
│
├── network/
│   ├── topologies/
│   │   └── vortex_topology.py     # 4-switch OVS mesh Mininet topology
│   └── traffic/
│       └── traffic_generator.py   # Benign and attack traffic generator
│
├── telemetry/
│   └── flow_monitor.py            # Exact delta rate monitor & circular buffer
│
├── security/
│   ├── detector.py                # Threat evaluator & incident generator
│   ├── feature_engineering.py     # Feature vector normalizer
│   └── mitigation.py              # OpenFlow action dispatcher & audit logger
│
├── qos/
│   ├── classifier.py              # Flow QoS tagger
│   ├── policy_engine.py           # Policy matcher & SLA evaluator
│   └── queue_manager.py           # OpenFlow queue mapper
│
├── ai/
│   ├── generate_datasets.py       # Synthetic dataset generator (6,000 samples)
│   ├── train_security_model.py    # Security model trainer (RandomForest + IsoForest)
│   ├── train_qos_model.py         # QoS model trainer (Multi-Class RF)
│   ├── inference.py               # Singleton high-speed inference engine
│   └── models/                    # Serialized joblib artifacts & metrics JSON
│
├── chatbot/
│   ├── assistant.py               # Context-aware conversational engine
│   └── intent_engine.py           # Regex intent classifier
│
├── frontend/
│   ├── index.html                 # Main single-page application
│   ├── login.html                 # NOC Login portal
│   ├── register.html              # Operator Registration portal
│   ├── css/                       # Modular CSS (variables, base, layout, sidebar, topbar, cards, etc.)
│   └── js/                        # Modular JavaScript (api, auth, state, charts, topology, security, qos, etc.)
│
├── data/                          # SQLite DB, CSV datasets, JSON telemetry
├── tests/
│   └── test_vortex.py             # Automated pytest test suite
├── requirements.txt
├── run_vortex.py                  # Master launcher CLI
└── README.md
```

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10+ (Tested on Python 3.10 - 3.14)
- Windows, macOS, or Linux / WSL

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Generate Datasets & Train Machine Learning Models
```powershell
python run_vortex.py --train
```

### 3. Run Automated Tests
```powershell
python run_vortex.py --test
```

### 4. Start VORTEX-SDN Platform
```powershell
python run_vortex.py
```
*The web browser will automatically open to `http://127.0.0.1:5000`.*

---

## 6. Authentication & User Provisioning

VORTEX-SDN uses real database accounts with salted SHA-256 password hashing, real Gmail SMTP email verification, and secure password reset.

- **Registration**: Visit `/register` to create a new operator, administrator, or viewer account.
- **Email Verification**: When SMTP is configured, an activation link is sent to the registered email address.
- **Password Reset**: Visit `/forgot-password` to request a secure 30-minute password reset link.
- **SMTP Configuration**: Configure SMTP credentials in `.env` (see `.env.example`).

---

## 7. Demo Scenarios

The platform includes 8 interactive stateful simulation scenarios available under **Demo Scenarios**:

1. **NORMAL NETWORK**: Stable baseline flows across 4 hosts. 0% loss, ~14ms latency, 100% health.
2. **DDoS ATTACK**: High-rate UDP flood from `h4` (10.0.0.4) to `h1` (10.0.0.1). AI detects CRITICAL attack, triggers alert and opens incident.
3. **PORT SCAN**: Multi-port probe across ports 20..8080 from `h4`. AI flags PORT_SCAN anomaly.
4. **BRUTE FORCE**: Rapid authentication burst against SSH port 22 on `h2`. AI flags HIGH threat.
5. **NETWORK CONGESTION**: Heavy bulk FTP saturates link bandwidth (92%), latency rises, loss hits 3.8%.
6. **QOS DEGRADATION**: Jitter spikes to 28ms, voice/video degraded, QoS engine flags SLA violations.
7. **HIGH LATENCY**: Link transit delay spikes to 90ms+.
8. **RECOVERY**: OpenFlow DROP/RATE_LIMIT rules clear attack streams, network health recovers to 98%.

---

## 8. Running with Ryu & Mininet (Linux / WSL)

To connect VORTEX-SDN to live Open vSwitch switches in Mininet:

### Terminal 1: Launch Ryu Controller
```bash
ryu-manager controller/vortex_controller.py --ofp-tcp-listen-port 6653
```

### Terminal 2: Launch Mininet 4-Switch Mesh Topology
```bash
sudo python network/topologies/vortex_topology.py
```

### Terminal 3: Launch VORTEX Backend
```bash
python run_vortex.py --server
```

---

## 9. VORTEX AI Assistant

The floating assistant widget understands natural language queries grounded directly in live backend state:
- *"What is the current network health?"*
- *"Are there any active threats?"*
- *"Why is QoS health at this level?"*
- *"Which host is generating the most traffic?"*
- *"Explain critical security alerts and mitigation steps."*
- *"Show topology and controller status."*

---

## 10. License
VORTEX-SDN is released under the MIT Open Source License.
