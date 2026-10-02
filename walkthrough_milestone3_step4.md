# ThreatLens AI — Milestone 3, Step 4: Behavioral Analysis System

## Executive Overview
ThreatLens AI Milestone 3, Step 4 implements a dedicated, telemetry-driven **Behavioral Analysis System**. This system ingests, normalizes, stores, and evaluates security telemetry (process spawning, file modifications, registry changes, network sockets, injection attempts, and persistence mechanisms) into objective behavioral indicators. It calculates a rule-based **Behavioral Risk Score** (0–100) and **Behavioral Risk Level** (LOW, MEDIUM, HIGH, CRITICAL), fuses findings with the static EMBER ML prediction into a unified **Threat Risk Score**, and triggers explicit SOC alerts without ever executing binaries on the host system.

---

## 1. Existing Behavioral Architecture Audit
Before Step 4, the repository possessed:
- A rudimentary MITRE technique mapping dictionary (9 hardcoded tags) in `backend/app/services/behavioral_service.py`.
- Embedded storage of raw telemetry within scan records in `storage/db.json` without normalized event decoupling.
- A single ingestion endpoint `POST /api/scans/{scan_id}/behavioral`.
- Static analysis cards and MITRE technique badges in the frontend.

**What Step 4 Added:**
- Normalized behavioral event schema supporting 14 event types across 6 major operational categories.
- Dedicated `BehavioralAnalysisEngine` in `backend/app/services/behavioral_analysis_service.py`.
- Dedicated storage collection `behavioral_events` in `storage/db.json` with scan and file association.
- Dedicated REST API routes in `backend/app/api/routes/behavioral.py` (`GET /api/behavioral/{scan_id}`, `GET /api/behavioral/{scan_id}/summary`, `POST /api/behavioral/events`).
- Transparent, documented rule-based risk scoring and combined "Threat Risk Score" calculation.
- Automated behavioral alert generation on high/critical telemetry triggers.
- Clean frontend UI card rendering Behavioral Risk Scores, Activity counts, and analytical indicators in `FileAnalysisPage.tsx`.

---

## 2. New & Modified Components

| File | Type | Role |
|---|:---:|---|
| [backend/app/services/behavioral_analysis_service.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/services/behavioral_analysis_service.py) | **NEW** | Core analytical engine, indicator rules, risk score calculations, and legacy telemetry converter |
| [backend/app/api/routes/behavioral.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/api/routes/behavioral.py) | **NEW** | REST endpoints for event ingestion, reports, and summary metrics |
| [backend/tests/test_behavioral_analysis.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/tests/test_behavioral_analysis.py) | **NEW** | Automated test suite verifying 9 core behavioral capabilities |
| [backend/app/schemas/scan.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/schemas/scan.py) | **MODIFIED** | Added `BehavioralEvent`, `BehavioralEventSubmission`, `BehavioralSummaryResponse`, and enhanced report fields |
| [backend/app/services/db.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/services/db.py) | **MODIFIED** | Added `behavioral_events` table and persistence helpers |
| [backend/app/services/behavioral_service.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/services/behavioral_service.py) | **MODIFIED** | Bridged legacy functions to delegate to `BehavioralAnalysisEngine` |
| [backend/app/api/routes/scans.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/api/routes/scans.py) | **MODIFIED** | Persists incoming telemetry to `behavioral_events` and triggers behavioral alerts |
| [backend/app/main.py](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/backend/app/main.py) | **MODIFIED** | Registered `behavioral.router` under `/api` and `/api/v1` |
| [src/services/threatlensApi.ts](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/src/services/threatlensApi.ts) | **MODIFIED** | Added TypeScript interfaces and client methods (`getBehavioralReport`, `submitBehavioralEvents`) |
| [src/pages/FileAnalysisPage.tsx](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/src/pages/FileAnalysisPage.tsx) | **MODIFIED** | Added Behavioral Telemetry & Indicators section in report view |

---

## 3. Normalized Behavioral Event Schema

Every ingested behavioral event conforms to the following normalized structure:

```json
{
  "event_id": "uuid-v4-identifier",
  "scan_id": "associated-scan-uuid",
  "file_id": "optional-file-uuid",
  "timestamp": "2026-09-21T14:00:00Z",
  "event_type": "process_creation | file_modification | registry_modification | network_connection | injection_attempt | persistence_attempt | ...",
  "process_name": "notepad.exe",
  "parent_process": "cmd.exe",
  "target": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "source": "192.168.1.50",
  "destination": "198.51.100.45",
  "port": 4444,
  "command": "powershell.exe -enc ...",
  "severity": "low | medium | high | critical",
  "indicator": "T1055.012",
  "description": "Cross-process memory injection detected targeting svchost.exe.",
  "metadata": {}
}
```

### Supported Event Categories
1. **Process Activity**: `process_creation`, `process_termination`, `suspicious_command`
2. **File System Activity**: `file_creation`, `file_modification`, `file_deletion`
3. **Registry & Configuration**: `registry_modification`, `service_creation`
4. **Network Communications**: `network_connection`, `dns_request`
5. **Persistence & Auto-Start**: `persistence_attempt`
6. **Privilege & Defense Evasion**: `injection_attempt`, `privilege_escalation`, `suspicious_api`

---

## 4. Behavioral Indicators (Analytical Language)
All findings use objective, non-definitive security terminology:
- `IND-PROC-001` (Unusual Process Spawning): *"Detected behavioral indicator: Child process spawned under unexpected parameters or command flags requiring investigation."*
- `IND-PROC-002` (Process Injection): *"Process injection indicator observed: Cross-process memory manipulation or process hollowing behavior recorded in telemetry."*
- `IND-PERS-001` (Potential Persistence): *"Potential persistence behavior: Auto-start registry run key or scheduled startup modification observed."*
- `IND-NET-001` (Suspicious Network Connection): *"Suspicious outbound network connection observed contacting non-standard communication port or flagged C2 infrastructure."*
- `IND-FILE-001` (High-Frequency File Modification): *"High-frequency file modification indicator observed: Rapid file state mutations or potential bulk data alteration observed."*
- `IND-EVAS-001` (Security Control Tampering): *"Potential security control tampering observed: System recovery inhibition or telemetry suppression indicator detected."*

---

## 5. Risk Scoring Formula
The Behavioral Risk Score is calculated deterministically:

$$\text{Severity Points} = \sum_{\text{events}} w_{\text{sev}}(\text{event})$$
$$\text{Indicator Points} = \sum_{\text{indicators}} w_{\text{ind}}(\text{indicator})$$
$$\text{Behavioral Risk Score} = \min\left(100, \text{round}\left(0.4 \times \text{Severity Points} + 0.6 \times \text{Indicator Points}\right)\right)$$

### Severity Weights:
- `critical`: 35 points (event), 25 points (indicator)
- `high`: 25 points (event), 15 points (indicator)
- `medium`: 15 points (event), 10 points (indicator)
- `low`: 5 points (event), 5 points (indicator)

### Behavioral Risk Level Mapping:
- **0 – 39**: `LOW`
- **40 – 69**: `MEDIUM`
- **70 – 84**: `HIGH`
- **85 – 100**: `CRITICAL`

---

## 6. Combined Threat Risk Score Formula
The system fuses the static EMBER ML prediction and the behavioral telemetry into a single transparent score called **"Threat Risk Score"**:

$$\text{Threat Risk Score} = \begin{cases} \text{round}\left(0.5 \times \text{Static ML Score} + 0.5 \times \text{Behavioral Risk Score}\right), & \text{if telemetry exists} \\ \text{Static ML Score}, & \text{if no telemetry exists} \end{cases}$$

- `>= 70`: `MALICIOUS`
- `40 – 69`: `SUSPICIOUS`
- `< 40`: `BENIGN`

---

## 7. API Endpoints

1. `GET /api/behavioral/{scan_id}`: Retrieves the complete behavioral analysis report, detected indicators, severity distribution, category counts, and recommendations.
2. `GET /api/behavioral/{scan_id}/summary`: Retrieves concise behavioral metrics for dashboard cards and summary badges.
3. `POST /api/behavioral/events`: Ingests normalized behavioral events associated with a scan, saves them to storage, recalculates the scan's Threat Risk Score, and creates alerts if high-risk.
4. `POST /api/scans/{scan_id}/behavioral`: Backward-compatible telemetry ingestion endpoint.

---

## 8. Storage Layer
Stored in `storage/db.json` under the `behavioral_events` array. Each event record is indexed and queryable by `scan_id` and `file_id`.

---

## 9. Alert Integration
When telemetry yields a `behavioral_risk_level` of `HIGH` or `CRITICAL`, or detects critical indicators (e.g. Process Injection, Shadow Copy Deletion, C2 Sockets), a SOC alert is created automatically in `storage/db.json` with the title `Behavioral Alert: <Indicator Name> (<Filename>)` and specific incident response recommendations.

---

## 10. Frontend Integration
In [FileAnalysisPage.tsx](file:///c:/Users/dharanesh/OneDrive/Desktop/infy/src/pages/FileAnalysisPage.tsx), a dedicated **"Behavioral Telemetry & Indicators"** section appears whenever behavioral telemetry is associated with a scan:
- Shows Behavioral Risk Score & Risk Level badge.
- Displays activity counts for Spawned Processes, File Mutations, Registry Keys, and Network Sockets.
- Lists all detected behavioral indicators with severity badges and analytical descriptions.
- Displays prioritized investigation actions.

---

## 11. Security Considerations
- **Zero Host Execution**: The system treats telemetry strictly as incoming structured JSON data. No executables are detonated, launched, or sandboxed on the host.
- **Input Validation**: All payloads are strongly typed and validated through Pydantic schemas.
- **Data Isolation**: Events remain strictly partitioned by `scan_id`.

---

## 12. Testing & Verification Results
- **Automated Backend Tests**: **22 out of 22 passed** (`pytest` in 3.63s):
  - 7 dedicated behavioral tests in `test_behavioral_analysis.py`
  - 13 ML and scan tests in `test_malware_analysis.py`
  - 2 file management tests in `test_files.py`
- **Frontend Production Build**: `tsc -b && vite build` succeeded with exit code 0 in 2.34s.
- **Model Integrity Check**: SHA-256 hashes of all 5 protected model files were verified 100% untouched.

---

## 13. Limitations
- Behavioral analysis relies entirely on recorded telemetry feeds (e.g. from EDR agents, sandbox logs, or security gateways). It does not observe host kernels directly.
- Indicators represent analytical patterns and do not serve as standalone legal or forensic proof of malware in isolation.
