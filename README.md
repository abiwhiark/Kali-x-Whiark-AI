# Kali x Whiark AI — Autonomous Cybersecurity Operator

> **College Cybersecurity Project**  
> An autonomous, modular, AI-powered cybersecurity operator (Terminal Agent & Chatbot: **Kali AI**) inspired by HexStrike AI and modern offensive/defensive architectures. Powered by **Google Gemini API** native function calling and local model support (Ollama) with an independent Python execution controller, real security tool registry, security validator, and reactive dashboard.

---

## 1. Architectural Philosophy

Kali AI is **our own agent architecture**. We do not use Gemini CLI, nor do we run a pre-packaged agent:

```
                  USER (Web Browser)
                         │
                         ▼
             React + Vite Frontend Dashboard
          (AI Chat, Activity Stream, Plan, Findings)
                         │
             SSE / REST  ▼
            FastAPI Backend Controller
                         │
      ┌──────────────────┴──────────────────┐
      │                                     │
      ▼                                     ▼
Google Gemini API                   SQLite Database
(Reasoning Brain &             (Audit Trail, Assessments,
Function Calling)                       Findings)
      │
      │ 1. AI requests tool via Function Call
      ▼
Security Tool Registry
(7 Registered Tools & JSON Schemas)
      │
      │ 2. Independent Verification
      ▼
Security Validator
(Target CIDR, Allowed Tools, Parameter Schemas, Max Iterations)
      │
      │ 3. Approved Execution
      ▼
Tool Execution Controller
(Mock Phase 1 -> Subprocess / Kali Linux Binaries)
      │
      │ 4. Structured Results & Normalized Findings
      ▼
Finding Normalizer & Correlator
(Deduplication, Risk Scoring, Cross-Tool Evidence)
      │
      │ 5. Results Feed Back to Gemini
      ▼
Gemini Adaptive Decision Loop
(Analyze evidence -> Decide next action -> Final Report)
```

- **Brain**: Google Gemini (via `google-genai` SDK and native tool calling).
- **Controller**: Our Python FastAPI agent backend.
- **Capabilities**: Pre-defined, strictly constrained security tool wrappers.
- **Execution Environment**: Authorized Kali Linux or local laboratory.
- **Safety Boundary**: Security Validator prevents arbitrary command injection, restricts targets to authorized subnets, and enforces loop boundaries.

---

## 2. Security Tool Registry

The agent interacts **only** with registered tool definitions — never arbitrary shell strings:

| Tool ID | Name | Category | Primary Purpose | Risk Level |
| :--- | :--- | :--- | :--- | :--- |
| `nmap_scan` | Nmap Scanner | Reconnaissance | Port discovery, exposed services, OS guess | Medium |
| `whatweb_scan` | WhatWeb Analyzer | Web Analysis | Web server, CMS, language, framework detection | Low |
| `nuclei_scan` | Nuclei Scanner | Vulnerability Scan | Template-based detection of known CVEs & exposures | Medium |
| `nikto_scan` | Nikto Scanner | Web Analysis | Server misconfigurations & dangerous files | Medium |
| `sslyze_scan` | SSLyze Analyzer | SSL/TLS | Protocol versions, ciphers, certificate validation | Low |
| `zap_scan` | OWASP ZAP Scanner | Web Analysis | Passive/active web application security checks | High |
| `gobuster_scan` | Gobuster Directory | Discovery | Controlled wordlist-based endpoint discovery | Medium |

---

## 3. Defense-in-Depth Security Controls

The agent controller enforces mandatory restrictions that the LLM cannot override:
1. **Target Allowlisting**: Only hostnames or IP addresses inside `ALLOWED_TARGETS` (e.g., `127.0.0.1`, `localhost`, RFC1918 private subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) can be scanned.
2. **Strict Parameter Validation**: Arguments are validated against explicit JSON Schemas and enums before execution.
3. **Execution Limits**: Hard upper bounds on loop iterations (`MAX_AGENT_ITERATIONS = 10`) and total tool calls (`MAX_TOOL_CALLS = 15`) prevent infinite recursion.
4. **Timeouts**: Every tool execution is wrapped in an async timeout.
5. **Demonstration Mode**: Clearly distinguished mock execution when no Gemini API key is configured.

---

## 4. Quickstart Guide

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Node.js 18+ (tested on Node.js 24)
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd "kali ai"
   ```

2. **Configure Environment Variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env`:
   - Set `GEMINI_API_KEY=your_key_here` to enable live Gemini intelligence.
   - Leave empty to run in **Demonstration Mode**.

3. **Install Backend Dependencies:**
   ```bash
   python -m pip install -r backend/requirements.txt
   ```

4. **Install Frontend Dependencies:**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

---

## 5. Running the Application

### 🖥️ Terminal CLI (NEW — Recommended for quick use):
```bash
# Interactive REPL — full shell with colored output
python cli.py

# One-shot scan without entering the REPL
python cli.py -o "nmap scan" -t localhost
python cli.py -o "full security assessment" -t 192.168.1.1
python cli.py -o "check ssl" -t mysite.com --no-color

# In-REPL commands:
#   help            → Show all commands
#   tools           → List all security tools
#   target <host>   → Set a persistent scan target
#   quit / exit     → Exit
```

### Start the Backend (Terminal 1):
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
API Docs available at: [http://localhost:8000/docs](http://localhost:8000/docs)

### Start the Frontend (Terminal 2):
```bash
cd frontend
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 6. Running Tests

Run the backend unit and integration test suite:
```bash
python -m pytest backend/tests -v
```

Run the frontend production build test:
```bash
cd frontend
npm run build
```

---

## 7. Project Structure

```
kali ai/
├── backend/
│   ├── main.py                     # FastAPI application entrypoint
│   ├── requirements.txt            # Python dependencies
│   ├── api/
│   │   └── routes.py               # REST endpoints & SSE chat stream
│   ├── core/
│   │   └── config.py               # Pydantic Settings & environment config
│   ├── database/
│   │   └── db.py                   # Async SQLite storage
│   ├── models/
│   │   └── schemas.py              # Pydantic schemas (Finding, Assessment, Tools)
│   ├── services/
│   │   ├── agent/
│   │   │   └── orchestrator.py     # Core autonomous decision loop
│   │   ├── gemini/
│   │   │   └── client.py           # Gemini SDK & Demo client
│   │   ├── tool_registry/
│   │   │   └── registry.py         # Tool definitions & executors
│   │   ├── security/
│   │   │   └── validator.py        # Target & parameter security validation
│   │   ├── analysis/
│   │   │   ├── normalizer.py       # Finding extraction from tool outputs
│   │   │   └── correlator.py       # Deduplication, correlation, & risk scoring
│   │   └── reporting/
│   │       └── generator.py        # Markdown report generation
│   └── tests/                      # Pytest test suite (38 unit/integration tests)
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── index.css
│       ├── api.js                  # SSE stream parser & fetch helpers
│       ├── App.jsx                 # Main dashboard UI
│       └── components/
│           └── Sidebar.jsx         # Plan, Activity, Findings, Tools, History tabs
├── .env.example
├── .gitignore
├── pytest.ini
└── README.md
```

---

## 8. Development Roadmap

- [x] **Stage 1 — Gemini Agent Foundation**: Tool registry, security validator, mock tools, autonomous decision loop, finding normalization, correlation, risk scoring, report generator, SQLite history, React dashboard with real-time SSE streaming.
- [x] **Stage 2 — Initial Kali Tool Integration & HexStrike Terminal Model**: Real sub-process wrappers for **Nmap**, **WhatWeb**, and **Nuclei** with automatic binary detection and graceful fallback; unified Terminal REPL (`cli.py`) offering dual conversational chat (like Gemini / ChatGPT) and autonomous tool execution (like HexStrike AI).
- [ ] **Stage 3 — Extended Web & TLS Tools**: Sub-process wrappers for Nikto and SSLyze.
- [ ] **Stage 4 — Deep Assessment Tools**: OWASP ZAP API integration and rate-limited Gobuster.
- [ ] **Stage 5 — Advanced Adaptive Engine**: Multi-vector attack surface graphs and MITRE ATT&CK mapping.
