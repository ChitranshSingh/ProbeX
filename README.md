# ProbeX

> **This is a scoped-down solo prototype for an evaluation round — full
> architecture and team build plan will be in `docs/` (added later).**

ProbeX is a web-based **Dynamic Application Security Testing (DAST)** scanner
that runs entirely on localhost with zero external services besides an optional
Gemini API key.  It crawls a target web application, fuzzes discovered endpoints
with curated payloads, scores confidence, and generates context-aware AI
remediation — all surfaced in a React frontend over WebSockets.

---

## Run it locally

### Prerequisites

- Python 3.11+
- (Optional) A [Google Gemini API key](https://aistudio.google.com/) for AI remediation

### 1 — Clone and navigate

```bash
git clone <repo-url>
cd ProbeX/backend
```

### 2 — Create a virtual environment and install dependencies

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3 — Configure environment

```bash
# From the repo root
copy .env.example backend\.env        # Windows
# cp .env.example backend/.env        # macOS / Linux
```

Edit `backend/.env` and set `GEMINI_API_KEY` if you want AI-powered remediation.
Leave it blank to use the static offline fallback.

### 4 — Start the API server

```bash
# From the backend/ directory, with venv active
uvicorn app.main:app --reload
```

The server starts at **http://localhost:8000**.

### 5 — Verify it works

```bash
# Health check
curl http://localhost:8000/api/health
# Expected: {"status":"ok"}
```

Open **http://localhost:8000/docs** in your browser to see the interactive
OpenAPI UI and confirm all schemas render correctly.

### 6 — (Optional) Seed the example scan

```bash
# From the backend/ directory, with venv active
python -m seed.seed_example_scan
```

This inserts a synthetic demo scan into SQLite.  All seeded records carry
`is_example=true` so the frontend can clearly distinguish them from live scans.

---

## Project structure

```
probex/
├── backend/
│   ├── app/                    # FastAPI application
│   │   ├── main.py             # App factory, CORS, lifespan
│   │   ├── schemas.py          # Pydantic v2 request/response models
│   │   ├── api/
│   │   │   ├── scans.py        # POST/GET scan REST endpoints
│   │   │   └── ws.py           # WebSocket real-time stream
│   │   ├── core/
│   │   │   ├── config.py       # pydantic-settings config loader
│   │   │   └── runner.py       # Scan orchestration (engine pipeline)
│   │   └── db/
│   │       ├── models.py       # SQLModel ORM table definitions
│   │       ├── session.py      # Engine + session factory
│   │       └── crud.py         # DB helper functions
│   ├── engine/                 # Standalone DAST engine (zero FastAPI imports)
│   │   ├── models.py           # Plain dataclasses mirroring API schemas
│   │   ├── http_client.py      # Async HTTPX wrapper
│   │   ├── crawler.py          # BFS web crawler
│   │   ├── fuzzer.py           # Payload injection engine
│   │   ├── confidence.py       # Signal-based confidence scorer
│   │   ├── detectors/          # Per-vulnerability detector modules
│   │   └── reporter.py         # ScanResult assembler + risk scorer
│   ├── templates/
│   │   └── payloads/           # YAML payload templates (xss.yaml, sqli.yaml, …)
│   ├── ai/
│   │   ├── remediation.py      # Gemini API integration
│   │   ├── prompts.py          # Prompt templates
│   │   └── offline_fallback.py # CWE-keyed static remediation library
│   └── requirements.txt
├── frontend/                   # Scaffolded in Task S5
├── seed/
│   └── seed_example_scan.py    # Insert synthetic demo scan (Task S4)
├── .env.example
└── README.md
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Liveness probe |
| `POST` | `/api/scans` | Create and enqueue a scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{scan_id}` | Get scan with full findings |
| `WS` | `/ws/{scan_id}` | Real-time scan progress stream |

---

## Consent requirement

Every `POST /api/scans` request must include `"consent_confirmed": true`.  This
is a hard gate — requests with `false` are rejected with HTTP 422.  **Only scan
applications you own or have explicit written authorisation to test.**
