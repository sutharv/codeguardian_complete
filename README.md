# 🛡️ CodeGuardian

## Policy-Aware Secure Coding Assistant with LLM and Function Invocation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📖 Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Quick Start](#quick-start)
4. [Detailed Setup](#detailed-setup)
5. [Usage](#usage)
6. [API Reference](#api-reference)
7. [Architecture](#architecture)
8. [Project Structure](#project-structure)
9. [Supported Vulnerabilities](#supported-vulnerabilities)
10. [Authors](#authors)

---

## 🎯 Overview

CodeGuardian is an intelligent security assistant that combines traditional static analysis tools with LLM-powered contextual analysis. It detects security vulnerabilities in real-time and provides actionable remediation suggestions.

### Why CodeGuardian?

| Problem | CodeGuardian Solution |
|---------|----------------------|
| High false positive rates | LLM-based contextual filtering |
| No fix suggestions | AI-powered remediation with rationale |
| Disconnected from policies | Built-in OWASP, CWE compliance |
| Late vulnerability discovery | Real-time IDE integration |

---

## ✨ Features

- **🔍 Multi-Scanner Analysis** - Combines Bandit, Semgrep, and custom rules
- **🧠 LLM-Powered Analysis** - Reduces false positives, provides context
- **📋 Policy Compliance** - OWASP Top 10, CWE/SANS Top 25
- **💡 Smart Remediation** - Context-aware fix suggestions
- **⚡ Real-time Scanning** - IDE integration ready
- **🌐 REST API** - Easy integration with any tool
- **🖥️ Web Dashboard** - Beautiful UI for code analysis

---

## 🚀 Quick Start

```bash
# 1. Extract and navigate
cd codeguardian

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 3. Install everything
pip install -r requirements.txt

# 4. Start server
python -m uvicorn src.api.server:app --reload --port 8080

# 5. Open dashboard.html in browser
```

**Server running at:** http://127.0.0.1:8080

---

## 📋 Detailed Setup

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Git (optional)

### Step 1: Extract Project

Extract `codeguardian.zip` to your desired location.

### Step 2: Open Terminal

```bash
# Windows
cd C:\path\to\codeguardian

# Mac/Linux
cd /path/to/codeguardian
```

### Step 3: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows PowerShell)
venv\Scripts\activate

# Activate (Windows CMD)
venv\Scripts\activate.bat

# Activate (Mac/Linux)
source venv/bin/activate
```

You should see `(venv)` at the start of your command line.

### Step 4: Install Dependencies

```bash
# Install all requirements
pip install -r requirements.txt
```

This installs:
- FastAPI (web framework)
- Uvicorn (ASGI server)
- Bandit (Python security scanner)
- Semgrep (multi-language scanner)
- Anthropic SDK (LLM integration)
- Other utilities

### Step 5: Configure (Optional)

For AI-powered features, set your API key:

```bash
# Windows PowerShell
$env:ANTHROPIC_API_KEY="your-api-key-here"

# Mac/Linux
export ANTHROPIC_API_KEY="your-api-key-here"
```

### Step 6: Start the Server

```bash
python -m uvicorn src.api.server:app --reload --port 8080
```

**Expected Output:**
```
INFO:     Uvicorn running on http://127.0.0.1:8080
INFO:     Registered scanner: bandit
INFO:     Registered scanner: semgrep
INFO:     Loaded 14 policy rules
INFO:     Bandit scanner initialized successfully
INFO:     Semgrep scanner initialized successfully
INFO:     CodeGuardian API initialized successfully
INFO:     Application startup complete.
```

### Step 7: Open Dashboard

Open `dashboard.html` in your web browser.

---

## 💻 Usage

### Using the Web Dashboard

1. Open `dashboard.html` in your browser
2. Click **"🔍 Analyzer"** tab
3. Paste your code or click an example button
4. Click **"Analyze Code"**
5. View vulnerabilities and suggested fixes

### Using the API

#### Analyze Code

```bash
curl -X POST http://127.0.0.1:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
    "language": "python"
  }'
```

#### Check Health

```bash
curl http://127.0.0.1:8080/health
```

#### List Policies

```bash
curl http://127.0.0.1:8080/api/policy/list
```

### Using the CLI

```bash
# Analyze a file
python scripts/cli.py analyze your_code.py

# Quick snippet analysis
python scripts/cli.py quick "import pickle; pickle.loads(data)"

# List policies
python scripts/cli.py policies

# Start server
python scripts/cli.py server
```

---

## 📡 API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| GET | `/docs` | Swagger API documentation |
| POST | `/api/analyze` | Full security analysis |
| POST | `/api/analyze/realtime` | Fast analysis for IDE |
| POST | `/api/policy/check` | Policy compliance check |
| GET | `/api/policy/list` | List available policies |
| POST | `/api/remediate` | Generate fix suggestions |
| GET | `/api/scanners` | List active scanners |

### Request/Response Examples

#### POST /api/analyze

**Request:**
```json
{
  "code": "def get_user(id):\n    return db.execute(f'SELECT * FROM users WHERE id = {id}')",
  "language": "python",
  "policies": ["OWASP_TOP_10"],
  "include_remediation": true
}
```

**Response:**
```json
{
  "request_id": "REQ-ABC123",
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "category": "sql_injection",
      "severity": "critical",
      "title": "SQL Injection via string formatting",
      "description": "User input directly interpolated into SQL query",
      "location": {
        "file_path": "<input>",
        "start_line": 2,
        "end_line": 2
      },
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021-Injection"
    }
  ],
  "remediations": [
    {
      "vulnerability_id": "VULN-001",
      "suggested_fix": "db.execute('SELECT * FROM users WHERE id = %s', (id,))",
      "rationale": "Use parameterized queries to prevent SQL injection"
    }
  ],
  "analysis_time_ms": 245.5
}
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLIENT LAYER                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Dashboard  │  │  VSCode     │  │  CLI / curl         │  │
│  │  (HTML)     │  │  Extension  │  │                     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼─────────────────────┼────────────┘
          │                │                     │
          ▼                ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│                     API LAYER (FastAPI)                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  /api/analyze  │  /api/policy  │  /api/remediate    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    CORE ANALYZER                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Scanner    │  │  Policy     │  │  Remediation        │  │
│  │  Aggregator │  │  Engine     │  │  Generator          │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼─────────────────────┼────────────┘
          │                │                     │
          ▼                ▼                     ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────────────┐
│    SCANNERS     │ │   POLICIES  │ │      LLM (Claude)       │
│ ┌─────────────┐ │ │ ┌─────────┐ │ │  ┌───────────────────┐  │
│ │   Bandit    │ │ │ │ OWASP   │ │ │  │ False Positive    │  │
│ ├─────────────┤ │ │ ├─────────┤ │ │  │ Reduction         │  │
│ │   Semgrep   │ │ │ │ CWE     │ │ │  ├───────────────────┤  │
│ ├─────────────┤ │ │ ├─────────┤ │ │  │ Context Analysis  │  │
│ │   Custom    │ │ │ │ Custom  │ │ │  ├───────────────────┤  │
│ └─────────────┘ │ │ └─────────┘ │ │  │ Fix Generation    │  │
└─────────────────┘ └─────────────┘ │  └───────────────────┘  │
                                    └─────────────────────────┘
```

---

## 📁 Project Structure

```
codeguardian/
│
├── 📄 README.md                 # This file
├── 📄 requirements.txt          # Python dependencies
├── 📄 pyproject.toml           # Project configuration
├── 📄 dashboard.html           # Web UI (open in browser)
├── 📄 Dockerfile               # Container deployment
├── 📄 docker-compose.yml       # Container orchestration
│
├── 📁 src/                     # Source code
│   ├── 📄 __init__.py
│   │
│   ├── 📁 api/                 # REST API
│   │   ├── 📄 __init__.py
│   │   └── 📄 server.py        # FastAPI server
│   │
│   ├── 📁 core/                # Core logic
│   │   ├── 📄 __init__.py
│   │   ├── 📄 analyzer.py      # Main analyzer
│   │   ├── 📄 models.py        # Data models
│   │   └── 📄 utils.py         # Utilities
│   │
│   ├── 📁 scanners/            # Security scanners
│   │   ├── 📄 __init__.py
│   │   ├── 📄 base.py          # Base interface
│   │   ├── 📄 bandit_scanner.py
│   │   ├── 📄 semgrep_scanner.py
│   │   └── 📄 aggregator.py    # Combines results
│   │
│   ├── 📁 policy/              # Policy engine
│   │   ├── 📄 __init__.py
│   │   └── 📄 engine.py        # OWASP/CWE rules
│   │
│   └── 📁 remediation/         # Fix suggestions
│       ├── 📄 __init__.py
│       └── 📄 generator.py     # AI-powered fixes
│
├── 📁 configs/                 # Configuration
│   ├── 📄 config.yaml          # Main config
│   └── 📁 policies/            # Custom policies
│       └── 📄 custom_policy.json
│
├── 📁 scripts/                 # CLI tools
│   └── 📄 cli.py               # Command-line interface
│
├── 📁 tests/                   # Test suite
│   └── 📄 test_codeguardian.py
│
└── 📁 docs/                    # Documentation
    └── 📄 API.md
```

---

## 🔒 Supported Vulnerabilities

### By Category

| Category | CWE | OWASP | Description |
|----------|-----|-------|-------------|
| SQL Injection | CWE-89 | A03:2021 | Database query manipulation |
| Command Injection | CWE-78 | A03:2021 | OS command execution |
| XSS | CWE-79 | A03:2021 | Cross-site scripting |
| Path Traversal | CWE-22 | A01:2021 | Directory traversal |
| Hardcoded Secrets | CWE-798 | A07:2021 | Embedded credentials |
| Insecure Deserialization | CWE-502 | A08:2021 | Unsafe object handling |
| Broken Authentication | CWE-287 | A07:2021 | Auth mechanism flaws |
| SSRF | CWE-918 | A10:2021 | Server-side request forgery |
| Weak Cryptography | CWE-327 | A02:2021 | Insecure algorithms |

### Supported Languages

- ✅ Python
- ✅ JavaScript
- ✅ TypeScript
- ✅ Java
- ✅ Go
- ✅ Rust (partial)

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

---

## 🐳 Docker Deployment

```bash
# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f codeguardian

# Stop
docker-compose down
```

---

## 🤝 Authors

- **Suthar Vishalkumar Jadeshbhai**
- **Syed Abdullah**

**Course:** Software Engineering Laboratory

---

## 📄 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- OWASP Foundation for security standards
- Anthropic for Claude LLM
- PyCQA for Bandit
- r2c for Semgrep
