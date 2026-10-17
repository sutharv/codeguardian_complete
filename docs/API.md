# CodeGuardian API Documentation

## Base URL
```
http://127.0.0.1:8080
```

## Authentication
Currently no authentication required for local development.

---

## Endpoints

### Health Check

**GET** `/health`

Check server status and scanner availability.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "scanners": {
    "bandit": true,
    "semgrep": true
  }
}
```

---

### Analyze Code

**POST** `/api/analyze`

Perform full security analysis on code.

**Request Body:**
```json
{
  "code": "def get_user(id):\n    return db.execute(f'SELECT * FROM users WHERE id = {id}')",
  "language": "python",
  "policies": ["OWASP_TOP_10"],
  "include_remediation": true
}
```

**Parameters:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| code | string | Yes | Source code to analyze |
| language | string | Yes | python, javascript, typescript, java, go |
| policies | array | No | Policy standards to check (default: ["OWASP_TOP_10"]) |
| include_remediation | bool | No | Generate fix suggestions (default: true) |

**Response:**
```json
{
  "request_id": "REQ-ABC123",
  "vulnerabilities": [
    {
      "id": "VULN-XYZ789",
      "category": "sql_injection",
      "severity": "critical",
      "title": "SQL Injection via string formatting",
      "description": "User input directly interpolated into SQL query",
      "location": {
        "file_path": "<input>",
        "start_line": 2,
        "end_line": 2,
        "code_snippet": "..."
      },
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021-Injection",
      "scanner": "bandit",
      "confidence": 0.9
    }
  ],
  "policy_violations": [],
  "remediations": [
    {
      "vulnerability_id": "VULN-XYZ789",
      "suggested_fix": "cursor.execute('SELECT * FROM users WHERE id = %s', (id,))",
      "rationale": "Use parameterized queries to prevent SQL injection",
      "security_impact": "Eliminates sql_injection vulnerability",
      "confidence": 0.8
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "total_policy_violations": 0,
    "has_critical": true,
    "has_high": false
  },
  "analysis_time_ms": 245.5
}
```

---

### Real-time Analysis

**POST** `/api/analyze/realtime`

Optimized analysis for IDE integration with caching.

Same request/response format as `/api/analyze`.

---

### Check Policy Compliance

**POST** `/api/policy/check`

Check code against specific policies.

**Request Body:**
```json
{
  "code": "DEBUG = True",
  "language": "python",
  "policies": ["OWASP_TOP_10", "SECURE_CODING"]
}
```

**Response:**
```json
{
  "compliant": false,
  "violation_count": 1,
  "violations": [
    {
      "rule_id": "OWASP-A05-001",
      "rule_name": "Debug Mode Enabled",
      "severity": "high",
      "message": "Debug mode should be disabled in production",
      "line": 1
    }
  ]
}
```

---

### List Policies

**GET** `/api/policy/list`

List all available security policies.

**Response:**
```json
{
  "policies": {
    "OWASP_TOP_10": {
      "rule_count": 8,
      "rules": [
        {"id": "OWASP-A01-001", "name": "Hardcoded Admin Credentials", "severity": "critical"},
        {"id": "OWASP-A02-001", "name": "Weak Cryptographic Algorithm", "severity": "high"}
      ]
    },
    "CWE_SANS_25": {...},
    "SECURE_CODING": {...}
  }
}
```

---

### List Scanners

**GET** `/api/scanners`

List available security scanners.

**Response:**
```json
{
  "scanners": [
    {"name": "bandit", "initialized": true, "languages": ["python"]},
    {"name": "semgrep", "initialized": true, "languages": ["python", "javascript", "typescript"]}
  ]
}
```

---

### Clear Cache

**POST** `/api/cache/clear`

Clear analysis cache.

**Query Parameters:**
- `file_path` (optional): Clear cache for specific file only

**Response:**
```json
{"status": "cache cleared"}
```

---

## Error Responses

**400 Bad Request:**
```json
{"detail": "Unsupported language: xyz"}
```

**500 Internal Server Error:**
```json
{"detail": "Analysis failed: error message"}
```

**503 Service Unavailable:**
```json
{"detail": "Analyzer not initialized"}
```

---

## Example Usage

### cURL
```bash
curl -X POST http://127.0.0.1:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "eval(user_input)", "language": "python"}'
```

### Python
```python
import requests

response = requests.post(
    "http://127.0.0.1:8080/api/analyze",
    json={
        "code": "query = f'SELECT * FROM users WHERE id = {id}'",
        "language": "python",
        "policies": ["OWASP_TOP_10"]
    }
)

result = response.json()
print(f"Found {len(result['vulnerabilities'])} vulnerabilities")
```

### JavaScript
```javascript
const response = await fetch('http://127.0.0.1:8080/api/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    code: 'eval(userInput)',
    language: 'javascript'
  })
});

const result = await response.json();
console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
```
