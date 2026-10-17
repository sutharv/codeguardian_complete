"""
CodeGuardian Comprehensive Test Suite
"""

import pytest
from src.core.models import (
    AnalysisRequest, Vulnerability, VulnerabilityCategory,
    Severity, Language, ScannerType, SourceLocation, PolicyRule
)
from src.core.utils import (
    generate_vuln_id, generate_request_id, detect_language,
    normalize_severity, get_cwe_info
)
from src.scanners.aggregator import ScannerAggregator
from src.policy.engine import PolicyEngine


class TestUtilities:
    def test_generate_vuln_id_unique(self):
        id1 = generate_vuln_id("sql", "file:10")
        id2 = generate_vuln_id("sql", "file:11")
        assert id1 != id2
        assert id1.startswith("VULN-")
    
    def test_detect_language(self):
        assert detect_language("app.py") == "python"
        assert detect_language("app.js") == "javascript"
        assert detect_language("unknown.xyz") is None
    
    def test_normalize_severity(self):
        assert normalize_severity("HIGH") == "high"
        assert normalize_severity("CRITICAL") == "critical"
    
    def test_get_cwe_info(self):
        info = get_cwe_info("CWE-89")
        assert info["name"] == "SQL Injection"


class TestPolicyEngine:
    @pytest.fixture
    def engine(self):
        return PolicyEngine()
    
    def test_policies_loaded(self, engine):
        policies = engine.get_available_policies()
        assert "OWASP_TOP_10" in policies
        assert "CWE_SANS_25" in policies
    
    @pytest.mark.asyncio
    async def test_detect_sql_injection(self, engine):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        violations = await engine.evaluate(code, Language.PYTHON, ["OWASP_TOP_10"])
        assert len(violations) > 0
    
    @pytest.mark.asyncio
    async def test_detect_hardcoded_secret(self, engine):
        code = 'api_key = "sk-1234567890abcdefghij"'
        violations = await engine.evaluate(code, Language.PYTHON, ["OWASP_TOP_10"])
        assert len(violations) > 0
    
    @pytest.mark.asyncio
    async def test_clean_code(self, engine):
        code = 'def add(a, b): return a + b'
        violations = await engine.evaluate(code, Language.PYTHON, ["OWASP_TOP_10"])
        critical = [v for v in violations if v.rule.severity == Severity.CRITICAL]
        assert len(critical) == 0


class TestScanners:
    @pytest.fixture
    def aggregator(self):
        return ScannerAggregator()
    
    def test_scanners_registered(self, aggregator):
        scanners = aggregator.get_available_scanners()
        assert "bandit" in scanners
        assert "semgrep" in scanners


VULNERABLE_SAMPLES = {
    "sql": 'f"SELECT * FROM users WHERE id = {id}"',
    "cmd": 'os.system(f"ls {input}")',
    "pickle": 'pickle.loads(data)',
    "secret": 'API_KEY = "sk-secret123456"',
}

SAFE_SAMPLES = {
    "sql": 'cursor.execute("SELECT * FROM users WHERE id = %s", (id,))',
    "cmd": 'subprocess.run(["ls", "-la"], shell=False)',
    "json": 'json.loads(data)',
    "secret": 'os.environ.get("API_KEY")',
}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
