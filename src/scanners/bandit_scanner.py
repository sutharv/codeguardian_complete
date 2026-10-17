"""
CodeGuardian Bandit Scanner
Python-specific security analysis using Bandit.
"""

import json
import tempfile
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime

from .base import BaseScanner
from ..core.models import (
    Vulnerability, VulnerabilityCategory, Severity, Language,
    ScannerType, SourceLocation
)
from ..core.utils import generate_vuln_id, get_cwe_info, logger


# Bandit test ID to category mapping
BANDIT_CATEGORY_MAP = {
    "B608": VulnerabilityCategory.SQL_INJECTION,
    "B609": VulnerabilityCategory.SQL_INJECTION,
    "B602": VulnerabilityCategory.COMMAND_INJECTION,
    "B603": VulnerabilityCategory.COMMAND_INJECTION,
    "B604": VulnerabilityCategory.COMMAND_INJECTION,
    "B605": VulnerabilityCategory.COMMAND_INJECTION,
    "B606": VulnerabilityCategory.COMMAND_INJECTION,
    "B607": VulnerabilityCategory.COMMAND_INJECTION,
    "B310": VulnerabilityCategory.PATH_TRAVERSAL,
    "B105": VulnerabilityCategory.HARDCODED_SECRETS,
    "B106": VulnerabilityCategory.HARDCODED_SECRETS,
    "B107": VulnerabilityCategory.HARDCODED_SECRETS,
    "B301": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "B302": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "B403": VulnerabilityCategory.INSECURE_DESERIALIZATION,
    "B303": VulnerabilityCategory.INSECURE_CRYPTO,
    "B304": VulnerabilityCategory.INSECURE_CRYPTO,
    "B305": VulnerabilityCategory.INSECURE_CRYPTO,
    "B324": VulnerabilityCategory.INSECURE_CRYPTO,
    "B701": VulnerabilityCategory.XSS,
    "B702": VulnerabilityCategory.XSS,
    "B703": VulnerabilityCategory.XSS,
}

BANDIT_CWE_MAP = {
    "B602": "CWE-78", "B603": "CWE-78", "B604": "CWE-78",
    "B605": "CWE-78", "B606": "CWE-78", "B607": "CWE-78",
    "B608": "CWE-89", "B609": "CWE-89",
    "B105": "CWE-798", "B106": "CWE-798", "B107": "CWE-798",
    "B301": "CWE-502", "B302": "CWE-502",
    "B303": "CWE-327", "B304": "CWE-327", "B305": "CWE-327", "B324": "CWE-327",
    "B310": "CWE-22",
    "B701": "CWE-79", "B702": "CWE-79", "B703": "CWE-79",
}


class BanditScanner(BaseScanner):
    """Bandit security scanner for Python."""
    
    @property
    def scanner_type(self) -> ScannerType:
        return ScannerType.BANDIT
    
    @property
    def supported_languages(self) -> list[Language]:
        return [Language.PYTHON]
    
    async def initialize(self) -> bool:
        """Check if Bandit is installed."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "bandit", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            self._initialized = proc.returncode == 0
            if self._initialized:
                logger.info("Bandit scanner initialized successfully")
            else:
                logger.warning("Bandit not available")
            return self._initialized
        except FileNotFoundError:
            logger.warning("Bandit not installed - run: pip install bandit")
            return False
    
    async def scan(self, code: str, language: Language, file_path: Optional[str] = None) -> list[Vulnerability]:
        """Scan Python code with Bandit."""
        if language != Language.PYTHON:
            return []
        
        if not self._initialized:
            await self.initialize()
            if not self._initialized:
                return []
        
        vulnerabilities = []
        
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
                tmp.write(code)
                tmp_path = tmp.name
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    "bandit", "-f", "json", "-ll", tmp_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.config.timeout_seconds
                )
                
                if stdout:
                    result = json.loads(stdout.decode())
                    vulnerabilities = self._parse_results(result, code, file_path or tmp_path)
            finally:
                Path(tmp_path).unlink(missing_ok=True)
                
        except asyncio.TimeoutError:
            logger.error("Bandit scan timed out")
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
        
        return self.filter_by_severity(vulnerabilities)
    
    def _parse_results(self, result: dict, code: str, file_path: str) -> list[Vulnerability]:
        """Parse Bandit JSON output."""
        vulnerabilities = []
        code_lines = code.splitlines()
        
        for finding in result.get("results", []):
            test_id = finding.get("test_id", "")
            line_num = finding.get("line_number", 1)
            
            # Extract snippet
            start = max(0, line_num - 2)
            end = min(len(code_lines), line_num + 1)
            snippet = "\n".join(code_lines[start:end])
            
            category = BANDIT_CATEGORY_MAP.get(test_id, VulnerabilityCategory.OTHER)
            cwe_id = BANDIT_CWE_MAP.get(test_id)
            cwe_info = get_cwe_info(cwe_id) if cwe_id else {}
            
            severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            severity = severity_map.get(finding.get("issue_severity", "MEDIUM"), "medium")
            
            vuln = Vulnerability(
                id=generate_vuln_id(test_id, f"{file_path}:{line_num}"),
                category=category,
                severity=Severity(severity),
                title=f"{test_id}: {finding.get('test_name', 'Unknown')}",
                description=finding.get("issue_text", ""),
                location=SourceLocation(
                    file_path=file_path,
                    start_line=line_num,
                    end_line=finding.get("line_range", [line_num])[-1],
                    code_snippet=snippet,
                ),
                cwe_id=cwe_id,
                owasp_category=cwe_info.get("owasp"),
                scanner=ScannerType.BANDIT,
                confidence={"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(
                    finding.get("issue_confidence", "MEDIUM"), 0.7
                ),
                detected_at=datetime.utcnow(),
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
